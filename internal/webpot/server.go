// Package webpot is a low-interaction HTTP honeypot. It records each request
// and answers with a fixed response.
//
// Invariants (HANDOFF.md §4.2, CLAUDE.md guardrails):
//   - It never opens outbound connections. Proxy requests (CONNECT,
//     absolute-form URIs) are logged and answered locally, never forwarded.
//   - Nothing received is executed, evaluated or reflected into a response.
package webpot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

type Config struct {
	DstPort        int   // reported destination port; 0 = the local listening port
	MaxBody        int64 // request body bytes kept per request
	MaxHeaderBytes int
	MaxConns       int
	RatePerMinute  float64 // new connections per source
	RateBurst      int
	MaxTracked     int // rate-limit table size

	ServerHeader string // "" omits the header
	PoweredBy    string // X-Powered-By; "" omits the header

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
}

func DefaultConfig() Config {
	return Config{
		MaxBody:           64 << 10,
		MaxHeaderBytes:    16 << 10,
		MaxConns:          512,
		RatePerMinute:     60,
		RateBurst:         30,
		MaxTracked:        100_000,
		ServerHeader:      "nginx",
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
	}
}

type Server struct {
	cfg     Config
	log     *Logger
	limiter *rateLimiter
	srv     *http.Server

	dropMu    sync.Mutex
	drops     map[string]int
	dropSince time.Time
}

type connKey struct{}

func New(cfg Config, log *Logger) *Server {
	s := &Server{
		cfg:       cfg,
		log:       log,
		limiter:   newRateLimiter(cfg.RatePerMinute, cfg.RateBurst, cfg.MaxTracked),
		drops:     make(map[string]int),
		dropSince: time.Now(),
	}
	s.srv = &http.Server{
		Handler:           s,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
		ConnState: s.connState,
		ErrorLog:  slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	s.srv.SetKeepAlivesEnabled(false)
	return s
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	captureLimit := s.cfg.MaxHeaderBytes + int(s.cfg.MaxBody) + 4096
	ll := &limitListener{
		Listener:     ln,
		sem:          make(chan struct{}, s.cfg.MaxConns),
		limiter:      s.limiter,
		captureLimit: captureLimit,
		onDrop:       s.recordDrop,
	}

	go s.maintenance(ctx)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()

	err := s.srv.Serve(ll)
	s.flushDrops()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	cc, _ := r.Context().Value(connKey{}).(*captureConn)

	body, _ := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBody+1))
	truncated := int64(len(body)) > s.cfg.MaxBody
	if truncated {
		body = body[:s.cfg.MaxBody]
	}

	status := s.respond(w, r)

	ev := s.baseEvent(now, EventHTTPRequest, r.RemoteAddr, cc)
	info := &HTTPInfo{
		Method:        r.Method,
		URI:           r.RequestURI,
		Proto:         r.Proto,
		Host:          r.Host,
		Path:          r.URL.Path,
		Query:         r.URL.RawQuery,
		ProxyRequest:  isProxyRequest(r),
		Headers:       r.Header,
		BodyLen:       len(body),
		BodyTruncated: truncated,
		Status:        status,
	}
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		info.BodySHA256 = hex.EncodeToString(sum[:])
	}
	ev.HTTP = info
	if cc != nil {
		cc.requestSeen.Store(true)
		ev.Raw = cc.snapshot()
	}
	s.write(ev)
}

func isProxyRequest(r *http.Request) bool {
	return r.Method == http.MethodConnect || r.URL.IsAbs()
}

// respond writes a fixed response. Nothing from the request is echoed back.
func (s *Server) respond(w http.ResponseWriter, r *http.Request) int {
	h := w.Header()
	if s.cfg.ServerHeader != "" {
		h.Set("Server", s.cfg.ServerHeader)
	}
	if s.cfg.PoweredBy != "" {
		h.Set("X-Powered-By", s.cfg.PoweredBy)
	}
	h.Set("Content-Type", "text/html")

	var status int
	var page string
	switch {
	case r.Method == http.MethodConnect:
		// Answer locally; the connection is never hijacked or tunnelled.
		status, page = http.StatusMethodNotAllowed, errorPage("405 Not Allowed", s.cfg.ServerHeader)
	case r.URL.Path == "/" && !r.URL.IsAbs() && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		status, page = http.StatusOK, indexPage
	default:
		status, page = http.StatusNotFound, errorPage("404 Not Found", s.cfg.ServerHeader)
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, page)
	}
	return status
}

const indexPage = "<!DOCTYPE html>\n<html>\n<head><title>Welcome</title></head>\n<body>\n<p>It works.</p>\n</body>\n</html>\n"

func errorPage(title, server string) string {
	footer := ""
	if server != "" {
		footer = "<hr><center>" + server + "</center>\n"
	}
	return "<html>\n<head><title>" + title + "</title></head>\n<body>\n<center><h1>" + title + "</h1></center>\n" + footer + "</body>\n</html>\n"
}

// connState logs connections that closed without a request reaching the
// handler: non-HTTP probes, requests net/http rejected, or timeouts.
func (s *Server) connState(c net.Conn, st http.ConnState) {
	if st != http.StateClosed {
		return
	}
	cc, ok := c.(*captureConn)
	if !ok || cc.requestSeen.Load() {
		return
	}
	ev := s.baseEvent(time.Now().UTC(), EventConnNoRequest, cc.RemoteAddr().String(), cc)
	ev.Raw = cc.snapshot()
	s.write(ev)
}

func (s *Server) baseEvent(now time.Time, typ, remote string, cc *captureConn) *Event {
	ev := &Event{ID: newID(), Time: now, Sensor: "web", EventType: typ}
	if cc != nil {
		ev.SrcIP, ev.SrcPort = splitAddr(cc.RemoteAddr())
		_, ev.DstPort = splitAddr(cc.LocalAddr())
	} else {
		ev.SrcIP, ev.SrcPort = splitAddr(stringAddr(remote))
	}
	if s.cfg.DstPort != 0 {
		ev.DstPort = s.cfg.DstPort
	}
	return ev
}

func (s *Server) write(ev *Event) {
	if err := s.log.Write(ev); err != nil {
		slog.Error("write event", "err", err)
	}
}

func (s *Server) recordDrop(ip string) {
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	if _, ok := s.drops[ip]; !ok && len(s.drops) >= s.cfg.MaxTracked {
		ip = "_overflow"
	}
	s.drops[ip]++
}

// flushDrops writes one rate_limited summary per source instead of one event
// per dropped connection, so a flood cannot fill the disk.
func (s *Server) flushDrops() {
	s.dropMu.Lock()
	drops, since := s.drops, s.dropSince
	s.drops, s.dropSince = make(map[string]int), time.Now()
	s.dropMu.Unlock()

	now := time.Now().UTC()
	for ip, n := range drops {
		ev := &Event{ID: newID(), Time: now, Sensor: "web", EventType: EventRateLimited, SrcIP: ip, DstPort: s.cfg.DstPort}
		ev.Dropped = &DropInfo{Count: n, Since: since.UTC(), Reason: "rate_limit"}
		s.write(ev)
	}
}

func (s *Server) maintenance(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.flushDrops()
			s.limiter.sweep(now)
		}
	}
}
