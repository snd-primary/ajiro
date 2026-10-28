package webpot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) events(t *testing.T) []Event {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var evs []Event
	sc := bufio.NewScanner(bytes.NewReader(b.buf.Bytes()))
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("bad JSON line %q: %v", sc.Text(), err)
		}
		evs = append(evs, ev)
	}
	return evs
}

func startServer(t *testing.T, cfg Config) (string, *syncBuffer) {
	t.Helper()
	out := &syncBuffer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := New(cfg, NewLogger(out)).Serve(ctx, ln); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), out
}

// send writes raw bytes and returns the full response.
func send(t *testing.T, addr, raw string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	resp, _ := io.ReadAll(c)
	return string(resp)
}

func waitEvents(t *testing.T, out *syncBuffer, n int) []Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := out.events(t)
		if len(evs) >= n || time.Now().After(deadline) {
			if len(evs) < n {
				t.Fatalf("got %d events, want %d", len(evs), n)
			}
			return evs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func decodeRaw(t *testing.T, r *RawCapture) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(r.B64)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRequestLogged(t *testing.T) {
	addr, out := startServer(t, DefaultConfig())
	req := "POST /index.php?s=/x&a=%00 HTTP/1.1\r\nHost: example\r\nUser-Agent: zgrab\r\nContent-Length: 5\r\n\r\nhello"
	resp := send(t, addr, req)
	if !strings.HasPrefix(resp, "HTTP/1.1 404") {
		t.Errorf("response = %q", resp)
	}

	ev := waitEvents(t, out, 1)[0]
	if ev.EventType != EventHTTPRequest || ev.Sensor != "web" || ev.SrcIP != "127.0.0.1" {
		t.Errorf("event = %+v", ev)
	}
	h := ev.HTTP
	if h.Method != "POST" || h.Path != "/index.php" || h.Query != "s=/x&a=%00" || h.URI != "/index.php?s=/x&a=%00" {
		t.Errorf("http = %+v", h)
	}
	if h.Headers.Get("User-Agent") != "zgrab" || h.BodyLen != 5 || h.BodyTruncated || h.BodySHA256 == "" {
		t.Errorf("http = %+v", h)
	}
	if got := decodeRaw(t, ev.Raw); got != req {
		t.Errorf("raw = %q, want %q", got, req)
	}
}

func TestBodyTruncated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBody = 4
	addr, out := startServer(t, cfg)
	send(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789")
	h := waitEvents(t, out, 1)[0].HTTP
	if h.BodyLen != 4 || !h.BodyTruncated {
		t.Errorf("http = %+v", h)
	}
}

// Proxy requests must be logged and answered locally, never forwarded.
func TestProxyRequestsNotForwarded(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	reached := make(chan struct{}, 10)
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			reached <- struct{}{}
			c.Close()
		}
	}()

	addr, out := startServer(t, DefaultConfig())
	tgt := target.Addr().String()
	r1 := send(t, addr, "CONNECT "+tgt+" HTTP/1.1\r\nHost: "+tgt+"\r\n\r\n")
	r2 := send(t, addr, "GET http://"+tgt+"/ HTTP/1.1\r\nHost: "+tgt+"\r\n\r\n")

	if !strings.HasPrefix(r1, "HTTP/1.1 405") {
		t.Errorf("CONNECT response = %q", r1)
	}
	if !strings.HasPrefix(r2, "HTTP/1.1 404") {
		t.Errorf("absolute-URI response = %q", r2)
	}
	evs := waitEvents(t, out, 2)
	for _, ev := range evs {
		if !ev.HTTP.ProxyRequest {
			t.Errorf("proxy_request = false for %+v", ev.HTTP)
		}
	}
	select {
	case <-reached:
		t.Fatal("honeypot connected to the proxy target")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNonHTTPProbeLogged(t *testing.T) {
	addr, out := startServer(t, DefaultConfig())
	probe := "\x16\x03\x01\x00\x05hello\x1b[31m"
	send(t, addr, probe)
	ev := waitEvents(t, out, 1)[0]
	if ev.EventType != EventConnNoRequest || ev.HTTP != nil {
		t.Errorf("event = %+v", ev)
	}
	if got := decodeRaw(t, ev.Raw); got != probe {
		t.Errorf("raw = %q, want %q", got, probe)
	}
}

func TestResponseDoesNotReflectInput(t *testing.T) {
	addr, _ := startServer(t, DefaultConfig())
	resp := send(t, addr, "GET /<script>alert(1)</script> HTTP/1.1\r\nHost: x\r\n\r\n")
	if strings.Contains(resp, "script") {
		t.Errorf("response reflects input: %q", resp)
	}
}

func TestPoweredByOptional(t *testing.T) {
	addr, _ := startServer(t, DefaultConfig())
	if resp := send(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); strings.Contains(resp, "X-Powered-By") {
		t.Errorf("X-Powered-By present by default: %q", resp)
	}
	cfg := DefaultConfig()
	cfg.PoweredBy = "PHP/8.3.0"
	addr, _ = startServer(t, cfg)
	if resp := send(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); !strings.Contains(resp, "X-Powered-By: PHP/8.3.0") {
		t.Errorf("X-Powered-By missing: %q", resp)
	}
}

func TestRateLimitDropsAndSummarizes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RatePerMinute = 0.001
	cfg.RateBurst = 2
	out := &syncBuffer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = New(cfg, NewLogger(out)).Serve(ctx, ln) }()

	addr := ln.Addr().String()
	for i := 0; i < 5; i++ {
		send(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	}
	cancel() // Serve flushes the drop summary on exit
	<-done

	var reqs, dropped int
	for _, ev := range out.events(t) {
		switch ev.EventType {
		case EventHTTPRequest:
			reqs++
		case EventRateLimited:
			dropped += ev.Dropped.Count
		}
	}
	if reqs != 2 || dropped != 3 {
		t.Errorf("requests = %d, dropped = %d; want 2, 3", reqs, dropped)
	}
}

func TestLimiterKeyIPv6Per64(t *testing.T) {
	a := limiterKey("2001:db8:1:2::1")
	b := limiterKey("2001:db8:1:2:ffff::9")
	c := limiterKey("2001:db8:1:3::1")
	if a != b || a == c {
		t.Errorf("keys: %s %s %s", a, b, c)
	}
	if limiterKey("192.0.2.1") != "192.0.2.1" {
		t.Error("IPv4 key changed")
	}
}

func TestLimiterFailsClosedWhenFull(t *testing.T) {
	l := newRateLimiter(60, 1, 1)
	now := time.Now()
	if !l.allow("192.0.2.1", now) {
		t.Fatal("first source denied")
	}
	if l.allow("192.0.2.2", now) {
		t.Error("new source allowed with full table")
	}
}
