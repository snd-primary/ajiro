package webpot

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// limitListener caps concurrent connections and applies the per-source rate
// limit at accept time, before any bytes are read or logged.
type limitListener struct {
	net.Listener
	sem          chan struct{}
	limiter      *rateLimiter
	captureLimit int
	onDrop       func(ip string)
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		l.sem <- struct{}{}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		ip, _ := splitAddr(c.RemoteAddr())
		if !l.limiter.allow(ip, time.Now()) {
			c.Close()
			<-l.sem
			l.onDrop(ip)
			continue
		}
		return &captureConn{
			Conn:    c,
			limit:   l.captureLimit,
			release: func() { <-l.sem },
		}, nil
	}
}

// captureConn records the first limit bytes read from the peer so the exact
// request (or non-HTTP probe) can be logged. Keep-alives are disabled, so one
// connection carries at most one request.
type captureConn struct {
	net.Conn
	limit int

	mu        sync.Mutex
	buf       []byte
	total     int64
	truncated bool

	requestSeen atomic.Bool
	release     func()
	closeOnce   sync.Once
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.total += int64(n)
		room := c.limit - len(c.buf)
		take := min(n, max(room, 0))
		c.buf = append(c.buf, p[:take]...)
		if take < n {
			c.truncated = true
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *captureConn) snapshot() *RawCapture {
	c.mu.Lock()
	defer c.mu.Unlock()
	return newRaw(c.buf, c.truncated, c.total)
}

func (c *captureConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.release)
	return err
}
