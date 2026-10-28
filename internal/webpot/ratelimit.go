package webpot

import (
	"net"
	"sync"
	"time"
)

// rateLimiter is a per-source token bucket. IPv6 sources are keyed by /64 so a
// single host cannot dodge the limit by rotating addresses. When the table is
// full, unknown sources are denied (fail closed) to bound memory.
type rateLimiter struct {
	mu         sync.Mutex
	rate       float64 // tokens per second
	burst      float64
	maxEntries int
	buckets    map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMinute float64, burst, maxEntries int) *rateLimiter {
	return &rateLimiter{
		rate:       perMinute / 60,
		burst:      float64(burst),
		maxEntries: maxEntries,
		buckets:    make(map[string]*bucket),
	}
}

func limiterKey(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ip
	}
	if p.To4() != nil {
		return p.String()
	}
	return p.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (l *rateLimiter) allow(ip string, now time.Time) bool {
	key := limiterKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxEntries {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have refilled completely; they behave the same as
// a fresh entry.
func (l *rateLimiter) sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
