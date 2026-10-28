package webpot

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Event is one JSON Lines record. Every string in it was chosen by the remote
// peer and must be treated as untrusted. encoding/json replaces invalid UTF-8
// with U+FFFD, so the exact bytes are only preserved in Raw.
type Event struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"ts"`
	Sensor    string    `json:"sensor"`
	EventType string    `json:"event_type"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port,omitempty"`
	DstPort   int       `json:"dst_port,omitempty"`

	HTTP    *HTTPInfo   `json:"http,omitempty"`
	Raw     *RawCapture `json:"raw,omitempty"`
	Dropped *DropInfo   `json:"dropped,omitempty"`
}

const (
	EventHTTPRequest   = "http_request"
	EventConnNoRequest = "conn_no_request" // connection closed without a request reaching the handler (non-HTTP probe, malformed request, timeout)
	EventRateLimited   = "rate_limited"
)

type HTTPInfo struct {
	Method       string      `json:"method"`
	URI          string      `json:"uri"` // request-target as sent
	Proto        string      `json:"proto"`
	Host         string      `json:"host"`
	Path         string      `json:"path"` // percent-decoded
	Query        string      `json:"query"`
	ProxyRequest bool        `json:"proxy_request"` // CONNECT or absolute-form URI; never forwarded
	Headers      http.Header `json:"headers"`

	BodyLen       int    `json:"body_len"`              // bytes kept (≤ max body)
	BodySHA256    string `json:"body_sha256,omitempty"` // over the kept bytes only
	BodyTruncated bool   `json:"body_truncated"`

	Status int `json:"status"`
}

// RawCapture holds the bytes read from the connection, base64 encoded.
type RawCapture struct {
	B64       string `json:"b64"`
	Len       int    `json:"len"`   // captured bytes
	Total     int64  `json:"total"` // bytes read from the connection
	Truncated bool   `json:"truncated"`
}

type DropInfo struct {
	Count  int       `json:"count"`
	Since  time.Time `json:"since"`
	Reason string    `json:"reason"`
}

func newRaw(b []byte, truncated bool, total int64) *RawCapture {
	return &RawCapture{
		B64:       base64.StdEncoding.EncodeToString(b),
		Len:       len(b),
		Total:     total,
		Truncated: truncated,
	}
}

// newID returns a UUIDv7 so that IDs sort by time.
func newID() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	_, _ = rand.Read(b[6:])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func splitAddr(a net.Addr) (string, int) {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.String(), t.Port
	}
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	p, _ := strconv.Atoi(port)
	return host, p
}
