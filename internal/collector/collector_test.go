package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snd-primary/ajiro/internal/webpot"
)

const testToken = "test-token"

func newTestHandler(t *testing.T, cfg Config) (*Handler, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	cfg.Token = testToken
	h, err := NewHandler(cfg, NewStore(out), nil)
	if err != nil {
		t.Fatal(err)
	}
	h.now = func() time.Time { return time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC) }
	return h, out
}

func post(h http.Handler, auth, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func result(t *testing.T, rec *httptest.ResponseRecorder) Result {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var res Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func records(t *testing.T, out *bytes.Buffer) []Record {
	t.Helper()
	var recs []Record
	sc := bufio.NewScanner(bytes.NewReader(out.Bytes()))
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad stored line %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	return recs
}

func httpEvent() *webpot.Event {
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	return &webpot.Event{
		ID:        "01a16fd8-dbfc-7b21-976f-052b08128714",
		Time:      time.Date(2026, 10, 24, 21, 37, 25, 0, time.UTC),
		Sensor:    "web",
		EventType: webpot.EventHTTPRequest,
		SrcIP:     "192.0.2.1",
		SrcPort:   51135,
		DstPort:   80,
		HTTP: &webpot.HTTPInfo{
			Method: "GET", URI: "/", Proto: "HTTP/1.1", Host: "x", Path: "/",
			Headers: http.Header{"User-Agent": {"zgrab"}},
			Status:  404,
		},
		Raw: &webpot.RawCapture{B64: base64.StdEncoding.EncodeToString(raw), Len: len(raw), Total: int64(len(raw))},
	}
}

func line(t *testing.T, ev *webpot.Event) string {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t, DefaultConfig())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ingest", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Errorf("status = %d, Allow = %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestUnauthorized(t *testing.T) {
	h, out := newTestHandler(t, DefaultConfig())
	for _, auth := range []string{"", "Bearer wrong", testToken, "bearer " + testToken, "Bearer " + testToken + " "} {
		rec := post(h, auth, line(t, httpEvent()))
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("auth %q: status = %d", auth, rec.Code)
		}
	}
	if out.Len() != 0 {
		t.Errorf("stored %q without auth", out.String())
	}
}

func TestAcceptsAllEventTypes(t *testing.T) {
	h, out := newTestHandler(t, DefaultConfig())

	noReq := httpEvent()
	noReq.EventType, noReq.HTTP = webpot.EventConnNoRequest, nil

	limited := httpEvent()
	limited.EventType, limited.HTTP, limited.Raw, limited.SrcPort = webpot.EventRateLimited, nil, nil, 0
	limited.Dropped = &webpot.DropInfo{Count: 3, Since: limited.Time, Reason: "rate_limit"}

	overflow := *limited
	overflow.SrcIP = "_overflow"

	body := line(t, httpEvent()) + "\n" + line(t, noReq) + line(t, limited) + line(t, &overflow)
	res := result(t, post(h, "Bearer "+testToken, body))
	if res != (Result{Accepted: 4}) {
		t.Errorf("result = %+v", res)
	}
	recs := records(t, out)
	if len(recs) != 4 {
		t.Fatalf("stored %d records", len(recs))
	}
	if !recs[0].ReceivedAt.Equal(h.now()) || recs[0].Event.HTTP.Headers.Get("User-Agent") != "zgrab" {
		t.Errorf("record = %+v", recs[0])
	}
}

func TestRejectsInvalidEvents(t *testing.T) {
	mutate := func(f func(*webpot.Event)) func(*testing.T) string {
		return func(t *testing.T) string {
			ev := httpEvent()
			f(ev)
			return line(t, ev)
		}
	}
	cases := map[string]func(*testing.T) string{
		"not json":        func(*testing.T) string { return "GET / HTTP/1.1\n" },
		"null":            func(*testing.T) string { return "null\n" },
		"unknown field":   func(t *testing.T) string { return strings.Replace(line(t, httpEvent()), `{"id"`, `{"evil":1,"id"`, 1) },
		"trailing data":   func(t *testing.T) string { return strings.TrimSuffix(line(t, httpEvent()), "\n") + " {}\n" },
		"bad id":          mutate(func(ev *webpot.Event) { ev.ID = "../../etc/passwd" }),
		"zero time":       mutate(func(ev *webpot.Event) { ev.Time = time.Time{} }),
		"other sensor":    mutate(func(ev *webpot.Event) { ev.Sensor = "cowrie" }),
		"unknown type":    mutate(func(ev *webpot.Event) { ev.EventType = "shell" }),
		"missing http":    mutate(func(ev *webpot.Event) { ev.HTTP = nil }),
		"bad src_ip":      mutate(func(ev *webpot.Event) { ev.SrcIP = "'; DROP TABLE events;--" }),
		"overflow on req": mutate(func(ev *webpot.Event) { ev.SrcIP = "_overflow" }),
		"bad port":        mutate(func(ev *webpot.Event) { ev.DstPort = 70000 }),
		"bad status":      mutate(func(ev *webpot.Event) { ev.HTTP.Status = 0 }),
		"bad sha256":      mutate(func(ev *webpot.Event) { ev.HTTP.BodySHA256 = "zz" }),
		"bad base64":      mutate(func(ev *webpot.Event) { ev.Raw.B64 = "%%%" }),
		"raw len lies":    mutate(func(ev *webpot.Event) { ev.Raw.Len = 1 }),
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			h, out := newTestHandler(t, DefaultConfig())
			res := result(t, post(h, "Bearer "+testToken, mk(t)+line(t, httpEvent())))
			if res != (Result{Accepted: 1, Rejected: 1}) {
				t.Errorf("result = %+v", res)
			}
			if n := len(records(t, out)); n != 1 {
				t.Errorf("stored %d records, want 1", n)
			}
		})
	}
}

func TestBatchTooLarge(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBatch = 1024
	h, out := newTestHandler(t, cfg)
	body := strings.Repeat(line(t, httpEvent()), 10)
	if rec := post(h, "Bearer "+testToken, body); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
	if out.Len() != 0 {
		t.Error("stored part of an oversized batch")
	}
}

func TestLineTooLong(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxLine = 1024
	h, out := newTestHandler(t, cfg)
	body := line(t, httpEvent()) + strings.Repeat("a", 2048) + "\n"
	if rec := post(h, "Bearer "+testToken, body); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if out.Len() != 0 {
		t.Error("stored part of a batch with an over-long line")
	}
}

func TestEmptyBatch(t *testing.T) {
	h, out := newTestHandler(t, DefaultConfig())
	if res := result(t, post(h, "Bearer "+testToken, "")); res != (Result{}) {
		t.Errorf("result = %+v", res)
	}
	if out.Len() != 0 {
		t.Error("stored something for an empty batch")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Everything a real webpot writes must pass validation, so the two packages
// cannot drift apart unnoticed.
func TestAcceptsRealWebpotOutput(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wlog := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = webpot.New(webpot.DefaultConfig(), webpot.NewLogger(wlog)).Serve(ctx, ln)
	}()

	addr := ln.Addr().String()
	resp, err := http.Post("http://"+addr+"/index.php?id=1%27", "text/plain", strings.NewReader("<?php system($_GET['c']); ?>"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("\x16\x03\x01\x00\xff not http\r\n\r\n"))
	c.Close()

	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(wlog.String(), "\n") < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	batch := wlog.String()
	n := strings.Count(batch, "\n")
	if n < 2 {
		t.Fatalf("webpot wrote %d events, want at least 2", n)
	}
	h, _ := newTestHandler(t, DefaultConfig())
	if res := result(t, post(h, "Bearer "+testToken, batch)); res != (Result{Accepted: n}) {
		t.Errorf("result = %+v, want %d accepted", res, n)
	}
}
