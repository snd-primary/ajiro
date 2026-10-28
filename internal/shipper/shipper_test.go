package shipper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snd-primary/ajiro/internal/collector"
	"github.com/snd-primary/ajiro/internal/webpot"
)

func TestParseTarget(t *testing.T) {
	ok := map[string]string{
		"https://203.0.113.10:8443/ingest": "203.0.113.10:8443",
		"https://203.0.113.10/ingest":      "203.0.113.10:443",
		"http://127.0.0.1:9000/ingest":     "127.0.0.1:9000",
		"http://[::1]:9000/ingest":         "[::1]:9000",
		"https://[2001:db8::0:1]/ingest":   "[2001:db8::1]:443",
	}
	for raw, addr := range ok {
		tg, err := ParseTarget(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if tg.Addr != addr || tg.URL.Host != addr {
			t.Errorf("%s: addr = %s, host = %s, want %s", raw, tg.Addr, tg.URL.Host, addr)
		}
	}
	bad := []string{
		"",
		"https://collector.example.com/ingest", // would need DNS
		"https://localhost/ingest",
		"http://203.0.113.10/ingest", // plain http off-host
		"ftp://203.0.113.10/ingest",
		"https://user:pw@203.0.113.10/ingest",
		"https://203.0.113.10/ingest?x=1",
		"https://[fe80::1%25en0]/ingest",
	}
	for _, raw := range bad {
		if _, err := ParseTarget(raw); err == nil {
			t.Errorf("%q: accepted", raw)
		}
	}
}

func mustClient(t *testing.T, srv *httptest.Server, roots *x509.CertPool) (*Target, *http.Client) {
	t.Helper()
	tg, err := ParseTarget(srv.URL + "/ingest")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(tg, roots)
	if err != nil {
		t.Fatal(err)
	}
	return tg, c
}

func TestClientIgnoresProxyEnv(t *testing.T) {
	tg, _ := ParseTarget("https://203.0.113.10/ingest")
	c, err := NewClient(tg, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Error("transport has a proxy func")
	}
}

func TestHTTPSNeedsPinnedCert(t *testing.T) {
	tg, _ := ParseTarget("https://203.0.113.10/ingest")
	if _, err := NewClient(tg, nil); err == nil {
		t.Error("https client without pinned roots")
	}
}

func TestClientOnlyDialsTarget(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { otherHits.Add(1) }))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/ingest", http.StatusTemporaryRedirect)
	}))
	defer target.Close()

	_, c := mustClient(t, target, nil)
	if _, err := c.Get(other.URL); err == nil || !strings.Contains(err.Error(), "refusing to dial") {
		t.Errorf("dial to another address: err = %v", err)
	}
	resp, err := c.Get(target.URL + "/ingest")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want the redirect itself", resp.StatusCode)
	}
	if n := otherHits.Load(); n != 0 {
		t.Errorf("other server was contacted %d times", n)
	}
}

func TestTLSPinning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	pinned := x509.NewCertPool()
	pinned.AddCert(srv.Certificate())
	_, c := mustClient(t, srv, pinned)
	resp, err := c.Get(srv.URL + "/ingest")
	if err != nil {
		t.Fatalf("pinned cert rejected: %v", err)
	}
	resp.Body.Close()

	_, c = mustClient(t, srv, x509.NewCertPool())
	if _, err := c.Get(srv.URL + "/ingest"); err == nil {
		t.Error("unpinned cert accepted")
	}
}

func newTailer(path string, maxLine int) *tailer { return &tailer{path: path, maxLine: maxLine} }

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// drain reads and commits until nothing is left, returning the lines.
func drain(t *testing.T, tl *tailer) []string {
	t.Helper()
	var got []string
	for range 10 {
		lines, off, err := tl.next(1 << 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) == 0 {
			continue
		}
		for _, l := range lines {
			got = append(got, string(l))
		}
		tl.commit(off)
	}
	return got
}

func TestTailerHoldsPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.jsonl")
	appendFile(t, path, "a\nb")
	tl := newTailer(path, 100)
	defer tl.close()
	if got := drain(t, tl); fmt.Sprint(got) != "[a]" {
		t.Errorf("got %v", got)
	}
	appendFile(t, path, "c\n")
	if got := drain(t, tl); fmt.Sprint(got) != "[bc]" {
		t.Errorf("got %v", got)
	}
}

func TestTailerFollowsRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.jsonl")
	appendFile(t, path, "1\n")
	tl := newTailer(path, 100)
	defer tl.close()
	drain(t, tl)

	appendFile(t, path, "2\n") // written just before rotation
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "3\n")
	if got := drain(t, tl); fmt.Sprint(got) != "[2 3]" {
		t.Errorf("got %v", got)
	}
}

func TestTailerTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.jsonl")
	appendFile(t, path, "long line\n")
	tl := newTailer(path, 100)
	defer tl.close()
	drain(t, tl)
	if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := drain(t, tl); fmt.Sprint(got) != "[x]" {
		t.Errorf("got %v", got)
	}
}

func TestTailerDropsLongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "in.jsonl")
	appendFile(t, path, strings.Repeat("A", 3000)+"\nok\n"+strings.Repeat("B", 20)+"\nok2\n")
	tl := newTailer(path, 16)
	defer tl.close()
	if got := drain(t, tl); fmt.Sprint(got) != "[ok ok2]" {
		t.Errorf("got %v", got)
	}
}

func testEvent(i int) *webpot.Event {
	raw := []byte(fmt.Sprintf("GET /%d HTTP/1.1\r\n\r\n", i))
	return &webpot.Event{
		ID:        fmt.Sprintf("01a16fd8-dbfc-7b21-976f-%012x", i),
		Time:      time.Date(2026, 10, 25, 0, 0, i, 0, time.UTC),
		Sensor:    "web",
		EventType: webpot.EventHTTPRequest,
		SrcIP:     "192.0.2.1",
		HTTP:      &webpot.HTTPInfo{Method: "GET", URI: "/", Path: "/", Status: 404},
		Raw:       &webpot.RawCapture{B64: base64.StdEncoding.EncodeToString(raw), Len: len(raw), Total: int64(len(raw))},
	}
}

func writeEvents(t *testing.T, path string, from, n int) {
	t.Helper()
	var b strings.Builder
	for i := from; i < from+n; i++ {
		j, err := json.Marshal(testEvent(i))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	appendFile(t, path, b.String())
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

func (b *syncBuffer) ids() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ids []string
	sc := bufio.NewScanner(bytes.NewReader(b.buf.Bytes()))
	for sc.Scan() {
		var r collector.Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			ids = append(ids, r.Event.ID)
		}
	}
	return ids
}

// startPipeline runs a real collector handler over TLS and a shipper that
// tails a temp file into it.
func startPipeline(t *testing.T, ccfg collector.Config, scfg Config) (input string, stored *syncBuffer, stop func()) {
	t.Helper()
	stored = &syncBuffer{}
	ccfg.Token = "tok"
	h, err := collector.NewHandler(ccfg, collector.NewStore(stored), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(h)

	dir := t.TempDir()
	input = filepath.Join(dir, "webpot.jsonl")
	scfg.Input, scfg.StatePath, scfg.Token = input, filepath.Join(dir, "state.json"), "tok"
	scfg.Poll = 10 * time.Millisecond

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tg, c := mustClient(t, srv, roots)
	s, err := New(scfg, tg, c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Run(ctx)
	}()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done; srv.Close() }) }
	t.Cleanup(stop)
	return input, stored, stop
}

func waitIDs(t *testing.T, b *syncBuffer, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ids := b.ids()
		if len(ids) >= n || time.Now().After(deadline) {
			if len(ids) < n {
				t.Fatalf("collector stored %d events, want %d", len(ids), n)
			}
			return ids
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShipsToCollector(t *testing.T) {
	input, stored, stop := startPipeline(t, collector.DefaultConfig(), DefaultConfig())
	writeEvents(t, input, 0, 3)
	waitIDs(t, stored, 3)
	writeEvents(t, input, 3, 2)
	ids := waitIDs(t, stored, 5)
	stop()
	if len(ids) != 5 || ids[4] != testEvent(4).ID {
		t.Errorf("ids = %v", ids)
	}

	st, err := loadState(filepath.Join(filepath.Dir(input), "state.json"))
	if err != nil || st == nil {
		t.Fatalf("state = %v, %v", st, err)
	}
	fi, _ := os.Stat(input)
	if st.Offset != fi.Size() {
		t.Errorf("state offset = %d, file size = %d", st.Offset, fi.Size())
	}
}

// A batch the collector finds too large is split until it fits.
func TestSplitsRefusedBatches(t *testing.T) {
	line, _ := json.Marshal(testEvent(0))
	ccfg := collector.DefaultConfig()
	ccfg.MaxBatch = int64(len(line)*3/2 + 1)
	input, stored, _ := startPipeline(t, ccfg, DefaultConfig())
	writeEvents(t, input, 0, 8)
	if ids := waitIDs(t, stored, 8); len(ids) != 8 {
		t.Errorf("stored %d events, want exactly 8", len(ids))
	}
}

func TestResumesFromState(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.jsonl")
	appendFile(t, input, "old\nnew\n")
	fi, _ := os.Stat(input)
	id := idOf(fi)
	tl := &tailer{path: input, maxLine: 100, resume: &State{Dev: id.Dev, Ino: id.Ino, Offset: 4}}
	defer tl.close()
	if got := drain(t, tl); fmt.Sprint(got) != "[new]" {
		t.Errorf("got %v", got)
	}
}
