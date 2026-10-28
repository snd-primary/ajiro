package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snd-primary/ajiro/internal/webpot"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.duckdb"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func countEvents(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestInsertDeduplicatesByID(t *testing.T) {
	db := openTestDB(t)
	rec := Record{ReceivedAt: time.Now(), Event: httpEvent()}
	for range 2 {
		if err := db.Insert(context.Background(), []Record{rec}); err != nil {
			t.Fatal(err)
		}
	}
	if n := countEvents(t, db); n != 1 {
		t.Errorf("events = %d, want 1", n)
	}
}

// Attacker-written strings must be stored as data, byte for byte.
func TestInsertStoresHostileStringsVerbatim(t *testing.T) {
	db := openTestDB(t)
	ev := httpEvent()
	ev.HTTP.Path = "/'); DROP TABLE events;--"
	ev.HTTP.Headers.Set("User-Agent", "\x1b[31mred\x1b[0m ' OR 1=1 --")
	if err := db.Insert(context.Background(), []Record{{ReceivedAt: time.Now(), Event: ev}}); err != nil {
		t.Fatal(err)
	}
	var path, ua string
	var status int
	err := db.SQL().QueryRow("SELECT http_path, http_user_agent, http_status FROM events WHERE id = ?", ev.ID).Scan(&path, &ua, &status)
	if err != nil {
		t.Fatal(err)
	}
	if path != ev.HTTP.Path || ua != ev.HTTP.Headers.Get("User-Agent") || status != 404 {
		t.Errorf("path = %q, ua = %q, status = %d", path, ua, status)
	}
}

func TestEventJSONRoundTrips(t *testing.T) {
	db := openTestDB(t)
	ev := httpEvent()
	if err := db.Insert(context.Background(), []Record{{ReceivedAt: time.Now(), Event: ev}}); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.SQL().QueryRow("SELECT event->>'$.raw.b64' FROM events").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != ev.Raw.B64 {
		t.Errorf("raw.b64 = %q, want %q", raw, ev.Raw.B64)
	}
}

func TestSQLCannotReachOutside(t *testing.T) {
	db := openTestDB(t)
	local := filepath.Join(t.TempDir(), "x.csv")
	if err := os.WriteFile(local, []byte("a\n1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"SELECT * FROM read_csv('" + local + "')",
		"SELECT * FROM read_csv('https://example.com/x.csv')",
		"INSTALL httpfs",
		"SET enable_external_access = true",
		"COPY events TO '" + filepath.Join(t.TempDir(), "out.csv") + "'",
	} {
		if _, err := db.SQL().Exec(q); err == nil {
			t.Errorf("%s: allowed", q)
		}
	}
}

func TestHandlerWritesDB(t *testing.T) {
	db := openTestDB(t)
	out := &bytes.Buffer{}
	cfg := DefaultConfig()
	cfg.Token = testToken
	h, err := NewHandler(cfg, NewStore(out), db)
	if err != nil {
		t.Fatal(err)
	}
	body := line(t, httpEvent()) + "not json\n"
	for range 2 { // a shipper resend
		if res := result(t, post(h, "Bearer "+testToken, body)); res != (Result{Accepted: 1, Rejected: 1}) {
			t.Errorf("result = %+v", res)
		}
	}
	if n := countEvents(t, db); n != 1 {
		t.Errorf("events = %d, want 1", n)
	}
	if n := len(records(t, out)); n != 2 {
		t.Errorf("archive has %d lines, want 2 (dedup happens in the db)", n)
	}
}

func TestImportRebuildsFromArchive(t *testing.T) {
	var archive bytes.Buffer
	noReq := httpEvent()
	noReq.ID, noReq.EventType, noReq.HTTP = "01a16fd8-dbfc-7b21-976f-000000000002", webpot.EventConnNoRequest, nil
	for _, ev := range []*webpot.Event{httpEvent(), noReq, httpEvent()} {
		b, _ := json.Marshal(Record{ReceivedAt: time.Now(), Event: ev})
		archive.Write(b)
		archive.WriteByte('\n')
	}
	archive.WriteString(`{"received_at":"2026-10-25T00:00:00Z","event":{"id":"x"}}` + "\n")
	archive.WriteString(strings.Repeat("\n", 3))

	db := openTestDB(t)
	n, rejected, err := Import(context.Background(), &archive, db, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || rejected != 1 {
		t.Errorf("imported %d, rejected %d", n, rejected)
	}
	if c := countEvents(t, db); c != 2 {
		t.Errorf("events = %d, want 2", c)
	}
}
