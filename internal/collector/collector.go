// Package collector receives JSON Lines batches from shippers, validates each
// event and appends the accepted ones to a JSON Lines archive.
//
// Batches are untrusted even after authentication: the token lives on the
// honeypot host, which may be compromised (CLAUDE.md, HANDOFF.md §4.3).
package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/snd-primary/ajiro/internal/webpot"
)

type Config struct {
	Token    string // required; compared in constant time
	MaxBatch int64  // request body bytes
	MaxLine  int    // bytes per JSON line
}

func DefaultConfig() Config {
	return Config{
		MaxBatch: 8 << 20,
		MaxLine:  1 << 20,
	}
}

// Record is one archived line: the validated event plus when it arrived.
type Record struct {
	ReceivedAt time.Time     `json:"received_at"`
	Event      *webpot.Event `json:"event"`
}

// Result is the response body for an accepted batch.
type Result struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

type Handler struct {
	cfg   Config
	want  []byte
	store *Store
	db    *DB // nil = JSON Lines archive only
	now   func() time.Time
}

func NewHandler(cfg Config, store *Store, db *DB) (*Handler, error) {
	if cfg.Token == "" {
		return nil, errors.New("collector: empty token")
	}
	return &Handler{cfg: cfg, want: []byte("Bearer " + cfg.Token), store: store, db: db, now: time.Now}, nil
}

// ServeHTTP handles POST /ingest. Invalid events are counted and dropped; the
// rest of the batch is still stored. A batch that is too large or has an
// over-long line is rejected as a whole and nothing from it is stored.
//
// The JSON Lines archive is written first and is the source of truth; the
// database can be rebuilt from it (Import). If either write fails the
// shipper gets 500 and resends, which the database absorbs by id.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Check the token before reading the body.
	if !checkBearer(r, h.want) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.cfg.MaxBatch)
	sc := bufio.NewScanner(body)
	// The initial buffer's capacity also counts as a limit, so keep it ≤ MaxLine.
	sc.Buffer(make([]byte, 0, min(64<<10, h.cfg.MaxLine)), h.cfg.MaxLine)

	now := h.now().UTC()
	var recs []Record
	var lines [][]byte
	var rejects []rejection
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		ev, err := parseEvent(line)
		if err != nil {
			rejects = append(rejects, rejection{n, err})
			continue
		}
		rec := Record{ReceivedAt: now, Event: ev}
		b, err := json.Marshal(rec)
		if err != nil {
			rejects = append(rejects, rejection{n, errors.New("marshal failed")})
			continue
		}
		recs = append(recs, rec)
		lines = append(lines, b)
	}
	if err := sc.Err(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		// bufio.ErrTooLong (line over MaxLine) or a broken connection.
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := h.store.Append(lines); err != nil {
		slog.Error("store events", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if h.db != nil {
		if err := h.db.Insert(r.Context(), recs); err != nil {
			slog.Error("insert events", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	// Logged only once the batch is taken, and only our own reason strings,
	// never the line itself.
	for _, rj := range rejects {
		slog.Warn("reject event", "line", rj.line, "reason", rj.reason)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Result{Accepted: len(lines), Rejected: len(rejects)})
}

type rejection struct {
	line   int
	reason error
}
