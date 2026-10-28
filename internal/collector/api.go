package collector

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/snd-primary/ajiro/internal/webpot"
)

// QueryAPI serves read-only aggregates for the dashboard. It has its own
// listener and token: the ingest token lives on the honeypot host and must
// not grant reading the data (HANDOFF.md §3).
//
//	GET /api/summary     ?from&to
//	GET /api/timeseries  ?from&to&bucket=minute|hour|day&path
//	GET /api/top         ?from&to&field=<TopFields>&limit
//	GET /api/events      ?from&to&before&event_type&src_ip&path&limit
//	GET /api/events/{id}
//
// from/to are RFC 3339; the default range is the last 7 days. Response
// strings are attacker-written and must be escaped by whoever displays them.
type QueryAPI struct {
	db      *DB
	want    []byte
	sem     chan struct{}
	timeout time.Duration
	now     func() time.Time
	mux     *http.ServeMux
}

const (
	defaultRange = 7 * 24 * time.Hour
	maxLimit     = 500
	maxPathParam = 2048
)

func NewQueryAPI(db *DB, token string) (*QueryAPI, error) {
	if token == "" {
		return nil, errors.New("collector: empty query token")
	}
	a := &QueryAPI{
		db:      db,
		want:    []byte("Bearer " + token),
		sem:     make(chan struct{}, 4),
		timeout: 10 * time.Second,
		now:     time.Now,
		mux:     http.NewServeMux(),
	}
	a.mux.HandleFunc("GET /api/summary", a.summary)
	a.mux.HandleFunc("GET /api/timeseries", a.timeseries)
	a.mux.HandleFunc("GET /api/top", a.top)
	a.mux.HandleFunc("GET /api/events", a.events)
	a.mux.HandleFunc("GET /api/events/{id}", a.event)
	return a, nil
}

func (a *QueryAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if !checkBearer(r, a.want) {
		h.Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), a.timeout)
	defer cancel()
	a.mux.ServeHTTP(w, r.WithContext(ctx))
}

func (a *QueryAPI) summary(w http.ResponseWriter, r *http.Request) {
	rg, err := a.parseRange(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	s, err := a.db.Summary(r.Context(), rg)
	reply(w, s, err)
}

func (a *QueryAPI) timeseries(w http.ResponseWriter, r *http.Request) {
	rg, err := a.parseRange(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	q := r.URL.Query()
	bucket := q.Get("bucket")
	if bucket == "" {
		bucket = "hour"
	}
	if _, ok := Buckets[bucket]; !ok {
		badRequest(w, errors.New("bucket must be minute, hour or day"))
		return
	}
	path := q.Get("path")
	if len(path) > maxPathParam {
		badRequest(w, errors.New("path too long"))
		return
	}
	pts, err := a.db.Timeseries(r.Context(), rg, bucket, path)
	reply(w, map[string]any{"bucket": bucket, "points": pts}, err)
}

func (a *QueryAPI) top(w http.ResponseWriter, r *http.Request) {
	rg, err := a.parseRange(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	field := r.URL.Query().Get("field")
	if _, ok := TopFields[field]; !ok {
		badRequest(w, errors.New("unknown field"))
		return
	}
	limit, err := parseLimit(r, 20)
	if err != nil {
		badRequest(w, err)
		return
	}
	items, err := a.db.Top(r.Context(), rg, field, limit)
	reply(w, map[string]any{"field": field, "items": items}, err)
}

func (a *QueryAPI) events(w http.ResponseWriter, r *http.Request) {
	rg, err := a.parseRange(r)
	if err != nil {
		badRequest(w, err)
		return
	}
	limit, err := parseLimit(r, 100)
	if err != nil {
		badRequest(w, err)
		return
	}
	q := r.URL.Query()
	f := EventFilter{Range: rg, Limit: limit, Path: q.Get("path")}
	if f.Before = q.Get("before"); f.Before != "" && !isUUID(f.Before) {
		badRequest(w, errors.New("bad before"))
		return
	}
	switch f.EventType = q.Get("event_type"); f.EventType {
	case "", webpot.EventHTTPRequest, webpot.EventConnNoRequest, webpot.EventRateLimited:
	default:
		badRequest(w, errors.New("unknown event_type"))
		return
	}
	if f.SrcIP = q.Get("src_ip"); f.SrcIP != "" {
		ip, err := netip.ParseAddr(f.SrcIP)
		if err != nil {
			badRequest(w, errors.New("bad src_ip"))
			return
		}
		f.SrcIP = ip.String()
	}
	if len(f.Path) > maxPathParam {
		badRequest(w, errors.New("path too long"))
		return
	}

	evs, err := a.db.Events(r.Context(), f)
	resp := map[string]any{"events": evs}
	if err == nil && len(evs) == limit {
		resp["next"] = evs[len(evs)-1].ID
	}
	reply(w, resp, err)
}

func (a *QueryAPI) event(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		badRequest(w, errors.New("bad id"))
		return
	}
	e, err := a.db.Event(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	reply(w, e, err)
}

func (a *QueryAPI) parseRange(r *http.Request) (Range, error) {
	q := r.URL.Query()
	rg := Range{To: a.now().UTC()}
	if s := q.Get("to"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return rg, errors.New("to must be RFC 3339")
		}
		rg.To = t.UTC()
	}
	rg.From = rg.To.Add(-defaultRange)
	if s := q.Get("from"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return rg, errors.New("from must be RFC 3339")
		}
		rg.From = t.UTC()
	}
	if !rg.From.Before(rg.To) {
		return rg, errors.New("from must be before to")
	}
	return rg, nil
}

func parseLimit(r *http.Request, def int) (int, error) {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxLimit {
		return 0, errors.New("limit must be 1-500")
	}
	return n, nil
}

// badRequest answers with one of our own messages, never echoing input.
func badRequest(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		slog.Error("query", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func checkBearer(r *http.Request, want []byte) bool {
	got := []byte(r.Header.Get("Authorization"))
	return subtle.ConstantTimeCompare(got, want) == 1
}
