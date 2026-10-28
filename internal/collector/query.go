package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// The read side of the database. Every query here is fixed SQL; callers can
// only choose among whitelisted columns and bind values, never add SQL.

type Range struct {
	From, To time.Time // [From, To), UTC
}

type Summary struct {
	Events         int        `json:"events"`
	HTTPRequests   int        `json:"http_requests"`
	ConnNoRequest  int        `json:"conn_no_request"`
	RateLimited    int        `json:"rate_limited"` // dropped connections
	DistinctSrcIPs int        `json:"distinct_src_ips"`
	First          *time.Time `json:"first,omitempty"`
	Last           *time.Time `json:"last,omitempty"`
}

func (d *DB) Summary(ctx context.Context, r Range) (Summary, error) {
	var s Summary
	err := d.db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (event_type <> 'rate_limited'),
			count(*) FILTER (event_type = 'http_request'),
			count(*) FILTER (event_type = 'conn_no_request'),
			coalesce(sum(dropped_count), 0),
			count(DISTINCT src_ip) FILTER (event_type <> 'rate_limited'),
			min(ts) FILTER (event_type <> 'rate_limited'),
			max(ts) FILTER (event_type <> 'rate_limited')
		FROM events WHERE ts >= ? AND ts < ?`, r.From, r.To,
	).Scan(&s.Events, &s.HTTPRequests, &s.ConnNoRequest, &s.RateLimited, &s.DistinctSrcIPs, &s.First, &s.Last)
	return s, err
}

type Point struct {
	T         time.Time `json:"t"`
	EventType string    `json:"event_type"`
	N         int       `json:"n"`
}

// Buckets maps the accepted bucket names to date_trunc parts.
var Buckets = map[string]string{"minute": "minute", "hour": "hour", "day": "day"}

// Timeseries counts events per bucket and type. Rate-limited rows count the
// connections they stand for. path, if set, keeps only requests to it.
func (d *DB) Timeseries(ctx context.Context, r Range, bucket, path string) ([]Point, error) {
	part, ok := Buckets[bucket]
	if !ok {
		return nil, errors.New("bad bucket")
	}
	q := `
		SELECT date_trunc(?, ts) AS t, event_type,
			sum(CASE WHEN event_type = 'rate_limited' THEN dropped_count ELSE 1 END)
		FROM events WHERE ts >= ? AND ts < ?`
	args := []any{part, r.From, r.To}
	if path != "" {
		q += ` AND http_path = ?`
		args = append(args, path)
	}
	q += ` GROUP BY ALL ORDER BY t, event_type`

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pts := []Point{}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.T, &p.EventType, &p.N); err != nil {
			return nil, err
		}
		pts = append(pts, p)
	}
	return pts, rows.Err()
}

type topField struct {
	expr  string // fixed SQL expression
	where string // fixed SQL condition
}

// TopFields are the only columns /api/top can rank.
var TopFields = map[string]topField{
	"path":       {"http_path", "event_type = 'http_request'"},
	"query":      {"http_query", "event_type = 'http_request' AND http_query <> ''"},
	"user_agent": {"http_user_agent", "event_type = 'http_request'"},
	"method":     {"http_method", "event_type = 'http_request'"},
	"host":       {"http_host", "event_type = 'http_request'"},
	"src_ip":     {"src_ip", "event_type <> 'rate_limited'"},
	"dst_port":   {"CAST(dst_port AS VARCHAR)", "event_type <> 'rate_limited'"},
}

type TopItem struct {
	Value   string    `json:"value"`
	N       int       `json:"n"`
	Sources int       `json:"sources"` // distinct src_ip
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

func (d *DB) Top(ctx context.Context, r Range, field string, limit int) ([]TopItem, error) {
	f, ok := TopFields[field]
	if !ok {
		return nil, errors.New("bad field")
	}
	q := `SELECT ` + f.expr + ` AS value, count(*) AS n, count(DISTINCT src_ip), min(ts), max(ts)
		FROM events WHERE ` + f.where + ` AND ` + f.expr + ` IS NOT NULL AND ts >= ? AND ts < ?
		GROUP BY value ORDER BY n DESC, value LIMIT ?`
	rows, err := d.db.QueryContext(ctx, q, r.From, r.To, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []TopItem{}
	for rows.Next() {
		var it TopItem
		if err := rows.Scan(&it.Value, &it.N, &it.Sources, &it.First, &it.Last); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

type EventFilter struct {
	Range
	Before    string // id cursor: only events with a smaller id
	EventType string
	SrcIP     string
	Path      string
	Limit     int
}

// EventRow is one line of the event list; the full event is in EventDetail.
type EventRow struct {
	ID           string    `json:"id"`
	TS           time.Time `json:"ts"`
	EventType    string    `json:"event_type"`
	SrcIP        string    `json:"src_ip"`
	SrcPort      *int      `json:"src_port"`
	DstPort      *int      `json:"dst_port"`
	Method       *string   `json:"http_method"`
	URI          *string   `json:"http_uri"`
	Path         *string   `json:"http_path"`
	UserAgent    *string   `json:"http_user_agent"`
	Status       *int      `json:"http_status"`
	ProxyRequest *bool     `json:"http_proxy_request"`
	BodyLen      *int      `json:"http_body_len"`
	DroppedCount *int      `json:"dropped_count"`
}

// Events lists events newest first (ids are UUIDv7, so id order is time
// order). Pass the last id as Before to get the next page.
func (d *DB) Events(ctx context.Context, f EventFilter) ([]EventRow, error) {
	var where strings.Builder
	where.WriteString(`ts >= ? AND ts < ?`)
	args := []any{f.From, f.To}
	for _, c := range []struct {
		cond string
		val  string
	}{
		{` AND id < ?`, f.Before},
		{` AND event_type = ?`, f.EventType},
		{` AND src_ip = ?`, f.SrcIP},
		{` AND http_path = ?`, f.Path},
	} {
		if c.val != "" {
			where.WriteString(c.cond)
			args = append(args, c.val)
		}
	}
	args = append(args, f.Limit)

	rows, err := d.db.QueryContext(ctx, `
		SELECT id, ts, event_type, src_ip, src_port, dst_port, http_method, http_uri,
			http_path, http_user_agent, http_status, http_proxy_request, http_body_len, dropped_count
		FROM events WHERE `+where.String()+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	evs := []EventRow{}
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.ID, &e.TS, &e.EventType, &e.SrcIP, &e.SrcPort, &e.DstPort, &e.Method, &e.URI,
			&e.Path, &e.UserAgent, &e.Status, &e.ProxyRequest, &e.BodyLen, &e.DroppedCount); err != nil {
			return nil, err
		}
		evs = append(evs, e)
	}
	return evs, rows.Err()
}

type EventDetail struct {
	ReceivedAt time.Time       `json:"received_at"`
	Event      json.RawMessage `json:"event"`
}

var ErrNotFound = errors.New("not found")

func (d *DB) Event(ctx context.Context, id string) (EventDetail, error) {
	var e EventDetail
	var raw string
	err := d.db.QueryRowContext(ctx, `SELECT received_at, event::VARCHAR FROM events WHERE id = ?`, id).Scan(&e.ReceivedAt, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	e.Event = json.RawMessage(raw)
	return e, err
}
