package collector

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"

	_ "github.com/duckdb/duckdb-go/v2"
)

// DuckDB settings applied on open. The database holds attacker-written
// strings, so everything that lets SQL reach outside the process is off:
// no extension downloads, no reading files or URLs from SQL.
var dbSettings = url.Values{
	"autoinstall_known_extensions": {"false"},
	"autoload_known_extensions":    {"false"},
	"enable_external_access":       {"false"},
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id                  VARCHAR PRIMARY KEY,
	ts                  TIMESTAMP NOT NULL, -- UTC, as reported by the sensor
	received_at         TIMESTAMP NOT NULL, -- UTC, when the collector took it
	sensor              VARCHAR NOT NULL,
	event_type          VARCHAR NOT NULL,
	src_ip              VARCHAR NOT NULL,
	src_port            INTEGER,
	dst_port            INTEGER,
	http_method         VARCHAR,
	http_uri            VARCHAR,
	http_host           VARCHAR,
	http_path           VARCHAR,
	http_query          VARCHAR,
	http_user_agent     VARCHAR,
	http_proxy_request  BOOLEAN,
	http_status         INTEGER,
	http_body_len       INTEGER,
	http_body_sha256    VARCHAR,
	http_body_truncated BOOLEAN,
	dropped_count       INTEGER,
	event               JSON NOT NULL -- the full validated event
)`

const insertEvent = `INSERT OR IGNORE INTO events VALUES
	(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// DB is the collector's DuckDB database. Only the collector writes to it
// (CLAUDE.md); events are deduplicated by id because shippers resend.
type DB struct {
	db *sql.DB
}

func OpenDB(path string) (*DB, error) {
	return openDB(path, nil)
}

// OpenDBReadOnly opens path for queries. It fails while a collector has the
// database open for writing.
func OpenDBReadOnly(path string) (*DB, error) {
	return openDB(path, url.Values{"access_mode": {"read_only"}})
}

func openDB(path string, extra url.Values) (*DB, error) {
	q := url.Values{}
	for k, v := range dbSettings {
		q[k] = v
	}
	for k, v := range extra {
		q[k] = v
	}
	db, err := sql.Open("duckdb", path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	if extra.Get("access_mode") != "read_only" {
		if _, err := db.Exec(schema); err != nil {
			db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error { return d.db.Close() }

// SQL exposes the handle for read-only queries.
func (d *DB) SQL() *sql.DB { return d.db }

// Insert adds records in one transaction. Values are always bound as
// parameters, never formatted into SQL.
func (d *DB) Insert(ctx context.Context, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, insertEvent)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range recs {
		args, err := eventArgs(r)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func eventArgs(r Record) ([]any, error) {
	ev := r.Event
	full, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	args := []any{
		ev.ID, ev.Time.UTC(), r.ReceivedAt.UTC(), ev.Sensor, ev.EventType,
		ev.SrcIP, ev.SrcPort, ev.DstPort,
	}
	if h := ev.HTTP; h != nil {
		args = append(args, h.Method, h.URI, h.Host, h.Path, h.Query,
			h.Headers.Get("User-Agent"), h.ProxyRequest, h.Status,
			h.BodyLen, nullString(h.BodySHA256), h.BodyTruncated)
	} else {
		args = append(args, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	}
	if ev.Dropped != nil {
		args = append(args, ev.Dropped.Count)
	} else {
		args = append(args, nil)
	}
	return append(args, string(full)), nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
