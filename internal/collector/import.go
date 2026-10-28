package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
)

// Import loads a JSON Lines archive written by Store into db, for example to
// rebuild the database. Lines are validated again; events already in db are
// skipped by id.
func Import(ctx context.Context, r io.Reader, db *DB, maxLine int) (imported, rejected int, err error) {
	const batch = 1000
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, min(64<<10, maxLine)), maxLine)
	var recs []Record
	flush := func() error {
		if err := db.Insert(ctx, recs); err != nil {
			return err
		}
		imported += len(recs)
		recs = recs[:0]
		return nil
	}
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		rec, err := parseRecord(line)
		if err != nil {
			rejected++
			slog.Warn("skip archive line", "line", n, "reason", err)
			continue
		}
		recs = append(recs, rec)
		if len(recs) == batch {
			if err := flush(); err != nil {
				return imported, rejected, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return imported, rejected, err
	}
	return imported, rejected, flush()
}

func parseRecord(line []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return rec, errMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return rec, errTrailing
	}
	if rec.ReceivedAt.IsZero() || rec.Event == nil {
		return rec, errors.New("bad record")
	}
	return rec, validate(rec.Event)
}
