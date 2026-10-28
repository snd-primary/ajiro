// Package shipper tails webpot's JSON Lines output and pushes it to the
// collector's ingest endpoint in batches.
//
// It runs on the honeypot host and is the only process there allowed to send
// anything out. Invariants (HANDOFF.md §4.1, CLAUDE.md guardrails):
//   - It connects to exactly one IP:port, never resolves names, ignores proxy
//     settings and does not follow redirects (see Target and NewClient).
//   - It only forwards lines; it never interprets or executes their content.
//
// Delivery is at-least-once: a batch is resent until the collector answers
// 200, so the collector may see duplicates (deduplicate by event id).
package shipper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type Config struct {
	Input      string // webpot JSON Lines file
	StatePath  string
	Token      string
	BatchBytes int // request body bytes per batch; must exceed MaxLine
	MaxLine    int // longer input lines are dropped
	Poll       time.Duration
	MaxBackoff time.Duration
}

func DefaultConfig() Config {
	return Config{
		BatchBytes: 1 << 20,
		MaxLine:    512 << 10,
		Poll:       time.Second,
		MaxBackoff: time.Minute,
	}
}

type Shipper struct {
	cfg    Config
	target *Target
	client *http.Client
	tail   *tailer
	saved  State
}

func New(cfg Config, target *Target, client *http.Client) (*Shipper, error) {
	if cfg.Token == "" {
		return nil, errors.New("shipper: empty token")
	}
	if cfg.Input == "" || cfg.StatePath == "" {
		return nil, errors.New("shipper: input and state paths are required")
	}
	if cfg.BatchBytes <= cfg.MaxLine {
		return nil, errors.New("shipper: batch bytes must exceed max line")
	}
	st, err := loadState(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("shipper: load state: %w", err)
	}
	s := &Shipper{
		cfg:    cfg,
		target: target,
		client: client,
		tail:   &tailer{path: cfg.Input, maxLine: cfg.MaxLine, resume: st},
	}
	if st != nil {
		s.saved = *st
	}
	return s, nil
}

// Run ships until ctx is cancelled.
func (s *Shipper) Run(ctx context.Context) error {
	defer s.tail.close()
	for {
		lines, off, err := s.tail.next(s.cfg.BatchBytes)
		if err != nil {
			slog.Error("read input", "err", err)
		}
		if len(lines) == 0 {
			s.save()
			if !sleep(ctx, s.cfg.Poll) {
				return nil
			}
			continue
		}
		if err := s.deliver(ctx, lines); err != nil {
			return nil // only fails when ctx is done
		}
		s.tail.commit(off)
		s.save()
	}
}

func (s *Shipper) save() {
	st := s.tail.state()
	if st == s.saved || s.tail.f == nil {
		return
	}
	if err := saveState(s.cfg.StatePath, st); err != nil {
		slog.Error("save state", "err", err)
		return
	}
	s.saved = st
}

// refusedError means the collector will never take this batch as is.
type refusedError struct{ status int }

func (e *refusedError) Error() string { return fmt.Sprintf("collector refused batch: %d", e.status) }

// deliver sends lines until the collector stores them or ctx is done. A batch
// the collector refuses as too large or malformed is split in half; a single
// refused line is dropped so that it cannot block everything after it.
func (s *Shipper) deliver(ctx context.Context, lines [][]byte) error {
	backoff := time.Second
	for {
		err := s.send(ctx, lines)
		if err == nil {
			return nil
		}
		var refused *refusedError
		if errors.As(err, &refused) {
			if len(lines) == 1 {
				slog.Warn("collector refused a line; dropping it", "status", refused.status)
				return nil
			}
			mid := len(lines) / 2
			if err := s.deliver(ctx, lines[:mid]); err != nil {
				return err
			}
			return s.deliver(ctx, lines[mid:])
		}
		slog.Warn("send failed; retrying", "err", err, "in", backoff)
		if !sleep(ctx, backoff) {
			return ctx.Err()
		}
		backoff = min(backoff*2, s.cfg.MaxBackoff)
	}
}

func (s *Shipper) send(ctx context.Context, lines [][]byte) error {
	body := append(bytes.Join(lines, []byte{'\n'}), '\n')
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.target.URL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

	switch resp.StatusCode {
	case http.StatusOK:
		var res struct {
			Accepted int `json:"accepted"`
			Rejected int `json:"rejected"`
		}
		if err := json.Unmarshal(respBody, &res); err != nil {
			slog.Warn("unreadable collector response; treating batch as stored")
		}
		if res.Rejected > 0 {
			slog.Warn("collector rejected events", "accepted", res.Accepted, "rejected", res.Rejected)
		}
		return nil
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		return &refusedError{status: resp.StatusCode}
	default:
		return fmt.Errorf("collector answered %d", resp.StatusCode)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
