package collector

import (
	"bytes"
	"io"
	"os"
	"sync"
)

// Store appends records to a JSON Lines archive. Reopen supports external log
// rotation (rename the file, then send SIGHUP).
type Store struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    io.Writer
}

// OpenStore opens path for appending. "-" writes to stdout.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	if path == "-" {
		s.w = os.Stdout
		return s, nil
	}
	if err := s.Reopen(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewStore writes to w. Used by tests.
func NewStore(w io.Writer) *Store { return &Store{w: w} }

func (s *Store) Reopen() error {
	if s.path == "" || s.path == "-" {
		return nil
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.f
	s.f, s.w = f, f
	s.mu.Unlock()
	if old != nil {
		return old.Close()
	}
	return nil
}

// Append writes a batch in one write and, for files, syncs it to disk before
// returning: the shipper may discard its copy once we answer 200.
func (s *Store) Append(lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(buf.Bytes()); err != nil {
		return err
	}
	if s.f != nil {
		return s.f.Sync()
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}
