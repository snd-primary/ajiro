package webpot

import (
	"encoding/json"
	"io"
	"os"
	"sync"
)

// Logger appends events as JSON Lines. Reopen supports external log rotation
// (rename the file, then send SIGHUP).
type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
	w    io.Writer
}

// OpenLogger opens path for appending. "-" writes to stdout.
func OpenLogger(path string) (*Logger, error) {
	l := &Logger{path: path}
	if path == "-" {
		l.w = os.Stdout
		return l, nil
	}
	if err := l.Reopen(); err != nil {
		return nil, err
	}
	return l, nil
}

// NewLogger writes to w. Used by tests.
func NewLogger(w io.Writer) *Logger { return &Logger{w: w} }

func (l *Logger) Reopen() error {
	if l.path == "" || l.path == "-" {
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	l.mu.Lock()
	old := l.f
	l.f, l.w = f, f
	l.mu.Unlock()
	if old != nil {
		return old.Close()
	}
	return nil
}

func (l *Logger) Write(ev *Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.w.Write(b)
	return err
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}
