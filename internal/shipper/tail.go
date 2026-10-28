package shipper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

// State is how far the input has been delivered. It is saved after every
// accepted batch so a restart resumes where it stopped.
type State struct {
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Offset int64  `json:"offset"`
}

func loadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// saveState writes atomically: a crash leaves either the old or the new state.
func saveState(path string, st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".shipper-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// tailer reads complete lines from a file that is appended to and rotated by
// rename. It drains the old file before switching to the new one.
type tailer struct {
	path    string
	maxLine int
	resume  *State // applied on the first open if the file is the same one

	f        *os.File
	id       fileID
	off      int64
	skipping bool // inside a line longer than maxLine
}

func (t *tailer) open() error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	t.f, t.id, t.off = f, idOf(fi), 0
	if st := t.resume; st != nil {
		t.resume = nil
		if (fileID{Dev: st.Dev, Ino: st.Ino}) == t.id {
			t.off = st.Offset
		} else {
			slog.Warn("input file changed while stopped; reading the new file from the start (unsent lines of the old file are not sent)")
		}
	}
	return nil
}

func (t *tailer) state() State { return State{Dev: t.id.Dev, Ino: t.id.Ino, Offset: t.off} }

func (t *tailer) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// next returns complete lines from the current offset, at most maxBytes in
// total, and the offset just past them. The offset only moves on commit,
// except over data that is dropped (over-long lines) or after a rotation.
func (t *tailer) next(maxBytes int) ([][]byte, int64, error) {
	if t.f == nil {
		if err := t.open(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, t.off, nil
			}
			return nil, t.off, err
		}
	}
	fi, err := t.f.Stat()
	if err != nil {
		return nil, t.off, err
	}
	if fi.Size() < t.off {
		slog.Warn("input was truncated; reading it from the start")
		t.off, t.skipping = 0, false
	}

	buf := make([]byte, maxBytes)
	n, err := t.f.ReadAt(buf, t.off)
	if err != nil && err != io.EOF {
		return nil, t.off, err
	}
	buf = buf[:n]

	if t.skipping {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			t.off += int64(n)
			return nil, t.off, nil
		}
		t.off += int64(i + 1)
		t.skipping = false
		return t.next(maxBytes)
	}

	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		if n >= t.maxLine {
			slog.Warn("dropping an input line longer than the limit", "limit", t.maxLine)
			t.off += int64(n)
			t.skipping = true
			return nil, t.off, nil
		}
		if t.rotated() {
			if n > 0 {
				slog.Warn("dropping an incomplete last line of the rotated input", "bytes", n)
			}
			t.close()
			t.id, t.off = fileID{}, 0
		}
		return nil, t.off, nil
	}

	var lines [][]byte
	for _, l := range bytes.Split(buf[:end], []byte{'\n'}) {
		switch {
		case len(bytes.TrimSpace(l)) == 0:
		case len(l) > t.maxLine:
			slog.Warn("dropping an input line longer than the limit", "limit", t.maxLine)
		default:
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		t.off += int64(end + 1)
		return nil, t.off, nil
	}
	return lines, t.off + int64(end+1), nil
}

func (t *tailer) commit(off int64) { t.off = off }

// rotated reports whether the path now names a different file than the one
// being read. A missing path (renamed, not yet recreated) is not a rotation.
func (t *tailer) rotated() bool {
	fi, err := os.Stat(t.path)
	if err != nil {
		return false
	}
	return idOf(fi) != t.id
}
