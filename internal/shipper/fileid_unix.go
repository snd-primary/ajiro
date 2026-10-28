//go:build unix

package shipper

import (
	"os"
	"syscall"
)

// fileID identifies a file independently of its name, so that a rename by
// logrotate can be told apart from new data in the same file.
type fileID struct {
	Dev uint64
	Ino uint64
}

func idOf(fi os.FileInfo) fileID {
	st := fi.Sys().(*syscall.Stat_t)
	return fileID{Dev: uint64(st.Dev), Ino: st.Ino}
}
