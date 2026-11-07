package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked means another Phase 01 update already owns the resource.
var ErrLocked = errors.New("another update holds the idleleo lock")

// UpdateLock is an exclusive flock held for one change transaction.
type UpdateLock struct {
	file *os.File
}

// AcquireUpdate takes a non-blocking exclusive lock. The OS releases it if
// the process exits, so a SIGKILL cannot strand the lock.
func AcquireUpdate(path string) (*UpdateLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &UpdateLock{file: f}, nil
}

// Release unlocks and closes the descriptor.
func (l *UpdateLock) Release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}
