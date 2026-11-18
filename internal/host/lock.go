package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
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

// AcquireUpdateWait retries a non-blocking lock until timeout. Concurrent hot
// user changes queue instead of failing; the wait is bounded so a wedged
// holder still surfaces as ErrLocked.
func AcquireUpdateWait(path string, timeout time.Duration) (*UpdateLock, error) {
	deadline := time.Now().Add(timeout)
	for {
		l, err := AcquireUpdate(path)
		if err == nil {
			return l, nil
		}
		if !errors.Is(err, ErrLocked) || !time.Now().Before(deadline) {
			return nil, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// LockHeld reports whether another process currently holds the lock. A lock
// file left behind by a finished transaction is not "held".
func LockHeld(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return true, nil
		}
		return false, err
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, nil
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
