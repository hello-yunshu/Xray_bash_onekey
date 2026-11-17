package tcpcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// OSBackend is the real host implementation. Every path goes through
// host.Paths.Join, so a sandbox root redirects both the managed file and the
// /proc/sys reads/writes into the disposable directory.
type OSBackend struct {
	Paths host.Paths
}

func (b OSBackend) GOOS() string { return runtime.GOOS }

func (b OSBackend) abs(rel string) (string, error) { return b.Paths.Join(rel, true) }

func sysctlRel(key string) string {
	return "proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

func (b OSBackend) KernelRelease() (string, error) {
	path, err := b.abs("proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (b OSBackend) ReadSysctl(key string) (string, error) {
	path, err := b.abs(sysctlRel(key))
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (b OSBackend) ListCongestion() ([]string, error) {
	raw, err := b.ReadSysctl("net.ipv4.tcp_available_congestion_control")
	if err != nil {
		return nil, err
	}
	return strings.Fields(raw), nil
}

// WriteSysctl writes exactly one key. It never replays `sysctl --system`, so
// unrelated keys in /etc/sysctl.d are not re-applied with elevated effects.
func (b OSBackend) WriteSysctl(key, value string) error {
	path, err := b.abs(sysctlRel(key))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(value + "\n"); err != nil {
		return err
	}
	return nil
}

func (b OSBackend) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (b OSBackend) StatFile(path string) (FileState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return FileState{}, nil
		}
		return FileState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return FileState{}, fmt.Errorf("symlink refused: %s", path)
	}
	state := FileState{Exists: true, Mode: info.Mode().Perm()}
	if raw, ok := info.Sys().(*syscall.Stat_t); ok {
		state.UID = int(raw.Uid)
		state.GID = int(raw.Gid)
	}
	return state, nil
}

// WriteFile is atomic: a temp file in the target directory is renamed into
// place, so a crash never leaves a half-written sysctl file.
func (b OSBackend) WriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".idleleo-tcp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	return nil
}

func (b OSBackend) Chown(path string, uid, gid int) error { return os.Chown(path, uid, gid) }

func (b OSBackend) RemoveFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (b OSBackend) ListDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (b OSBackend) Root() bool { return os.Geteuid() == 0 }

// Lock reuses the update flock primitive but on a TCP-specific lock file, so
// TCP tuning does not block config updates and vice versa.
func (b OSBackend) Lock(path string) (func(), error) {
	lock, err := host.AcquireUpdate(path)
	if err != nil {
		return nil, err
	}
	return lock.Release, nil
}
