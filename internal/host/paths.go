// Package host owns path resolution, the update lock, and controlled
// external command execution. It never invokes a shell.
package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SandboxMarker is the only accepted Phase 01 mutation sandbox marker.
const SandboxMarker = ".idleleo-phase01-sandbox"
const SandboxMarkerValue = "I_ACCEPT_DISPOSABLE_SANDBOX"

// Paths maps the product layout under an explicit root. root="/" is the real
// system; any other root is a disposable test sandbox.
type Paths struct {
	Root string
}

// NewPaths validates and resolves the root once.
func NewPaths(root string) (Paths, error) {
	if strings.TrimSpace(root) == "" {
		return Paths{}, errors.New("root required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Paths{}, err
	}
	if abs != "/" {
		abs, err = filepath.EvalSymlinks(abs)
		if err != nil {
			return Paths{}, fmt.Errorf("resolve root: %w", err)
		}
	}
	if abs != "/" {
		fi, err := os.Lstat(abs)
		if err != nil {
			return Paths{}, err
		}
		if !fi.IsDir() {
			return Paths{}, errors.New("root is not a directory")
		}
	}
	return Paths{Root: abs}, nil
}

// IsSandbox reports whether this root is a disposable directory.
func (p Paths) IsSandbox() bool { return p.Root != "/" }

// Join resolves rel under the root. It rejects absolute paths, "..", and
// symlink components. Existing final symlinks are rejected; missing parents
// are allowed only for writes.
func (p Paths) Join(rel string, forWrite bool) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(rel) || clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe relative path")
	}
	parts := strings.Split(clean, string(os.PathSeparator))
	cur := p.Root
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		last := i == len(parts)-1
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				if last || forWrite {
					continue
				}
				return "", err
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink refused: %s", cur)
		}
		if last {
			if !fi.Mode().IsRegular() && forWrite {
				return "", fmt.Errorf("target is not a regular file: %s", cur)
			}
		} else if !fi.IsDir() {
			return "", fmt.Errorf("unsafe parent: %s", cur)
		}
	}
	return cur, nil
}

// Layout paths. All are relative for Join.
func (p Paths) ManagerMetadata() string { return "etc/idleleo/v1/metadata.json" }
func (p Paths) LegacyConfig() string    { return "etc/idleleo/conf/install_config.json" }
func (p Paths) RuntimeConfig() string   { return "etc/idleleo/conf/xray/config.json" }
func (p Paths) StatusConfig() string    { return "etc/idleleo/conf/status_config.json" }
func (p Paths) RelayConfig() string     { return "etc/idleleo/conf/nginx/relay-stream.conf" }
func (p Paths) InfoFile() string        { return "etc/idleleo/info/xray_info.inf" }
func (p Paths) TransactionsDir() string { return "var/lib/idleleo/transactions" }

// LockFile returns the Phase 01 update lock. It deliberately matches the
// existing Bash lock name so the switch window cannot run two writers.
func (p Paths) LockFile() string {
	if p.IsSandbox() {
		return filepath.Join(p.Root, "run/lock/idleleo-update.lock")
	}
	return "/run/lock/idleleo-update.lock"
}

// JournalFile is a bounded transaction record, never a secret store.
func (p Paths) JournalFile() string {
	return filepath.Join(p.Root, p.TransactionsDir(), "phase01.json")
}

// RequireSandbox accepts only a marked disposable root. Phase 01 must never
// mutate the real system.
func (p Paths) RequireSandbox() error {
	if !p.IsSandbox() {
		return errors.New("Phase 01 mutation requires a disposable sandbox root")
	}
	pth, err := p.Join(SandboxMarker, false)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(pth)
	if err != nil {
		return fmt.Errorf("sandbox marker required: %w", err)
	}
	if strings.TrimSpace(string(b)) != SandboxMarkerValue {
		return errors.New("sandbox marker value mismatch")
	}
	return nil
}
