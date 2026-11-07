package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteAuditRel is the append-only record of real-root write approvals.
const WriteAuditRel = "var/log/idleleo/system-writes.log"

// containerMarkers is a variable so tests can simulate both sides of the
// boundary without changing the production paths.
var containerMarkers = []string{"/.dockerenv", "/run/.containerenv"}

// InContainer reports whether this process runs inside a container. The marker
// must be a regular file: binding an empty directory over it is a supported way
// to simulate a real-host run in tests.
func InContainer() bool {
	for _, marker := range containerMarkers {
		fi, err := os.Stat(marker)
		if err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// RequireSystemWrite gates commands that write outside a disposable sandbox.
//
// A sandbox root must carry the Phase 01 marker. On the real root, container
// runs still require the explicit --container acknowledgement plus the
// IDLELEO_ALLOW_SYSTEM_WRITES environment value; a real host (no container
// marker) is allowed so an actual VPS can migrate, but every such write is
// appended to WriteAuditRel before it proceeds. If the audit trail cannot be
// written, the write is refused.
func RequireSystemWrite(root string, ack bool) error {
	if root != "/" {
		p, err := NewPaths(root)
		if err != nil {
			return err
		}
		return p.RequireSandbox()
	}
	mode, err := writeMode(ack)
	if err != nil {
		return err
	}
	if err := recordSystemWrite(root, mode); err != nil {
		return fmt.Errorf("system write refused: audit trail unavailable: %w", err)
	}
	return nil
}

// writeMode decides whether a real-root write is allowed. Container runs need
// both the flag and the environment acknowledgement; a real host does not.
func writeMode(ack bool) (string, error) {
	if !InContainer() {
		return "host", nil
	}
	if !ack {
		return "", errors.New("container root writes require --container")
	}
	if os.Getenv("IDLELEO_ALLOW_SYSTEM_WRITES") != "I_ACCEPT_CONTAINER_ONLY" {
		return "", errors.New("container root writes require IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY")
	}
	return "container", nil
}

func recordSystemWrite(root, mode string) error {
	dir := filepath.Join(root, "var/log/idleleo")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(root, WriteAuditRel)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	line := fmt.Sprintf("%s mode=%s uid=%d pid=%d argv=%q\n",
		time.Now().UTC().Format(time.RFC3339), mode, os.Geteuid(), os.Getpid(),
		strings.Join(os.Args, " "))
	_, err = f.WriteString(line)
	return err
}
