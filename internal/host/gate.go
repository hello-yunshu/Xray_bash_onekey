package host

import (
	"errors"
	"os"
)

// RequireSystemWrite gates any command that writes outside a disposable
// sandbox. A sandbox root must carry the Phase 01 marker; the real root
// requires the container acknowledgement plus the two environment markers the
// Phase 02 install path already uses. It never touches a real VPS silently.
func RequireSystemWrite(root string, ack bool) error {
	if root != "/" {
		p, err := NewPaths(root)
		if err != nil {
			return err
		}
		return p.RequireSandbox()
	}
	if !ack {
		return errors.New("real root writes require --container")
	}
	if os.Getenv("IDLELEO_ALLOW_SYSTEM_WRITES") != "I_ACCEPT_CONTAINER_ONLY" {
		return errors.New("real root writes require IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY")
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return nil
		}
	}
	return errors.New("refusing real root writes outside a container")
}
