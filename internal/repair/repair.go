// Package repair applies the safe, reversible subset of doctor findings. It
// never invents configuration: it fixes directories, restrictive modes, stale
// temporary files and expired locks, then reports what still needs a human.
//
// Every path is resolved with Lstat component by component: a symlink anywhere
// in the chain is reported and never chmod/chown/removed.
package repair

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const SchemaVersion = 1

// Report lists what changed and what could not be fixed automatically.
type Report struct {
	SchemaVersion int      `json:"schemaVersion"`
	Root          string   `json:"root"`
	DryRun        bool     `json:"dryRun"`
	Actions       []string `json:"actions"`
	Remaining     []string `json:"remaining"`
	Healthy       bool     `json:"healthy"`
}

// Options controls the repair pass.
type Options struct {
	DryRun  bool
	Now     time.Time
	FixLock bool
}

// Run applies or previews repairs. Without FixLock an expired lock is only
// reported, because deleting a lock another process still holds is unsafe.
func Run(ctx context.Context, root string, opts Options) (Report, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	paths, err := host.NewPaths(root)
	if err != nil {
		return Report{}, err
	}
	rep := Report{SchemaVersion: SchemaVersion, Root: root, DryRun: opts.DryRun}
	if ctx.Err() != nil {
		return rep, ctx.Err()
	}
	// A real repair shares the same mutex as backup/restore and install, so it
	// cannot race a writer. A dry run stays read-only and takes no lock.
	var held bool
	if !opts.DryRun {
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			if errors.Is(err, host.ErrLocked) {
				return rep, errors.New("another update is running; rerun repair after it finishes")
			}
			return rep, err
		}
		defer lock.Release()
		held = true
	}
	for _, d := range []struct {
		rel  string
		mode os.FileMode
	}{
		{"etc/idleleo/conf", 0o750},
		{"etc/idleleo/conf/xray", 0o750},
		{"etc/idleleo/cert", 0o750},
		{"etc/idleleo/v1", 0o750},
		{"etc/idleleo/info", 0o750},
		{"etc/idleleo/alerts", 0o750},
		{"etc/idleleo/backup", 0o700},
	} {
		p, statErr := resolve(root, d.rel, false)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			rep.do(opts, "create "+d.rel, func() error {
				_, err := mkdirSecure(root, d.rel, d.mode)
				return err
			})
		case statErr != nil:
			rep.Remaining = append(rep.Remaining, d.rel+": "+statErr.Error())
		default:
			fi, err := os.Lstat(p)
			if err != nil {
				rep.Remaining = append(rep.Remaining, d.rel+": "+err.Error())
				continue
			}
			switch {
			case !fi.IsDir():
				rep.Remaining = append(rep.Remaining, d.rel+": not a directory")
			case fi.Mode().Perm() != d.mode:
				rep.do(opts, fmt.Sprintf("set mode of %s to %04o", d.rel, d.mode), func() error { return os.Chmod(p, d.mode) })
			}
		}
	}
	// A runtime config and its key must not be readable by other users.
	for _, f := range []struct {
		rel  string
		mode os.FileMode
	}{
		{paths.RuntimeConfig(), 0o640},
		{"etc/idleleo/cert/xray.key", 0o600},
		{"etc/idleleo/cert/xray.crt", 0o644},
		{"etc/idleleo/v1/metadata.json", 0o600},
	} {
		p, statErr := resolve(root, f.rel, false)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			rep.Remaining = append(rep.Remaining, f.rel+": "+statErr.Error())
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil {
			rep.Remaining = append(rep.Remaining, f.rel+": "+err.Error())
			continue
		}
		if !fi.Mode().IsRegular() {
			rep.Remaining = append(rep.Remaining, f.rel+": not a regular file")
			continue
		}
		if fi.Mode().Perm() != f.mode {
			rep.do(opts, fmt.Sprintf("set mode of %s to %04o", f.rel, f.mode), func() error { return os.Chmod(p, f.mode) })
		}
	}
	// The service runs as the unprivileged xray account. Hardening the file to
	// 0600 root:root would make the *next* restart fail, so the group must stay
	// aligned with that account.
	rep.fixServiceGroup(paths, opts)
	rep.checkConfig(paths, opts)
	rep.checkCertificate(root)
	rep.checkLock(paths, opts, held)
	rep.checkTemp(root, opts)
	sort.Strings(rep.Actions)
	rep.Healthy = len(rep.Remaining) == 0
	return rep, nil
}

// resolve walks rel under root and refuses any symlink component. With
// allowMissing the caller gets the target path back when the tail is absent.
func resolve(root, rel string, allowMissing bool) (string, error) {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := root
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("unsafe path %q", rel)
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			if allowMissing && errors.Is(err, os.ErrNotExist) {
				return cur, nil
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlink refused: %s", cur)
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return "", fmt.Errorf("not a directory: %s", cur)
		}
	}
	return cur, nil
}

// mkdirSecure creates rel one component at a time without ever passing through
// an existing symlink.
func mkdirSecure(root, rel string, mode os.FileMode) (string, error) {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := root
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("unsafe path %q", rel)
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		switch {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("symlink refused: %s", cur)
			}
			if !fi.IsDir() {
				return "", fmt.Errorf("not a directory: %s", cur)
			}
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(cur, mode); err != nil {
				return "", err
			}
		default:
			return "", err
		}
	}
	return cur, nil
}

// fixServiceGroup keeps the runtime config and its directory readable by the
// xray service account's group. Ownership itself stays root-owned.
func (r *Report) fixServiceGroup(paths host.Paths, opts Options) {
	g, err := user.LookupGroup("xray")
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	for _, rel := range []string{"etc/idleleo/conf", filepath.Dir(paths.RuntimeConfig()), paths.RuntimeConfig()} {
		p, statErr := resolve(paths.Root, rel, false)
		if statErr != nil {
			continue
		}
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Gid) == gid {
			continue
		}
		r.do(opts, "set group of "+rel+" to xray", func() error { return os.Chown(p, -1, gid) })
	}
}

// do performs one repair, or records exactly what a dry run would have done.
func (r *Report) do(opts Options, label string, fn func() error) {
	if opts.DryRun {
		r.Actions = append(r.Actions, "would "+label)
		return
	}
	if err := fn(); err != nil {
		r.Remaining = append(r.Remaining, label+": "+err.Error())
		return
	}
	r.Actions = append(r.Actions, label)
}

func (r *Report) checkConfig(paths host.Paths, opts Options) {
	configPath, err := paths.Join(paths.RuntimeConfig(), false)
	if err != nil {
		r.Remaining = append(r.Remaining, "runtime config is missing")
		return
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		r.Remaining = append(r.Remaining, "runtime config is not readable: "+err.Error())
		return
	}
	var any map[string]any
	if err := json.Unmarshal(body, &any); err != nil {
		r.Remaining = append(r.Remaining, "runtime config is not valid JSON: "+err.Error())
	}
}

func (r *Report) checkCertificate(root string) {
	p, err := resolve(root, "etc/idleleo/cert/xray.crt", false)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.Remaining = append(r.Remaining, "etc/idleleo/cert/xray.crt: "+err.Error())
		}
		return
	}
	body, err := os.ReadFile(p)
	if err != nil {
		return
	}
	block, _ := pem.Decode(body)
	if block == nil {
		r.Remaining = append(r.Remaining, "certificate is not PEM")
		return
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		r.Remaining = append(r.Remaining, "certificate cannot be parsed: "+err.Error())
	}
}

func (r *Report) checkLock(paths host.Paths, opts Options, selfHeld bool) {
	fi, err := os.Stat(paths.LockFile())
	if err != nil {
		return
	}
	// A lock file that a finished transaction left behind is not held. Testing
	// the flock avoids reporting a healthy root as busy forever. When this run
	// holds the lock itself, the probe would always report "held", so skip it.
	heldByOther := false
	if !selfHeld {
		held, heldErr := host.LockHeld(paths.LockFile())
		if heldErr != nil {
			return
		}
		heldByOther = held
	}
	if !heldByOther && opts.FixLock {
		r.do(opts, "remove stale update lock", func() error {
			err := os.Remove(paths.LockFile())
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		})
		return
	}
	if heldByOther {
		r.Remaining = append(r.Remaining, "an update lock is held; rerun after it finishes")
		return
	}
	if opts.Now.Sub(fi.ModTime()) <= 30*time.Minute {
		return
	}
	if !opts.FixLock {
		r.Remaining = append(r.Remaining, "stale update lock; rerun with --fix-lock to remove it")
		return
	}
	r.do(opts, "remove stale update lock", func() error {
		err := os.Remove(paths.LockFile())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
}

// checkTemp removes only our own abandoned restore staging directories. A
// symlink is reported, never followed or removed.
func (r *Report) checkTemp(root string, opts Options) {
	dir, err := resolve(root, "var/tmp", false)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.Remaining = append(r.Remaining, "var/tmp: "+err.Error())
		}
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if len(name) < 8 || name[:8] != "restore-" {
			continue
		}
		target := filepath.Join(dir, name)
		fi, err := os.Lstat(target)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			r.Remaining = append(r.Remaining, "refusing to remove symlink var/tmp/"+name)
			continue
		}
		if !fi.IsDir() || opts.Now.Sub(fi.ModTime()) < time.Hour {
			continue
		}
		r.do(opts, "remove abandoned staging directory var/tmp/"+name, func() error { return os.RemoveAll(target) })
	}
}
