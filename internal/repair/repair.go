// Package repair applies the safe, reversible subset of doctor findings. It
// never invents configuration: it fixes directories, restrictive modes, stale
// temporary files and expired locks, then reports what still needs a human.
package repair

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	for _, d := range []struct {
		rel  string
		mode os.FileMode
	}{
		{"etc/idleleo/conf", 0o750},
		{"etc/idleleo/cert", 0o750},
		{"etc/idleleo/v1", 0o750},
		{"etc/idleleo/info", 0o750},
		{"etc/idleleo/alerts", 0o750},
		{"etc/idleleo/backup", 0o700},
	} {
		p := filepath.Join(root, d.rel)
		fi, statErr := os.Stat(p)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			rep.do(opts, "create "+d.rel, func() error { return os.MkdirAll(p, d.mode) })
		case statErr != nil:
			rep.Remaining = append(rep.Remaining, d.rel+": "+statErr.Error())
		case !fi.IsDir():
			rep.Remaining = append(rep.Remaining, d.rel+": not a directory")
		case fi.Mode().Perm() != d.mode:
			rep.do(opts, fmt.Sprintf("set mode of %s to %04o", d.rel, d.mode), func() error { return os.Chmod(p, d.mode) })
		}
	}
	// A runtime config and its key must not be readable by other users.
	for _, f := range []struct {
		rel  string
		mode os.FileMode
	}{
		{paths.RuntimeConfig(), 0o600},
		{"etc/idleleo/cert/xray.key", 0o600},
		{"etc/idleleo/cert/xray.crt", 0o644},
		{"etc/idleleo/v1/metadata.json", 0o600},
	} {
		p := filepath.Join(root, f.rel)
		fi, statErr := os.Stat(p)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			rep.Remaining = append(rep.Remaining, f.rel+": "+statErr.Error())
			continue
		}
		if fi.Mode().Perm() != f.mode {
			rep.do(opts, fmt.Sprintf("set mode of %s to %04o", f.rel, f.mode), func() error { return os.Chmod(p, f.mode) })
		}
	}
	rep.checkConfig(paths, opts)
	rep.checkCertificate(root)
	rep.checkLock(paths, opts)
	rep.checkTemp(root, opts)
	sort.Strings(rep.Actions)
	rep.Healthy = len(rep.Remaining) == 0
	return rep, nil
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
	p := filepath.Join(root, "etc/idleleo/cert/xray.crt")
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

func (r *Report) checkLock(paths host.Paths, opts Options) {
	fi, err := os.Stat(paths.LockFile())
	if err != nil {
		return
	}
	if opts.Now.Sub(fi.ModTime()) <= 30*time.Minute {
		r.Remaining = append(r.Remaining, "an update lock is held; rerun after it finishes")
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

// checkTemp removes only our own abandoned restore staging directories.
func (r *Report) checkTemp(root string, opts Options) {
	dir := filepath.Join(root, "var/tmp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) < 8 || e.Name()[:8] != "restore-" {
			continue
		}
		info, err := e.Info()
		if err != nil || opts.Now.Sub(info.ModTime()) < time.Hour {
			continue
		}
		target := filepath.Join(dir, e.Name())
		r.do(opts, "remove abandoned staging directory var/tmp/"+e.Name(), func() error { return os.RemoveAll(target) })
	}
}
