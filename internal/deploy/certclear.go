package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const managedCertRel = "etc/idleleo/cert"

// ClearCertsSpec is one "clear every managed certificate" request.
type ClearCertsSpec struct {
	Root                 string
	AllowContainerWrites bool
	DryRun               bool
}

// ClearCertsReport is the machine-readable result.
type ClearCertsReport struct {
	Dir      string   `json:"dir"`
	Removed  []string `json:"removed"`
	Skipped  []string `json:"skipped,omitempty"`
	Missing  bool     `json:"missing"`
	DryRun   bool     `json:"dryRun"`
	Warnings []string `json:"warnings"`
}

// ClearCertificates deletes ACME and imported material under the managed
// certificate directory, plus acme.sh's *_ecc account directories on the real
// system. It never follows symlinks and is idempotent when the directory is
// already empty.
func ClearCertificates(ctx context.Context, spec ClearCertsSpec) (ClearCertsReport, error) {
	rep := ClearCertsReport{DryRun: spec.DryRun, Removed: []string{}, Warnings: []string{}}
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return rep, err
	}
	dir, err := paths.Join(managedCertRel, false)
	if err != nil {
		if os.IsNotExist(err) {
			rep.Missing = true
			return rep, nil
		}
		return rep, err
	}
	rep.Dir = dir

	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return rep, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return rep, err
		}
		defer lock.Release()
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			rep.Missing = true
			return rep, nil
		}
		return rep, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		target := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(target)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return rep, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			rep.Skipped = append(rep.Skipped, target)
			rep.Warnings = append(rep.Warnings, "symlink left untouched: "+target)
			continue
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			rep.Skipped = append(rep.Skipped, target)
			rep.Warnings = append(rep.Warnings, "special file left untouched: "+target)
			continue
		}
		if !spec.DryRun {
			if err := os.RemoveAll(target); err != nil {
				return rep, err
			}
		}
		rep.Removed = append(rep.Removed, target)
	}

	// acme.sh keeps account state outside the managed tree. Only touch it on
	// the real root so a sandbox test can never delete the operator's account.
	if paths.Root == "/" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			removed, skipped, warnings := clearAcmeState(filepath.Join(home, ".acme.sh"), spec.DryRun)
			rep.Removed = append(rep.Removed, removed...)
			rep.Skipped = append(rep.Skipped, skipped...)
			rep.Warnings = append(rep.Warnings, warnings...)
		}
	}
	return rep, nil
}

func clearAcmeState(dir string, dryRun bool) (removed, skipped, warnings []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			warnings = append(warnings, "acme.sh state not scanned: "+err.Error())
		}
		return nil, nil, warnings
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_ecc") {
			continue
		}
		target := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(target)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			skipped = append(skipped, target)
			warnings = append(warnings, "symlink left untouched: "+target)
			continue
		}
		if !dryRun {
			if err := os.RemoveAll(target); err != nil {
				warnings = append(warnings, fmt.Sprintf("remove %s: %v", target, err))
				continue
			}
		}
		removed = append(removed, target)
	}
	return removed, skipped, warnings
}
