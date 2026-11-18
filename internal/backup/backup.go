// Package backup creates, verifies and restores archives of the manager-owned
// state. Archives carry private keys, so creation refuses to overwrite and
// uses 0600; verification never extracts and restore refuses path escapes,
// links and device nodes.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const SchemaVersion = 1

// managedDirs are the only trees an archive may contain and a restore may
// touch. Geodata is opt-in because it is large and reproducible.
var managedDirs = []string{
	"etc/idleleo/conf",
	"etc/idleleo/cert",
	"etc/idleleo/v1",
	"etc/idleleo/info",
	"etc/idleleo/alerts",
}

const geodataDir = "etc/idleleo/share/xray"

// Entry is one archived regular file.
type Entry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is stored inside the archive and is the verification anchor. The
// source fields make a cold migration auditable without unpacking.
type Manifest struct {
	SchemaVersion    int      `json:"schemaVersion"`
	CreatedAt        string   `json:"createdAt"`
	IncludeGeo       bool     `json:"includeGeodata"`
	SourceArch       string   `json:"sourceArch,omitempty"`
	SourceVersion    string   `json:"sourceVersion,omitempty"`
	ManagedResources []string `json:"managedResources"`
	RestoreLimits    []string `json:"restoreLimits"`
	Entries          []Entry  `json:"entries"`
	Skipped          []string `json:"skipped,omitempty"`
}

// Change is one restore difference shown by a dry run.
type Change struct {
	Path   string `json:"path"`
	Action string `json:"action"` // add | replace | unchanged
}

// Report summarises a create or restore without exposing file contents.
type Report struct {
	SchemaVersion int      `json:"schemaVersion"`
	Archive       string   `json:"archive"`
	ArchiveSHA256 string   `json:"archiveSha256"`
	Bytes         int64    `json:"bytes"`
	Files         int      `json:"files"`
	CreatedAt     string   `json:"createdAt"`
	Restored      []string `json:"restored,omitempty"`
	Changes       []Change `json:"changes,omitempty"`
	DryRun        bool     `json:"dryRun,omitempty"`
	PreBackup     string   `json:"preBackup,omitempty"`
	Sensitive     bool     `json:"sensitive"`
}

// CreateOptions narrows what a backup includes.
type CreateOptions struct {
	IncludeGeodata bool
	SourceArch     string
	SourceVersion  string
	Now            time.Time
}

var restoreLimits = []string{
	"only etc/idleleo/{conf,cert,v1,info,alerts} and opt-in geo assets",
	"regular files only; symlinks, devices and path escapes are rejected",
	"the whole archive must expand to at most 4 GiB",
	"the staged xray config must pass the managed validator before any swap",
}

// Create writes a verified tar.gz and returns its digest. It refuses to
// overwrite an existing path and never follows a symlink in the tree.
func Create(ctx context.Context, root, archive string, opts CreateOptions) (Report, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
		return Report{}, err
	}
	out, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Report{}, fmt.Errorf("backup archive: %w", err)
	}
	defer out.Close()

	var entries []Entry
	var skipped []string
	for _, rel := range append(append([]string{}, managedDirs...), maybeGeo(opts.IncludeGeodata)...) {
		dir := filepath.Join(root, rel)
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			relPath, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relPath = filepath.ToSlash(relPath)
			if fi.Mode()&os.ModeSymlink != 0 {
				skipped = append(skipped, relPath+" (symlink)")
				return nil
			}
			if !fi.Mode().IsRegular() {
				skipped = append(skipped, relPath+" (not a regular file)")
				return nil
			}
			entries = append(entries, Entry{Path: relPath, Mode: uint32(fi.Mode().Perm()), Size: fi.Size()})
			return nil
		})
		if err != nil {
			return Report{}, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	now := opts.Now
	for i := range entries {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entries[i].Path)))
		if err != nil {
			return Report{}, err
		}
		sum := sha256.Sum256(body)
		entries[i].SHA256 = hex.EncodeToString(sum[:])
		if err := writeTar(tw, entries[i].Path, entries[i].Mode, now, body); err != nil {
			return Report{}, err
		}
	}
	if opts.SourceArch == "" {
		opts.SourceArch = runtime.GOARCH
	}
	manifest := Manifest{
		SchemaVersion:    SchemaVersion,
		CreatedAt:        now.Format(time.RFC3339),
		IncludeGeo:       opts.IncludeGeodata,
		SourceArch:       opts.SourceArch,
		SourceVersion:    opts.SourceVersion,
		ManagedResources: append(append([]string{}, managedDirs...), maybeGeo(opts.IncludeGeodata)...),
		RestoreLimits:    restoreLimits,
		Entries:          entries,
		Skipped:          skipped,
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Report{}, err
	}
	if err := writeTar(tw, "manifest.json", 0o600, now, append(body, '\n')); err != nil {
		return Report{}, err
	}
	if err := tw.Close(); err != nil {
		return Report{}, err
	}
	if err := gz.Close(); err != nil {
		return Report{}, err
	}
	if err := out.Close(); err != nil {
		return Report{}, err
	}
	sum, size, err := digestFile(archive)
	if err != nil {
		return Report{}, err
	}
	return Report{
		SchemaVersion: SchemaVersion, Archive: archive, ArchiveSHA256: sum, Bytes: size,
		Files: len(entries), CreatedAt: now.Format(time.RFC3339), Sensitive: true,
	}, nil
}

func maybeGeo(include bool) []string {
	if include {
		return []string{geodataDir}
	}
	return nil
}

func writeTar(tw *tar.Writer, name string, mode uint32, now time.Time, body []byte) error {
	hdr := &tar.Header{Name: name, Mode: int64(mode), Size: int64(len(body)), ModTime: now, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Verify reads the archive without extracting it, recomputes every hash and
// rejects entries that escape the managed trees.
func Verify(archive string) (Manifest, error) {
	f, err := os.Open(archive)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return Manifest{}, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]Entry{}
	var manifest Manifest
	var haveManifest bool
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, err
		}
		if !safeEntryName(hdr.Name) {
			return Manifest{}, fmt.Errorf("archive entry escapes the managed tree: %q", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("archive entry is not a regular file: %q", hdr.Name)
		}
		total += hdr.Size
		if total > 4<<30 {
			return Manifest{}, errors.New("archive expands beyond 4 GiB")
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return Manifest{}, err
		}
		if hdr.Name == "manifest.json" {
			if haveManifest {
				return Manifest{}, errors.New("archive contains more than one manifest")
			}
			if err := json.Unmarshal(body, &manifest); err != nil {
				return Manifest{}, fmt.Errorf("manifest: %w", err)
			}
			haveManifest = true
			continue
		}
		if _, dup := seen[hdr.Name]; dup {
			return Manifest{}, fmt.Errorf("archive contains a duplicate entry: %s", hdr.Name)
		}
		sum := sha256.Sum256(body)
		seen[hdr.Name] = Entry{Path: hdr.Name, Mode: uint32(hdr.Mode), Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	}
	if !haveManifest || manifest.SchemaVersion != SchemaVersion {
		return Manifest{}, errors.New("archive has no supported manifest")
	}
	// Consume the rest of the gzip stream so the footer checksum is verified and
	// bytes appended after the member are rejected instead of ignored.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return Manifest{}, fmt.Errorf("archive has trailing or corrupt data: %w", err)
	}
	for _, want := range manifest.Entries {
		got, ok := seen[want.Path]
		if !ok {
			return Manifest{}, fmt.Errorf("archive is missing %s", want.Path)
		}
		if got.SHA256 != want.SHA256 || got.Size != want.Size {
			return Manifest{}, fmt.Errorf("archive content does not match its manifest: %s", want.Path)
		}
	}
	return manifest, nil
}

func safeEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	if strings.HasPrefix(name, "manifest.json") {
		return name == "manifest.json"
	}
	for _, rel := range managedDirs {
		if strings.HasPrefix(name, rel+"/") && !strings.Contains(name, "..") {
			return true
		}
	}
	return strings.HasPrefix(name, geodataDir+"/") && !strings.Contains(name, "..")
}

// RestoreOptions controls the safety net around an extraction.
type RestoreOptions struct {
	NoPreBackup bool
	DryRun      bool
	Validate    func(ctx context.Context, configPath string) error
	Now         time.Time
}

// Restore verifies, extraction-stages, validates and then swaps files in. On a
// swap failure every replaced file is put back from the stage.
func Restore(ctx context.Context, root, archive string, opts RestoreOptions) (Report, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	manifest, err := Verify(archive)
	if err != nil {
		return Report{}, err
	}
	rep := Report{SchemaVersion: SchemaVersion, Archive: archive, Files: len(manifest.Entries), Sensitive: true, DryRun: opts.DryRun}
	if opts.DryRun {
		for _, e := range manifest.Entries {
			dst := filepath.Join(root, filepath.FromSlash(e.Path))
			action := "add"
			body, err := os.ReadFile(dst)
			switch {
			case err == nil:
				sum := sha256.Sum256(body)
				if hex.EncodeToString(sum[:]) == e.SHA256 {
					action = "unchanged"
				} else {
					action = "replace"
				}
			case !os.IsNotExist(err):
				return rep, err
			}
			rep.Changes = append(rep.Changes, Change{Path: e.Path, Action: action})
		}
		return rep, nil
	}
	if !opts.NoPreBackup {
		dir := filepath.Join(root, "etc/idleleo/backup")
		base := filepath.Join(dir, "pre-restore-"+opts.Now.Format("20060102T150405Z"))
		var out Report
		var err error
		for i := 0; i < 100; i++ {
			name := base + ".tar.gz"
			if i > 0 {
				name = base + "-" + strconv.Itoa(i) + ".tar.gz"
			}
			out, err = Create(ctx, root, name, CreateOptions{Now: opts.Now})
			if !errors.Is(err, os.ErrExist) {
				break
			}
		}
		if err != nil {
			return rep, fmt.Errorf("pre-restore backup failed: %w", err)
		}
		rep.PreBackup = out.Archive
	}
	if err := os.MkdirAll(filepath.Join(root, "var/tmp"), 0o750); err != nil {
		return rep, err
	}
	stage, err := os.MkdirTemp(filepath.Join(root, "var/tmp"), "restore-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(stage)
	if err := extract(ctx, archive, stage); err != nil {
		return rep, err
	}
	configRel := "etc/idleleo/conf/xray/config.json"
	if opts.Validate != nil {
		if _, err := os.Stat(filepath.Join(stage, configRel)); err == nil {
			if err := opts.Validate(ctx, filepath.Join(stage, configRel)); err != nil {
				return rep, fmt.Errorf("staged config rejected: %w", err)
			}
		}
	}
	type swap struct{ dst, old string }
	var swaps []swap
	rollback := func() {
		for i := len(swaps) - 1; i >= 0; i-- {
			_ = os.Remove(swaps[i].dst)
			if swaps[i].old != "" {
				_ = os.Rename(swaps[i].old, swaps[i].dst)
			}
		}
	}
	for _, e := range manifest.Entries {
		src := filepath.Join(stage, filepath.FromSlash(e.Path))
		dst := filepath.Join(root, filepath.FromSlash(e.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			rollback()
			return rep, err
		}
		old := dst + ".restore-old"
		_ = os.Remove(old)
		if _, err := os.Stat(dst); err == nil {
			if err := os.Rename(dst, old); err != nil {
				rollback()
				return rep, err
			}
			swaps = append(swaps, swap{dst: dst, old: old})
		} else {
			swaps = append(swaps, swap{dst: dst, old: ""})
		}
		if err := os.Rename(src, dst); err != nil {
			rollback()
			return rep, err
		}
		if err := os.Chmod(dst, os.FileMode(e.Mode)); err != nil {
			rollback()
			return rep, err
		}
		rep.Restored = append(rep.Restored, e.Path)
	}
	for _, s := range swaps {
		if s.old != "" {
			_ = os.Remove(s.old)
		}
	}
	return rep, nil
}

func extract(ctx context.Context, archive, stage string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	seen := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if hdr.Name == "manifest.json" {
			continue
		}
		if !safeEntryName(hdr.Name) || hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("refusing archive entry %q", hdr.Name)
		}
		if seen[hdr.Name] {
			return fmt.Errorf("refusing duplicate archive entry %q", hdr.Name)
		}
		seen[hdr.Name] = true
		total += hdr.Size
		if total > 4<<30 {
			return errors.New("archive expands beyond 4 GiB")
		}
		dst := filepath.Join(stage, filepath.FromSlash(hdr.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
}
