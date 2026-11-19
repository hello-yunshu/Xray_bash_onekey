// Package backup creates, verifies and restores archives of the manager-owned
// state. Archives carry private keys, so creation refuses to overwrite and
// uses 0600; verification never extracts and restore refuses path escapes,
// links and device nodes.
package backup

import (
	"archive/tar"
	"bufio"
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

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const (
	// maxArchiveBytes bounds the decompressed tar stream so a crafted archive
	// cannot exhaust memory or disk during verify.
	maxArchiveBytes int64 = 4 << 30
	// maxManifestBytes keeps a hostile manifest from being read into memory.
	maxManifestBytes int64 = 16 << 20
	// maxManagedFileBytes bounds one managed file (geodata is the largest).
	maxManagedFileBytes int64 = 1 << 30
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
	Warnings      []string `json:"warnings,omitempty"`
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
//
// The archive is written to a sibling temp file, fsynced and only then linked
// into place, so a crash leaves no half-valid archive at the requested name.
func Create(ctx context.Context, root, archive string, opts CreateOptions) (Report, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	absRoot, err := ensureRoot(root)
	if err != nil {
		return Report{}, err
	}
	if archiveInsideManaged(absRoot, archive) {
		return Report{}, errors.New("backup archive must not live inside the managed trees it archives")
	}
	outDir := filepath.Dir(archive)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return Report{}, err
	}
	if _, err := os.Lstat(archive); err == nil {
		return Report{}, fmt.Errorf("backup archive: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Report{}, fmt.Errorf("backup archive: %w", err)
	}
	tmp, err := os.CreateTemp(outDir, ".idleleo-backup-*.tar.gz")
	if err != nil {
		return Report{}, fmt.Errorf("backup archive: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	var entries []Entry
	var skipped []string
	for _, rel := range append(append([]string{}, managedDirs...), maybeGeo(opts.IncludeGeodata)...) {
		dir, err := securePath(absRoot, rel, false)
		if err != nil {
			// An optional tree (notably the opt-in GeoData directory) may be
			// absent while one of its parents exists. That is not a failure:
			// there is simply nothing to archive. Symlinks and unsafe parents
			// still return a non-ENOENT error and abort the backup.
			if errors.Is(err, os.ErrNotExist) {
				skipped = append(skipped, rel+" (absent)")
				continue
			}
			return Report{}, err
		}
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			skipped = append(skipped, rel+" (absent)")
			continue
		}
		err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
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
			relPath, err := filepath.Rel(absRoot, path)
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

	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	now := opts.Now
	for i := range entries {
		body, mode, err := readNoFollow(filepath.Join(absRoot, filepath.FromSlash(entries[i].Path)))
		if err != nil {
			return Report{}, err
		}
		entries[i].Mode = uint32(mode)
		entries[i].Size = int64(len(body))
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
	if err := tmp.Chmod(0o600); err != nil {
		return Report{}, err
	}
	if err := tmp.Sync(); err != nil {
		return Report{}, err
	}
	if err := tmp.Close(); err != nil {
		return Report{}, err
	}
	// Link is atomic and fails with EEXIST, so a concurrent create cannot both
	// believe they reserved the name.
	if err := os.Link(tmpName, archive); err != nil {
		return Report{}, fmt.Errorf("backup archive: %w", err)
	}
	if err := os.Remove(tmpName); err != nil {
		return Report{}, err
	}
	committed = true
	syncDir(outDir)
	if _, err := Verify(archive); err != nil {
		_ = os.Remove(archive)
		return Report{}, fmt.Errorf("backup verification failed: %w", err)
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
// rejects entries that escape the managed trees. It is deliberately strict:
// the tar contents must match the manifest exactly (no extra or missing
// files), modes and sizes must agree, and trailing or multi-member gzip
// streams are refused.
func Verify(archive string) (Manifest, error) {
	f, err := os.Open(archive)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return Manifest{}, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	// One member only. A concatenated gzip stream would let a second archive be
	// smuggled past a reader that trusts the first member.
	gz.Multistream(false)
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
		if hdr.Size < 0 || hdr.Size > maxManagedFileBytes {
			return Manifest{}, fmt.Errorf("archive entry has an invalid size: %q", hdr.Name)
		}
		total += hdr.Size
		if total > maxArchiveBytes {
			return Manifest{}, errors.New("archive expands beyond 4 GiB")
		}
		if hdr.Name == "manifest.json" {
			if haveManifest {
				return Manifest{}, errors.New("archive contains more than one manifest")
			}
			if hdr.Size > maxManifestBytes {
				return Manifest{}, errors.New("manifest is larger than the supported limit")
			}
			body := make([]byte, hdr.Size)
			if _, err := io.ReadFull(tr, body); err != nil {
				return Manifest{}, err
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
		h := sha256.New()
		n, err := io.Copy(h, tr)
		if err != nil {
			return Manifest{}, err
		}
		if n != hdr.Size {
			return Manifest{}, fmt.Errorf("archive entry is truncated: %s", hdr.Name)
		}
		seen[hdr.Name] = Entry{
			Path: hdr.Name, Mode: uint32(hdr.Mode) & 0o777, Size: n,
			SHA256: hex.EncodeToString(h.Sum(nil)),
		}
	}
	if !haveManifest || manifest.SchemaVersion != SchemaVersion {
		return Manifest{}, errors.New("archive has no supported manifest")
	}
	// Drain the member so the gzip footer/CRC is verified, then prove that no
	// bytes follow it.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return Manifest{}, fmt.Errorf("archive has trailing or corrupt data: %w", err)
	}
	if br.Buffered() > 0 {
		return Manifest{}, errors.New("archive has trailing data after the gzip member")
	}
	if n, _ := f.Read(make([]byte, 1)); n != 0 {
		return Manifest{}, errors.New("archive has trailing data after the gzip member")
	}
	if len(manifest.Entries) != len(seen) {
		return Manifest{}, fmt.Errorf("archive entries (%d) do not match the manifest (%d)",
			len(seen), len(manifest.Entries))
	}
	declared := make(map[string]bool, len(manifest.Entries))
	for _, want := range manifest.Entries {
		if !safeEntryName(want.Path) || want.Path == "manifest.json" {
			return Manifest{}, fmt.Errorf("manifest declares an unsafe path: %q", want.Path)
		}
		if declared[want.Path] {
			return Manifest{}, fmt.Errorf("manifest declares a duplicate entry: %s", want.Path)
		}
		declared[want.Path] = true
		got, ok := seen[want.Path]
		if !ok {
			return Manifest{}, fmt.Errorf("archive is missing %s", want.Path)
		}
		if got.SHA256 != want.SHA256 || got.Size != want.Size {
			return Manifest{}, fmt.Errorf("archive content does not match its manifest: %s", want.Path)
		}
		if got.Mode != want.Mode&0o777 {
			return Manifest{}, fmt.Errorf("archive mode does not match its manifest: %s", want.Path)
		}
	}
	for name := range seen {
		if !declared[name] {
			return Manifest{}, fmt.Errorf("archive contains an undeclared entry: %s", name)
		}
	}
	return manifest, nil
}

func safeEntryName(name string) bool {
	if name == "manifest.json" {
		return true
	}
	clean, err := cleanRel(name)
	if err != nil {
		return false
	}
	for _, rel := range managedDirs {
		if strings.HasPrefix(clean, rel+"/") {
			return true
		}
	}
	return strings.HasPrefix(clean, geodataDir+"/")
}

// RestoreOptions controls the safety net around an extraction.
type RestoreOptions struct {
	NoPreBackup bool
	DryRun      bool
	Validate    func(ctx context.Context, configPath string) error
	// Apply runs after the files are committed but before the transaction is
	// recorded COMMITTED, so a failed service restart rolls the tree back.
	Apply func(ctx context.Context) error
	Now   time.Time
}

// Restore verifies, stages, validates and then applies files inside a durable
// transaction. A SIGKILL leaves a PREPARED/APPLYING journal that `Recover`
// converges; it never deletes a snapshot it cannot verify.
func Restore(ctx context.Context, root, archive string, opts RestoreOptions) (Report, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	manifest, err := Verify(archive)
	if err != nil {
		return Report{}, err
	}
	rep := Report{SchemaVersion: SchemaVersion, Archive: archive, Files: len(manifest.Entries), Sensitive: true, DryRun: opts.DryRun}
	if sum, _, err := digestFile(archive); err == nil {
		rep.ArchiveSHA256 = sum
	}
	if opts.DryRun {
		for _, e := range manifest.Entries {
			dst := filepath.Join(root, filepath.FromSlash(e.Path))
			action := "add"
			fi, statErr := os.Lstat(dst)
			switch {
			case statErr == nil:
				if !fi.Mode().IsRegular() {
					return rep, fmt.Errorf("refusing to inspect a non-regular file: %s", dst)
				}
				body, _, err := readNoFollow(dst)
				if err != nil {
					return rep, err
				}
				sum := sha256.Sum256(body)
				if hex.EncodeToString(sum[:]) == e.SHA256 {
					action = "unchanged"
				} else {
					action = "replace"
				}
			case !errors.Is(statErr, os.ErrNotExist):
				return rep, statErr
			}
			rep.Changes = append(rep.Changes, Change{Path: e.Path, Action: action})
		}
		return rep, nil
	}

	absRoot, err := ensureRoot(root)
	if err != nil {
		return rep, err
	}
	lock, err := host.AcquireUpdate(lockFileFor(absRoot))
	if err != nil {
		if errors.Is(err, host.ErrLocked) {
			return rep, errors.New("another update holds the lock; retry after it finishes")
		}
		return rep, err
	}
	defer lock.Release()

	if prev, err := loadRestoreRecord(absRoot); err == nil {
		switch prev.State {
		case RestoreStatePrepared, RestoreStateApplying, RestoreStateRecoveryNeeded:
			return rep, fmt.Errorf("an interrupted restore is %s; run `idleleo backup recover` before restoring again", prev.State)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return rep, err
	}

	if !opts.NoPreBackup {
		dir := filepath.Join(absRoot, "etc/idleleo/backup")
		base := filepath.Join(dir, "pre-restore-"+opts.Now.Format("20060102T150405Z"))
		var out Report
		var err error
		for i := 0; i < 100; i++ {
			name := base + ".tar.gz"
			if i > 0 {
				name = base + "-" + strconv.Itoa(i) + ".tar.gz"
			}
			out, err = Create(ctx, absRoot, name, CreateOptions{Now: opts.Now})
			if !errors.Is(err, os.ErrExist) {
				break
			}
		}
		if err != nil {
			return rep, fmt.Errorf("pre-restore backup failed: %w", err)
		}
		rep.PreBackup = out.Archive
	}
	if _, err := secureMkdirAll(absRoot, "var/tmp", 0o750); err != nil {
		return rep, err
	}
	stage, err := os.MkdirTemp(filepath.Join(absRoot, "var/tmp"), "restore-")
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
	return restoreApply(ctx, absRoot, stage, manifest, rep, opts)
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
