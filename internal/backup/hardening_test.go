package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type rawEntry struct {
	name string
	mode int64
	body []byte
	typ  byte
}

func manifestFor(t *testing.T, entries []Entry) []byte {
	t.Helper()
	body, err := json.Marshal(Manifest{
		SchemaVersion: SchemaVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		Entries:       entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func writeRawArchive(t *testing.T, path string, entries []rawEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Typeflag: typ}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func sha(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func configEntry(body string, mode uint32) Entry {
	return Entry{Path: "etc/idleleo/conf/xray/config.json", Mode: mode, Size: int64(len(body)), SHA256: sha([]byte(body))}
}

func TestVerifyRejectsUndeclaredEntry(t *testing.T) {
	body := []byte(`{"inbounds":[]}`)
	manifest := manifestFor(t, []Entry{configEntry(string(body), 0o600)})
	archive := filepath.Join(t.TempDir(), "tampered.tar.gz")
	writeRawArchive(t, archive, []rawEntry{
		{name: "etc/idleleo/conf/xray/config.json", mode: 0o600, body: body},
		{name: "etc/idleleo/conf/xray/extra.json", mode: 0o600, body: []byte(`{}`)},
		{name: "manifest.json", mode: 0o600, body: manifest},
	})
	if _, err := Verify(archive); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected undeclared-entry rejection, got %v", err)
	}
}

func TestVerifyRejectsModeMismatch(t *testing.T) {
	body := []byte(`{"inbounds":[]}`)
	manifest := manifestFor(t, []Entry{configEntry(string(body), 0o644)})
	archive := filepath.Join(t.TempDir(), "mode.tar.gz")
	writeRawArchive(t, archive, []rawEntry{
		{name: "etc/idleleo/conf/xray/config.json", mode: 0o600, body: body},
		{name: "manifest.json", mode: 0o600, body: manifest},
	})
	if _, err := Verify(archive); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("expected mode rejection, got %v", err)
	}
}

func TestVerifyRejectsDuplicateManifest(t *testing.T) {
	body := []byte(`{}`)
	manifest := manifestFor(t, []Entry{configEntry(string(body), 0o600)})
	archive := filepath.Join(t.TempDir(), "dual-manifest.tar.gz")
	writeRawArchive(t, archive, []rawEntry{
		{name: "etc/idleleo/conf/xray/config.json", mode: 0o600, body: body},
		{name: "manifest.json", mode: 0o600, body: manifest},
		{name: "manifest.json", mode: 0o600, body: manifest},
	})
	if _, err := Verify(archive); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected duplicate-manifest rejection, got %v", err)
	}
}

func TestVerifyRejectsConcatenatedGzipMember(t *testing.T) {
	src := seedRoot(t)
	first := filepath.Join(t.TempDir(), "first.tar.gz")
	if _, err := Create(context.Background(), src, first, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(t.TempDir(), "second.tar.gz")
	if _, err := Create(context.Background(), src, second, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	combined := filepath.Join(t.TempDir(), "combined.tar.gz")
	if err := os.WriteFile(combined, append(a, b...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(combined); err == nil {
		t.Fatal("concatenated gzip members must be rejected")
	}
}

func TestVerifyRejectsOversizedManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge-manifest.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	// Only the header is needed: Verify must reject on the declared size before
	// allocating or reading the body.
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: maxManifestBytes + 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("expected oversized-manifest rejection, got %v", err)
	}
}

func TestVerifyRejectsNonCanonicalPath(t *testing.T) {
	body := []byte(`{}`)
	manifest := manifestFor(t, []Entry{configEntry(string(body), 0o600)})
	archive := filepath.Join(t.TempDir(), "noncanonical.tar.gz")
	writeRawArchive(t, archive, []rawEntry{
		{name: "etc/idleleo/conf//xray/config.json", mode: 0o600, body: body},
		{name: "manifest.json", mode: 0o600, body: manifest},
	})
	if _, err := Verify(archive); err == nil {
		t.Fatal("non-canonical archive path must be rejected")
	}
}

func TestCreateRefusesArchiveInsideManagedTree(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(root, "etc/idleleo/conf/xray", "self.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err == nil {
		t.Fatal("archive inside the managed tree must be refused")
	}
	if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused archive must not be created")
	}
}

func TestCreateLeavesNoPartialArchiveWhenCancelled(t *testing.T) {
	root := seedRoot(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "state.tar.gz")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Create(ctx, root, archive, CreateOptions{}); err == nil {
		t.Fatal("cancelled create must fail")
	}
	if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled create must not leave the final archive")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".idleleo-backup-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temp archive must be cleaned up, found %v", matches)
	}
}

func TestCreateRefusesSymlinkedManagedDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/idleleo"), 0o750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc/idleleo/conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), root, filepath.Join(t.TempDir(), "a.tar.gz"), CreateOptions{}); err == nil {
		t.Fatal("symlinked managed directory must be refused")
	}
}

func TestRestoreRefusesSymlinkComponent(t *testing.T) {
	src := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), src, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/idleleo"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(outside, "xray"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "xray/config.json"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc/idleleo/conf")); err != nil {
		t.Fatal(err)
	}
	_, err := Restore(context.Background(), root, archive, RestoreOptions{NoPreBackup: true})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink refusal, got %v", err)
	}
	body, err := os.ReadFile(filepath.Join(outside, "xray/config.json"))
	if err != nil || string(body) != "outside" {
		t.Fatalf("restore must not write through a symlink: %q %v", body, err)
	}
}

func TestRestoreRollsBackWhenServiceApplyFails(t *testing.T) {
	root, archive, want := versionedRoots(t, "old", "new")
	_, err := Restore(context.Background(), root, archive, RestoreOptions{
		NoPreBackup: true,
		Apply: func(context.Context) error {
			return errors.New("service refused to start")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("expected apply failure, got %v", err)
	}
	assertContent(t, root, want)
	rec, err := loadRestoreRecord(root)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != RestoreStateRolledBack {
		t.Fatalf("journal state = %s, want %s", rec.State, RestoreStateRolledBack)
	}
	if _, err := os.Stat(restoreSnapshotDir(root, rec.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("snapshot directory must be removed after a successful rollback")
	}
}

func TestRestoreRefusesWhileJournalIsInterrupted(t *testing.T) {
	root := seedRoot(t)
	if err := saveRestoreRecord(root, &restoreRecord{
		SchemaVersion: SchemaVersion, ID: "stuck", State: RestoreStateApplying,
		Root: root, Files: []restoreFile{{Path: "etc/idleleo/conf/xray/config.json"}},
	}); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := Restore(context.Background(), root, archive, RestoreOptions{NoPreBackup: true})
	if err == nil || !strings.Contains(err.Error(), "backup recover") {
		t.Fatalf("expected explicit recover instruction, got %v", err)
	}
}

func TestRecoverPreparedDoesNotTouchFiles(t *testing.T) {
	root, _, _ := versionedRoots(t, "old", "new")
	if err := saveRestoreRecord(root, &restoreRecord{
		SchemaVersion: SchemaVersion, ID: "prepared", State: RestoreStatePrepared,
		Root: root,
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := Recover(context.Background(), root, RecoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Action != "rolled-back" || !rep.Converged {
		t.Fatalf("unexpected recover report: %+v", rep)
	}
	assertContent(t, root, "old")
}

func TestRestoreHardKillConvergesWithExplicitRecover(t *testing.T) {
	if os.Getenv("IDLELEO_KILL_HELPER") == "1" {
		return // the helper is executed as a subprocess, not inline
	}
	root, archive, _ := versionedRoots(t, "old", "new")
	cmd := exec.Command(os.Args[0], "-test.run=TestRestoreKillHelper", "-test.v")
	cmd.Env = append(os.Environ(),
		"IDLELEO_KILL_HELPER=1",
		"IDLELEO_KILL_ROOT="+root,
		"IDLELEO_KILL_ARCHIVE="+archive,
		"IDLELEO_RESTORE_FAULT=after-half",
	)
	_, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("helper must be killed, got %v", err)
	}
	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("helper must die from SIGKILL, got %v", ws)
	}

	rec, err := loadRestoreRecord(root)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != RestoreStateApplying {
		t.Fatalf("journal state = %s, want %s", rec.State, RestoreStateApplying)
	}
	if string(readFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"))) != `{"v":"new"}` {
		t.Fatal("the kill point must leave at least one replaced file")
	}

	rep, err := Recover(context.Background(), root, RecoverOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Action != "rolled-back" || !rep.Converged {
		t.Fatalf("unexpected recover report: %+v", rep)
	}
	assertContent(t, root, "old")

	if _, err := Restore(context.Background(), root, archive, RestoreOptions{NoPreBackup: true}); err != nil {
		t.Fatalf("restore after recover must succeed: %v", err)
	}
	assertContent(t, root, "new")
}

func TestRestoreKillHelper(t *testing.T) {
	if os.Getenv("IDLELEO_KILL_HELPER") != "1" {
		return
	}
	root := os.Getenv("IDLELEO_KILL_ROOT")
	archive := os.Getenv("IDLELEO_KILL_ARCHIVE")
	_, err := Restore(context.Background(), root, archive, RestoreOptions{NoPreBackup: true})
	t.Logf("restore returned before fault: %v", err)
	os.Exit(9)
}

// versionedRoots builds a target root containing "old" content and an archive
// whose payload is "new" content.
func versionedRoots(t *testing.T, old, new string) (root, archive, want string) {
	t.Helper()
	root = t.TempDir()
	src := t.TempDir()
	files := map[string]string{
		"etc/idleleo/conf/xray/config.json": `{"v":"` + old + `"}`,
		"etc/idleleo/cert/xray.key":         "key-" + old,
		"etc/idleleo/cert/xray.crt":         "crt-" + old,
		"etc/idleleo/v1/metadata.json":      `{"v":"` + old + `"}`,
	}
	for rel, body := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(src, rel)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, rel), []byte(strings.ReplaceAll(body, old, new)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive = filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), src, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return root, archive, old
}

func assertContent(t *testing.T, root, version string) {
	t.Helper()
	if body := readFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json")); string(body) != `{"v":"`+version+`"}` {
		t.Fatalf("config content = %s, want version %s", body, version)
	}
	if body := readFile(t, filepath.Join(root, "etc/idleleo/cert/xray.key")); string(body) != "key-"+version {
		t.Fatalf("key content = %s, want version %s", body, version)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
