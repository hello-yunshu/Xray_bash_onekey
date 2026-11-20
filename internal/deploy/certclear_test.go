package deploy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// TestClearCertificatesKeepsInUseCertificate is the regression that reproduces
// the audit defect: a live Nginx HTTPS site references a certificate and the
// old clearer deleted it anyway, leaving `nginx -t` failing. The test uses only
// the original ClearCertsSpec fields so it also compiles against the baseline
// implementation, where it fails.
func TestClearCertificatesKeepsInUseCertificate(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), []byte("cert"))
	writeGuardTestFile(t, filepath.Join(certDir, "xray.key"), []byte("key"))
	confDir := filepath.Join(root, "etc/idleleo/conf/nginx")
	writeGuardTestFile(t, filepath.Join(confDir, "00-xray.conf"),
		[]byte("server {\n    ssl_certificate     /etc/idleleo/cert/xray.crt;\n    ssl_certificate_key /etc/idleleo/cert/xray.key;\n}\n"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"xray.crt", "xray.key"} {
		if _, statErr := os.Stat(filepath.Join(certDir, name)); statErr != nil {
			t.Fatalf("in-use certificate %s was deleted: %v", name, statErr)
		}
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("nothing referenced may be removed, got %v", rep.Removed)
	}
	assertPlanned(t, rep, filepath.Join(certDir, "xray.crt"), certActionKeep, true)
}

func TestClearCertificatesRemovesOnlyUnusedProjectMaterial(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), []byte("project cert"))
	writeGuardTestFile(t, filepath.Join(certDir, "xray.key"), []byte("project key"))
	// A third-party file dropped into the managed directory has no ownership
	// proof and must survive.
	writeGuardTestFile(t, filepath.Join(certDir, "third-party.pem"), []byte("third party"))
	outside := filepath.Join(t.TempDir(), "outside.pem")
	writeGuardTestFile(t, outside, []byte("keep"))
	if err := os.Symlink(outside, filepath.Join(certDir, "link.pem")); err != nil {
		t.Fatal(err)
	}

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 2 {
		t.Fatalf("expected the unused project pair to be removed, got %v", rep.Removed)
	}
	for _, name := range []string{"third-party.pem", "link.pem"} {
		if _, statErr := os.Lstat(filepath.Join(certDir, name)); statErr != nil {
			t.Fatalf("%s must be preserved: %v", name, statErr)
		}
	}
	if _, statErr := os.Stat(outside); statErr != nil {
		t.Fatalf("symlink target must be untouched: %v", statErr)
	}
	assertPlanned(t, rep, filepath.Join(certDir, "third-party.pem"), certActionKeep, false)
	assertPlanned(t, rep, filepath.Join(certDir, "xray.crt"), certActionDelete, false)
}

func TestClearCertificatesKeepsDirectoryWithUnknownOwnership(t *testing.T) {
	root := sandbox(t)
	archive := filepath.Join(root, "etc/idleleo/cert/archive")
	writeGuardTestFile(t, filepath.Join(archive, "xray.crt"), []byte("project"))
	writeGuardTestFile(t, filepath.Join(archive, "third-party.pem"), []byte("third party"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("a directory with an unproven file must be kept as a whole: %v", rep.Removed)
	}
	if _, err := os.Stat(filepath.Join(archive, "third-party.pem")); err != nil {
		t.Fatalf("the unknown file must survive: %v", err)
	}
}

func TestClearCertificatesRemovesProjectArchiveDirectory(t *testing.T) {
	root := sandbox(t)
	archive := filepath.Join(root, "etc/idleleo/cert/archive")
	writeGuardTestFile(t, filepath.Join(archive, "xray.crt"), []byte("project"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 {
		t.Fatalf("a fully project-owned archive must be removed: %v", rep.Removed)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("archive directory must be gone: %v", err)
	}
}

func TestClearCertificatesRespectsUserManagedMarker(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), []byte("user cert"))
	writeGuardTestFile(t, filepath.Join(certDir, ".user-managed"), []byte("managed-by=user\n"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("user-managed material must never be removed: %v", rep.Removed)
	}
}

func TestClearCertificatesDryRunChangesNothing(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), []byte("cert"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(certDir, "xray.crt")); err != nil {
		t.Fatalf("dry-run must not delete: %v", err)
	}
	if len(rep.Planned) != 1 || rep.Planned[0].Action != certActionDelete {
		t.Fatalf("dry-run must list the plan: %+v", rep.Planned)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/idleleo/certclear")); !os.IsNotExist(err) {
		t.Fatalf("dry-run must not create state: %v", err)
	}
}

func TestClearCertificatesMissingDirectoryIsIdempotent(t *testing.T) {
	root := sandbox(t)
	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Missing || len(rep.Removed) != 0 {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

// TestClearCertificatesRollsBackPartialFailure proves a mid-transaction rename
// failure restores every already-staged file instead of reporting success.
func TestClearCertificatesRollsBackPartialFailure(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), []byte("cert"))
	writeGuardTestFile(t, filepath.Join(certDir, "xray.key"), []byte("key"))

	calls := 0
	old := renameCertFile
	renameCertFile = func(from, to string) error {
		calls++
		if calls == 2 {
			return os.ErrPermission
		}
		return os.Rename(from, to)
	}
	t.Cleanup(func() { renameCertFile = old })

	if _, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root}); err == nil {
		t.Fatal("a failed removal must be reported, not claimed as success")
	}
	for _, name := range []string{"xray.crt", "xray.key"} {
		if _, statErr := os.Stat(filepath.Join(certDir, name)); statErr != nil {
			t.Fatalf("%s must be restored after a rollback: %v", name, statErr)
		}
	}
	if _, statErr := os.Stat(filepath.Join(root, "var/lib/idleleo/certclear/journal.json")); !os.IsNotExist(statErr) {
		t.Fatalf("a completed rollback must clear the journal: %v", statErr)
	}
}

// TestRecoverCertClearRestoresInterruptedRun simulates a SIGKILL after some
// renames: the persisted PREPARED journal must put every file back.
func TestRecoverCertClearRestoresInterruptedRun(t *testing.T) {
	root := sandbox(t)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(root, "etc/idleleo/cert")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "var/lib/idleleo/certclear/staging/crash")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	writeGuardTestFile(t, filepath.Join(stage, "000-xray.crt"), []byte("cert"))
	j := certClearJournal{
		SchemaVersion: certJournalSchema, State: certJournalPrepared, ID: "crash", Root: root,
		Moves: []certMove{{From: filepath.Join(certDir, "xray.crt"), To: filepath.Join(stage, "000-xray.crt"), Kind: "file"}},
	}
	if err := writeCertJournal(paths, &j); err != nil {
		t.Fatal(err)
	}

	recovered, err := recoverCertClearLocked(paths)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered {
		t.Fatal("an interrupted deletion must be reported as recovered")
	}
	if _, statErr := os.Stat(filepath.Join(certDir, "xray.crt")); statErr != nil {
		t.Fatalf("the interrupted run must restore the certificate: %v", statErr)
	}
}

func assertPlanned(t *testing.T, rep ClearCertsReport, path, action string, inUse bool) {
	t.Helper()
	for _, entry := range rep.Planned {
		if entry.Path == path {
			if entry.Action != action || entry.InUse != inUse {
				t.Fatalf("plan entry %s = action %s inUse %t, want %s/%t", path, entry.Action, entry.InUse, action, inUse)
			}
			return
		}
	}
	t.Fatalf("path %s missing from plan: %+v", path, rep.Planned)
}
