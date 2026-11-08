package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

func journalFixture(t *testing.T) (host.Paths, []string, deployJournal) {
	t.Helper()
	root := sandbox(t)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	configPath, _ := paths.Join(configRel, true)
	binPath, _ := paths.Join(binaryRel, true)
	unitPath, _ := paths.Join(unitRel, true)
	metaPath, _ := paths.Join(paths.ManagerMetadata(), true)
	for p, content := range map[string]string{
		configPath: "old-config",
		binPath:    "old-binary",
		unitPath:   "old-unit",
		metaPath:   "old-meta",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backups, err := captureFiles([]string{configPath, binPath, unitPath, metaPath})
	if err != nil {
		t.Fatal(err)
	}
	j, err := newJournal(paths, backups, serviceState{}, nil, "none", "ws")
	if err != nil {
		t.Fatal(err)
	}
	return paths, []string{configPath, binPath, unitPath, metaPath}, j
}

func TestRecoverRollsBackDeadInstall(t *testing.T) {
	paths, files, _ := journalFixture(t)
	for i, p := range files {
		if err := os.WriteFile(p, []byte("half-written-"+string(rune('0'+i))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := recoverPendingLocked(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Converged || report.Action != "rolled_back" || report.Restored != len(files) {
		t.Fatalf("unexpected report: %+v", report)
	}
	want := []string{"old-config", "old-binary", "old-unit", "old-meta"}
	for i, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != want[i] {
			t.Fatalf("%s restored to %q want %q", p, raw, want[i])
		}
	}
	if _, err := os.Stat(journalPath(paths)); !os.IsNotExist(err) {
		t.Fatalf("journal must be removed after convergence: %v", err)
	}
}

func TestRecoverKeepsJournalWhenSnapshotIsBad(t *testing.T) {
	paths, _, j := journalFixture(t)
	// Corrupt the snapshot the journal points at, then make the live file
	// differ so recovery really tries to restore it.
	if err := os.Remove(filepath.Join(snapshotDir(paths), filepath.Base(j.Entries[0].Snapshot))); err != nil {
		t.Fatal(err)
	}
	live, _ := applyRoot(paths, j.Entries[0].Rel)
	if err := os.WriteFile(live, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverPendingLocked(context.Background(), paths); err == nil {
		t.Fatal("recovery must fail when the snapshot is missing")
	}
	loaded, err := loadJournal(paths)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.State != JournalRecoveryRequired {
		t.Fatalf("journal must stay as %s, got %+v", JournalRecoveryRequired, loaded)
	}
}

func TestRecoverRefusesCorruptJournal(t *testing.T) {
	root := sandbox(t)
	paths, _ := host.NewPaths(root)
	if err := os.MkdirAll(deployDir(paths), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath(paths), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverPendingLocked(context.Background(), paths); err == nil ||
		!strings.Contains(err.Error(), "corrupt deploy journal") {
		t.Fatalf("corrupt journal must be refused, got %v", err)
	}
	if _, err := os.Stat(journalPath(paths)); err != nil {
		t.Fatal("corrupt journal must not be deleted")
	}
}

func TestRecoverCleansCommittedJournal(t *testing.T) {
	paths, _, j := journalFixture(t)
	j.State = JournalCommitted
	if err := writeJournal(paths, j); err != nil {
		t.Fatal(err)
	}
	report, err := recoverPendingLocked(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	if report.Action != "cleaned" {
		t.Fatalf("committed journal must only be cleaned: %+v", report)
	}
	if _, err := os.Stat(journalPath(paths)); !os.IsNotExist(err) {
		t.Fatal("journal must be cleaned")
	}
}

func TestRecoverRefusesPathOutsideRoot(t *testing.T) {
	paths, _, j := journalFixture(t)
	j.Entries[0].Rel = "../outside"
	j.State = JournalPrepared
	if err := writeJournal(paths, j); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverPendingLocked(context.Background(), paths); err == nil {
		t.Fatal("journal pointing outside root must be refused")
	}
}

// TestInstallConvergesPendingJournal proves the normal install path, not just
// the explicit recover command, converges a transaction left by a dead process.
func TestInstallConvergesPendingJournal(t *testing.T) {
	paths, files, _ := journalFixture(t)
	for i, p := range files {
		if err := os.WriteFile(p, []byte("half-written-"+string(rune('0'+i))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Install(context.Background(), InstallSpec{
		Root:         paths.Root,
		SourceBinary: stubXray(t),
		Mode:         "none",
		Transport:    "ws",
		Port:         10081,
		NoService:    true,
	})
	if err != nil {
		t.Fatalf("install must converge the pending journal, got %v", err)
	}
	cleared := false
	for _, w := range rep.Warnings {
		if w == "recovered unfinished deploy transaction" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("install must report the recovered transaction: %v", rep.Warnings)
	}
	if _, err := os.Stat(journalPath(paths)); !os.IsNotExist(err) {
		t.Fatalf("journal must be cleared after a successful install: %v", err)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "half-written") {
		t.Fatalf("install wrote over a half-applied config: %s", raw)
	}
	if _, err := os.Stat(files[0] + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("leftover atomic temp file survived: %v", err)
	}
}

func TestRecoverRequiresDeployLock(t *testing.T) {
	root := sandbox(t)
	paths, _ := host.NewPaths(root)
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(context.Background(), RecoverSpec{Root: root}); err == nil {
		t.Fatal("recovery must not run without the deploy lock")
	}
	lock.Release()
	if _, err := Recover(context.Background(), RecoverSpec{Root: root}); err != nil {
		t.Fatal(err)
	}
}
