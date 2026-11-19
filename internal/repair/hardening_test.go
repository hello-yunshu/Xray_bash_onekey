package repair

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

func TestRepairRefusesSymlinkedPaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/idleleo"), 0o750); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(outside, "xray.key")
	if err := os.WriteFile(key, []byte("outside-key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc/idleleo/cert")); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Remaining, "\n"), "symlink") {
		t.Fatalf("symlink must be reported, got %+v", rep.Remaining)
	}
	fi, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("repair must not chmod through a symlink: mode=%04o", fi.Mode().Perm())
	}
	if body, _ := os.ReadFile(key); string(body) != "outside-key" {
		t.Fatal("repair must not rewrite the symlink target")
	}
}

func TestRepairRefusesSymlinkedStagingEntry(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/tmp"), 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "var/tmp/restore-hijack")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(link, old, old); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), root, Options{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Remaining, "\n"), "symlink") {
		t.Fatalf("staging symlink must be reported, got %+v", rep.Remaining)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("staging symlink must be left alone: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("symlink target must survive: %v", err)
	}
}

func TestRepairDryRunTakesNoLockAndWritesNothing(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), root, Options{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "run/lock/idleleo-update.lock")); !os.IsNotExist(err) {
		t.Fatalf("dry run must not create a lock file: %v", err)
	}
	fi, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("dry run must not chmod: %04o", fi.Mode().Perm())
	}
}

func TestRepairRefusesWhileAnotherUpdateHoldsTheLock(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, "run/lock/idleleo-update.lock")
	lock, err := host.AcquireUpdate(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	_, err = Run(context.Background(), root, Options{})
	if err == nil || !strings.Contains(err.Error(), "another update") {
		t.Fatalf("expected lock refusal, got %v", err)
	}
}
