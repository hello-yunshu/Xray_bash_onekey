package repair

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRepairCreatesDirsAndRestrictsModes(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{"inbounds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	// 0640 root:xray, not 0600: the service user has to be able to read the
	// config after repair or the next restart dies with permission denied.
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("config mode = %04o", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(root, "etc/idleleo/backup")); err != nil {
		t.Fatalf("backup dir not created: %v", err)
	}
	if !rep.Healthy || len(rep.Actions) == 0 {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

func TestRepairDryRunChangesNothing(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), root, Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(config)
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("dry run changed the mode: %04o", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(root, "etc/idleleo/backup")); err == nil {
		t.Fatal("dry run created a directory")
	}
	if len(rep.Actions) == 0 {
		t.Fatalf("dry run reported no intended action: %+v", rep)
	}
}

func TestRepairStaleLockNeedsExplicitFlag(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, "run/lock/idleleo-update.lock")
	if err := os.MkdirAll(filepath.Dir(lock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if rep, err := Run(context.Background(), root, Options{}); err != nil || rep.Healthy {
		t.Fatalf("stale lock should remain a finding: %+v %v", rep, err)
	}
	rep, err := Run(context.Background(), root, Options{FixLock: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); err == nil {
		t.Fatal("stale lock was not removed")
	}
	if !rep.Healthy {
		t.Fatalf("unexpected remaining findings: %+v", rep)
	}
}

func TestRepairRemovesOldStagingDir(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "var/tmp/restore-123456")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stage, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), root, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stage); err == nil {
		t.Fatal("abandoned staging directory was not removed")
	}
}
