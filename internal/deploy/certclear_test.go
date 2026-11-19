package deploy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestClearCertificatesRemovesFilesAndKeepsSymlinks(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	if err := os.MkdirAll(filepath.Join(certDir, "archive"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeGuardTestFile(t, filepath.Join(certDir, "example.com.crt"), []byte("cert"))
	writeGuardTestFile(t, filepath.Join(certDir, "example.com.key"), []byte("key"))
	writeGuardTestFile(t, filepath.Join(certDir, "archive", "old.pem"), []byte("old"))

	outside := filepath.Join(t.TempDir(), "outside.pem")
	writeGuardTestFile(t, outside, []byte("keep"))
	if err := os.Symlink(outside, filepath.Join(certDir, "link.pem")); err != nil {
		t.Fatal(err)
	}

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 3 {
		t.Fatalf("expected 3 removals, got %v", rep.Removed)
	}
	if len(rep.Skipped) != 1 || len(rep.Warnings) != 1 {
		t.Fatalf("symlink must be skipped with a warning: %+v", rep)
	}
	entries, err := os.ReadDir(certDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "link.pem" {
		t.Fatalf("only the symlink may remain: %v", entries)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("symlink target must be untouched: %v", err)
	}
}

func TestClearCertificatesDryRunChangesNothing(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "example.com.crt"), []byte("cert"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 {
		t.Fatalf("dry-run must list the removal: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(certDir, "example.com.crt")); err != nil {
		t.Fatalf("dry-run must not delete: %v", err)
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
