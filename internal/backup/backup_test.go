package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func seedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/idleleo/conf/xray/config.json", `{"inbounds":[]}`, 0o600)
	write("etc/idleleo/cert/xray.key", "key-material", 0o600)
	write("etc/idleleo/cert/xray.crt", "cert-material", 0o644)
	write("etc/idleleo/v1/metadata.json", `{"schemaVersion":1}`, 0o600)
	if err := os.MkdirAll(filepath.Join(root, "var/tmp"), 0o750); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCreateRecordsSourceAndRestoreLimits(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{SourceVersion: "test-1", SourceArch: "arm64"}); err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(archive)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SourceArch != "arm64" || manifest.SourceVersion != "test-1" {
		t.Fatalf("source fields missing: %+v", manifest)
	}
	if len(manifest.ManagedResources) == 0 || len(manifest.RestoreLimits) == 0 {
		t.Fatalf("managed resources/limits must be explicit: %+v", manifest)
	}
}

func TestRestoreDryRunReportsChangesWithoutWriting(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.WriteFile(config, []byte(`{"inbounds":[{"port":1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root, "etc/idleleo/cert/xray.key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	rep, err := Restore(context.Background(), root, archive, RestoreOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DryRun {
		t.Fatalf("report must be marked dry-run")
	}
	actions := map[string]string{}
	for _, c := range rep.Changes {
		actions[c.Path] = c.Action
	}
	if actions["etc/idleleo/conf/xray/config.json"] != "replace" {
		t.Fatalf("modified config action = %q", actions["etc/idleleo/conf/xray/config.json"])
	}
	if actions["etc/idleleo/cert/xray.key"] != "add" {
		t.Fatalf("deleted key action = %q", actions["etc/idleleo/cert/xray.key"])
	}
	if actions["etc/idleleo/v1/metadata.json"] != "unchanged" {
		t.Fatalf("unchanged metadata action = %q", actions["etc/idleleo/v1/metadata.json"])
	}
	// Dry run must not restore the deleted key or create a pre-backup.
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatalf("dry run wrote the deleted key back")
	}
	entries, err := os.ReadDir(filepath.Join(root, "etc/idleleo/backup"))
	if err == nil && len(entries) != 0 {
		t.Fatalf("dry run created a pre-backup: %v", entries)
	}
}

func TestVerifyRejectsDuplicateEntries(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "dup.tar.gz")
	f, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	manifest := []byte(`{"schemaVersion":1,"entries":[]}`)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		body := []byte("same")
		if err := tw.WriteHeader(&tar.Header{Name: "etc/idleleo/conf/xray/config.json", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
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
	if _, err := Verify(archive); err == nil {
		t.Fatal("verification accepted duplicate entries")
	}
}

func TestCreateAndVerify(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	rep, err := Create(context.Background(), root, archive, CreateOptions{Now: time.Unix(1000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 4 || rep.ArchiveSHA256 == "" {
		t.Fatalf("unexpected report: %+v", rep)
	}
	fi, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode = %04o", fi.Mode().Perm())
	}
	manifest, err := Verify(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Entries) != 4 {
		t.Fatalf("manifest entries = %d", len(manifest.Entries))
	}
	// An archive is never silently overwritten.
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err == nil {
		t.Fatal("second create overwrote an existing archive")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xff
	if err := os.WriteFile(archive, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(archive); err == nil {
		t.Fatal("tampered archive verified")
	}
}

func TestVerifyRejectsTrailingGarbage(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(archive, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-a-gzip-member"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(archive); err == nil {
		t.Fatal("verification ignored bytes appended after the gzip member")
	}
}

func TestRestorePreBackupNamesAreUniqueWithinASecond(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	first, err := Restore(context.Background(), root, archive, RestoreOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Restore(context.Background(), root, archive, RestoreOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if first.PreBackup == second.PreBackup {
		t.Fatalf("two restores in one second reused %s", first.PreBackup)
	}
	for _, p := range []string{first.PreBackup, second.PreBackup} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("pre-backup %s missing: %v", p, err)
		}
	}
}

func TestVerifyRejectsPathEscape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evil.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("x")
	if err := tw.WriteHeader(&tar.Header{Name: "../evil", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	f.Close()
	if _, err := Verify(path); err == nil {
		t.Fatal("path escape accepted")
	}
}

func TestRestoreRoundTripKeepsPreRestoreBackup(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{Now: time.Unix(1000, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.WriteFile(config, []byte(`{"inbounds":[{"port":8443}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := Restore(context.Background(), root, archive, RestoreOptions{Validate: func(context.Context, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Restored) != 4 || rep.PreBackup == "" {
		t.Fatalf("unexpected restore report: %+v", rep)
	}
	body, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"inbounds":[]}` {
		t.Fatalf("config was not restored: %s", body)
	}
	if _, err := os.Stat(rep.PreBackup); err != nil {
		t.Fatalf("pre-restore backup missing: %v", err)
	}
}

func TestRestoreAbortsWhenStagedConfigIsRejected(t *testing.T) {
	root := seedRoot(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if _, err := Create(context.Background(), root, archive, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.WriteFile(config, []byte(`{"inbounds":[{"port":8443}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Restore(context.Background(), root, archive, RestoreOptions{
		NoPreBackup: true,
		Validate:    func(context.Context, string) error { return os.ErrInvalid },
	})
	if err == nil {
		t.Fatal("restore proceeded with a rejected config")
	}
	body, _ := os.ReadFile(config)
	if !bytes.Contains(body, []byte("8443")) {
		t.Fatalf("live config was touched: %s", body)
	}
}
