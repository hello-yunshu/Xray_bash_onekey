package componentupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func sandbox(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, host.SandboxMarker), host.SandboxMarkerValue+"\n", 0o644)
	return root
}

func xrayScript(version string, health bool) string {
	healthBody := "exit 0"
	if !health {
		healthBody = "exit 1"
	}
	return "#!/bin/sh\n" +
		"if [ \"$1\" = version ]; then echo \"Xray " + version + "\"; exit 0; fi\n" +
		"if [ \"$1\" = run ]; then " + healthBody + "; fi\n" +
		"exit 0\n"
}

func manifestFor(t *testing.T, dir, component, version, asset string, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	m := map[string]any{
		"schemaVersion": 1,
		"component":     component,
		"version":       version,
		"sha256":        hex.EncodeToString(sum[:]),
		"sizeBytes":     len(data),
		"url":           asset,
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, component+"-"+version+".json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func seedXray(t *testing.T, root, version string) []byte {
	t.Helper()
	body := []byte(xrayScript(version, true))
	writeFile(t, filepath.Join(root, "usr/local/bin/xray"), string(body), 0o755)
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"), "{}\n", 0o644)
	return body
}

func TestApplyXrayUpdateAndReinstall(t *testing.T) {
	root := sandbox(t)
	old := seedXray(t, root, "1.8.20")
	dir := t.TempDir()
	candidate := []byte(xrayScript("1.8.24", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.24", asset, candidate)
	ctx := context.Background()

	report, err := Apply(ctx, Spec{Root: root, Component: KindXray, ManifestSource: manifest})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if report.Action != "update" || report.PreviousVersion != "1.8.20" || report.NewVersion != "1.8.24" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if !report.Verified || !report.Health || report.Restarted || report.RolledBack {
		t.Fatalf("unexpected flags: %+v", report)
	}
	got, err := os.ReadFile(filepath.Join(root, "usr/local/bin/xray"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, candidate) {
		t.Fatal("installed binary is not the candidate bytes")
	}
	backup, err := os.ReadFile(report.BackupPath)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if !bytes.Equal(backup, old) {
		t.Fatal("backup is not the previous bytes")
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0], "reload skipped") {
		t.Fatalf("sandbox update must warn about the skipped reload: %+v", report.Warnings)
	}

	again, err := Apply(ctx, Spec{Root: root, Component: KindXray, ManifestSource: manifest})
	if err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if again.Action != "reinstall" || again.BackupPath == report.BackupPath {
		t.Fatalf("reinstall did not create a fresh backup: %+v", again)
	}
}

func TestApplyXrayRefusesDowngrade(t *testing.T) {
	root := sandbox(t)
	old := seedXray(t, root, "1.8.24")
	dir := t.TempDir()
	candidate := []byte(xrayScript("1.8.10", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.10", asset, candidate)

	_, err := Apply(context.Background(), Spec{Root: root, Component: KindXray, ManifestSource: manifest})
	if !errors.Is(err, ErrDowngrade) {
		t.Fatalf("expected ErrDowngrade, got %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "usr/local/bin/xray"))
	if !bytes.Equal(got, old) {
		t.Fatal("downgrade modified the binary")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "etc/idleleo/backup")); len(entries) != 0 {
		t.Fatal("downgrade created a backup")
	}
}

func TestApplyXrayDigestMismatchTouchesNothing(t *testing.T) {
	root := sandbox(t)
	old := seedXray(t, root, "1.8.20")
	dir := t.TempDir()
	candidate := []byte(xrayScript("1.8.24", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.24", asset, candidate)
	writeFile(t, asset, string(append(candidate, '\n')), 0o644)

	_, err := Apply(context.Background(), Spec{Root: root, Component: KindXray, ManifestSource: manifest})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "usr/local/bin/xray"))
	if !bytes.Equal(got, old) {
		t.Fatal("digest mismatch modified the binary")
	}
}

func TestApplyXrayHealthFailureRollsBack(t *testing.T) {
	root := sandbox(t)
	old := seedXray(t, root, "1.8.20")
	dir := t.TempDir()
	candidate := []byte(xrayScript("1.8.24", false))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.24", asset, candidate)

	report, err := Apply(context.Background(), Spec{Root: root, Component: KindXray, ManifestSource: manifest})
	if !errors.Is(err, ErrHealth) {
		t.Fatalf("expected ErrHealth, got %v", err)
	}
	if !report.RolledBack {
		t.Fatalf("report must mark the rollback: %+v", report)
	}
	got, _ := os.ReadFile(filepath.Join(root, "usr/local/bin/xray"))
	if !bytes.Equal(got, old) {
		t.Fatal("health failure did not restore the old binary")
	}
}

func TestApplyRejectsWrongComponentAndRealRoot(t *testing.T) {
	root := sandbox(t)
	seedXray(t, root, "1.8.20")
	dir := t.TempDir()
	candidate := []byte(xrayScript("1.8.24", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindNginx, "1.8.24", asset, candidate)
	if _, err := Apply(context.Background(), Spec{Root: root, Component: KindXray, ManifestSource: manifest}); !errors.Is(err, ErrComponentMismatch) {
		t.Fatalf("expected ErrComponentMismatch, got %v", err)
	}
	manifest = manifestFor(t, dir, KindXray, "1.8.24", asset, candidate)
	_, err := Apply(context.Background(), Spec{Root: "/", Component: KindXray, ManifestSource: manifest})
	var usage *change.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("expected usage error on the real root, got %v", err)
	}
}

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		mode := int64(0o644)
		if strings.HasSuffix(name, "/sbin/nginx") {
			mode = 0o755
		}
		hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func nginxScript(t *testing.T, version string, healthy bool) string {
	t.Helper()
	check := "exit 0"
	if !healthy {
		check = "exit 1"
	}
	return "#!/bin/sh\n" +
		"if [ \"$1\" = -v ]; then echo \"nginx version: nginx/" + version + "\" >&2; exit 0; fi\n" +
		"if [ \"$1\" = -t ]; then " + check + "; fi\n" +
		"exit 0\n"
}

func seedNginx(t *testing.T, root, version string) map[string]string {
	t.Helper()
	files := map[string]string{
		"nginx/sbin/nginx":      nginxScript(t, version, true),
		"nginx/conf/nginx.conf": "events {}\n",
		"nginx/logs/.keep":      "",
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, "/sbin/nginx") {
			mode = 0o755
		}
		writeFile(t, filepath.Join(root, "usr/local", filepath.FromSlash(name)), body, mode)
	}
	return files
}

func TestApplyNginxUpdateAndRollback(t *testing.T) {
	root := sandbox(t)
	seedNginx(t, root, "1.24.0")
	dir := t.TempDir()
	candidate := tarGz(t, map[string]string{
		"nginx/sbin/nginx":      nginxScript(t, "1.24.1", true),
		"nginx/conf/nginx.conf": "events {}\n",
	})
	asset := filepath.Join(dir, "nginx.tar.gz")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindNginx, "1.24.1", asset, candidate)

	report, err := Apply(context.Background(), Spec{Root: root, Component: KindNginx, ManifestSource: manifest})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !report.Health || report.PreviousVersion != "1.24.0" || report.NewVersion != "1.24.1" {
		t.Fatalf("unexpected report: %+v", report)
	}
	got, _ := os.ReadFile(filepath.Join(root, "usr/local/nginx/sbin/nginx"))
	if !bytes.Equal(got, []byte(nginxScript(t, "1.24.1", true))) {
		t.Fatal("nginx directory was not replaced")
	}
	if _, err := os.Stat(report.BackupPath); err != nil {
		t.Fatalf("nginx backup missing: %v", err)
	}

	bad := tarGz(t, map[string]string{
		"nginx/sbin/nginx":      nginxScript(t, "1.24.2", false),
		"nginx/conf/nginx.conf": "events {}\n",
	})
	badAsset := filepath.Join(dir, "bad.tar.gz")
	writeFile(t, badAsset, string(bad), 0o644)
	badManifest := manifestFor(t, dir, KindNginx, "1.24.2", badAsset, bad)
	failed, err := Apply(context.Background(), Spec{Root: root, Component: KindNginx, ManifestSource: badManifest})
	if !errors.Is(err, ErrHealth) {
		t.Fatalf("expected ErrHealth, got %v", err)
	}
	if !failed.RolledBack {
		t.Fatalf("health failure was not rolled back: %+v", failed)
	}
	restored, _ := os.ReadFile(filepath.Join(root, "usr/local/nginx/sbin/nginx"))
	if !bytes.Equal(restored, []byte(nginxScript(t, "1.24.1", true))) {
		t.Fatal("nginx health failure did not restore the previous directory")
	}
}
