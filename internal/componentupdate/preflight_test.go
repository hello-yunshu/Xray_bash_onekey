package componentupdate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func xrayPreflightScript(version string, acceptsConfig bool) string {
	body := "exit 0"
	if !acceptsConfig {
		body = "echo 'failed to load config: unsupported field' >&2; exit 1"
	}
	return "#!/bin/sh\n" +
		"if [ \"$1\" = version ]; then echo \"Xray " + version + "\"; exit 0; fi\n" +
		"if [ \"$1\" = -test ]; then " + body + "; fi\n" +
		"exit 0\n"
}

func levelByName(t *testing.T, report PreflightReport, name string) EvidenceLevel {
	t.Helper()
	for _, l := range report.Levels {
		if l.Name == name {
			return l
		}
	}
	t.Fatalf("level %q missing from %+v", name, report.Levels)
	return EvidenceLevel{}
}

func TestPreflightQualifiesXrayWithoutTouchingInstalledBinary(t *testing.T) {
	root := sandbox(t)
	old := seedXray(t, root, "1.8.20")
	dir := t.TempDir()
	candidate := []byte(xrayPreflightScript("1.8.24", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.24", asset, candidate)

	report, err := Preflight(context.Background(), Spec{
		Root: root, Component: KindXray, ManifestSource: manifest,
	})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if report.Action != "update" || report.PreviousVersion != "1.8.20" || report.CandidateVersion != "1.8.24" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if !report.DigestVerified || !report.Compatible {
		t.Fatalf("digest/compat flags wrong: %+v", report)
	}
	if got := levelByName(t, report, "installable"); got.Status != EvidenceDegraded {
		t.Fatalf("sandbox script must be degraded, not %q", got.Status)
	}
	if got := levelByName(t, report, "config-parses"); got.Status != EvidencePass {
		t.Fatalf("config-parses=%q detail=%q", got.Status, got.Detail)
	}
	for _, name := range []string{"service-starts", "client-connects"} {
		if got := levelByName(t, report, name); got.Status != EvidenceNotRun {
			t.Fatalf("%s=%q, want not-run", name, got.Status)
		}
	}
	installed, err := os.ReadFile(filepath.Join(root, "usr/local/bin/xray"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, old) {
		t.Fatal("preflight replaced the installed binary")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "etc/idleleo/backup")); len(entries) != 0 {
		t.Fatal("preflight created a backup")
	}
}

func TestPreflightRejectsCandidateThatCannotParseInstalledConfig(t *testing.T) {
	root := sandbox(t)
	old := seedXray(t, root, "1.8.20")
	dir := t.TempDir()
	candidate := []byte(xrayPreflightScript("1.8.24", false))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.24", asset, candidate)

	report, err := Preflight(context.Background(), Spec{
		Root: root, Component: KindXray, ManifestSource: manifest,
	})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
	if report.Compatible {
		t.Fatal("a rejected config must not be reported compatible")
	}
	if got := levelByName(t, report, "config-parses"); got.Status != EvidenceFail {
		t.Fatalf("config-parses=%q", got.Status)
	}
	installed, _ := os.ReadFile(filepath.Join(root, "usr/local/bin/xray"))
	if !bytes.Equal(installed, old) {
		t.Fatal("failed preflight modified the installed binary")
	}
}

func TestPreflightRefusesDowngrade(t *testing.T) {
	root := sandbox(t)
	seedXray(t, root, "1.8.24")
	dir := t.TempDir()
	candidate := []byte(xrayPreflightScript("1.8.10", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "1.8.10", asset, candidate)

	report, err := Preflight(context.Background(), Spec{
		Root: root, Component: KindXray, ManifestSource: manifest,
	})
	if !errors.Is(err, ErrDowngrade) {
		t.Fatalf("expected ErrDowngrade, got %v", err)
	}
	if report.Compatible {
		t.Fatal("a downgrade must not be reported compatible")
	}
}

func TestPreflightRejectsScriptForRealRoot(t *testing.T) {
	dir := t.TempDir()
	candidate := []byte(xrayPreflightScript("99.99.99", true))
	asset := filepath.Join(dir, "xray")
	writeFile(t, asset, string(candidate), 0o644)
	manifest := manifestFor(t, dir, KindXray, "99.99.99", asset, candidate)

	report, err := Preflight(context.Background(), Spec{
		Root: "/", Component: KindXray, ManifestSource: manifest,
	})
	if !errors.Is(err, ErrArtifact) {
		t.Fatalf("expected ErrArtifact on a real root, got %v", err)
	}
	if got := levelByName(t, report, "installable"); got.Status != EvidenceFail {
		t.Fatalf("installable=%q", got.Status)
	}
}

func TestPreflightNginxTestsCandidateAgainstInstalledConfig(t *testing.T) {
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

	report, err := Preflight(context.Background(), Spec{
		Root: root, Component: KindNginx, ManifestSource: manifest,
	})
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if got := levelByName(t, report, "installable"); got.Status != EvidencePass {
		t.Fatalf("installable=%q detail=%q", got.Status, got.Detail)
	}
	if got := levelByName(t, report, "config-parses"); got.Status != EvidencePass {
		t.Fatalf("config-parses=%q detail=%q", got.Status, got.Detail)
	}
	installed, _ := os.ReadFile(filepath.Join(root, "usr/local/nginx/sbin/nginx"))
	if !bytes.Equal(installed, []byte(nginxScript(t, "1.24.0", true))) {
		t.Fatal("preflight replaced the installed nginx")
	}
}
