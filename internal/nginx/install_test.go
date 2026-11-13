package nginx

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMainConf = `#user  nobody;
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    server {
        listen       80;
        server_name  localhost;
        error_page   500 502 503 504  /50x.html;
    }
}
`

func TestRewriteMainConfigHTTPMode(t *testing.T) {
	out := RewriteMainConfig(sampleMainConf, ConfigOptions{LocalIP: "203.0.113.9"})
	for _, want := range []string{
		"user idleleo-nginx idleleo-nginx;",
		"worker_processes  auto;",
		"worker_connections  4096;",
		"server_tokens off;",
		"if ($host = '203.0.113.9') {",
		"return 403;",
		"include /etc/idleleo/conf/nginx/*.conf;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rewritten config missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "#user  nobody;") {
		t.Fatal("comment-only user line was not replaced")
	}
	httpBlock := strings.Index(out, "http {")
	include := strings.Index(out, "include /etc/idleleo/conf/nginx/*.conf;")
	if include < httpBlock {
		t.Fatalf("project include must stay inside the http block:\n%s", out)
	}
}

func TestRewriteMainConfigStreamMode(t *testing.T) {
	out := RewriteMainConfig(sampleMainConf, ConfigOptions{Stream: true})
	if !strings.HasSuffix(strings.TrimSpace(out), "include /etc/idleleo/conf/nginx/00-xray.conf;") {
		t.Fatalf("stream include must be appended at the top level:\n%s", out)
	}
	if strings.Contains(out, "include /etc/idleleo/conf/nginx/*.conf;") {
		t.Fatalf("stream mode must not use the http glob:\n%s", out)
	}
}

func TestRewriteMainConfigIsIdempotent(t *testing.T) {
	opts := ConfigOptions{LocalIP: "198.51.100.7"}
	once := RewriteMainConfig(sampleMainConf, opts)
	twice := RewriteMainConfig(once, opts)
	if once != twice {
		t.Fatalf("rewrite is not idempotent:\n--- once ---\n%s\n--- twice ---\n%s", once, twice)
	}
	if strings.Count(twice, "server_tokens off;") != 1 {
		t.Fatalf("server_tokens duplicated:\n%s", twice)
	}
	if strings.Count(twice, "if ($host = '198.51.100.7')") != 1 {
		t.Fatalf("local IP guard duplicated:\n%s", twice)
	}
}

func TestInstallPublishesManagedTree(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	rep, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), LocalIP: "203.0.113.9", NoService: true,
	})
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if !rep.Verified || rep.AlreadyInstalled {
		t.Fatalf("unexpected report: %+v", rep)
	}
	main, err := os.ReadFile(filepath.Join(root, "usr/local/nginx/conf/nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"user idleleo-nginx idleleo-nginx;",
		"include /etc/idleleo/conf/nginx/*.conf;",
		"server_tokens off;",
	} {
		if !strings.Contains(string(main), want) {
			t.Fatalf("managed main config missing %q:\n%s", want, main)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "etc/idleleo/conf/nginx/nginx.default")); err != nil {
		t.Fatalf("default config not preserved: %v", err)
	}
	metaBytes, err := os.ReadFile(filepath.Join(root, MetadataRel))
	if err != nil {
		t.Fatalf("metadata missing: %v", err)
	}
	var meta Metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("metadata invalid: %v", err)
	}
	if meta.Build != "2026.10.15.7679" || meta.BinarySHA256 == "" || meta.SchemaVersion != 1 {
		t.Fatalf("metadata incomplete: %+v", meta)
	}
	assertMode(t, filepath.Join(root, "usr/local/nginx"), 0o755)
	assertMode(t, filepath.Join(root, "usr/local/nginx/sbin/nginx"), 0o755)
	assertMode(t, filepath.Join(root, "etc/idleleo/conf/nginx"), 0o750)
	assertMode(t, filepath.Join(root, "etc/idleleo/conf/nginx/nginx.default"), 0o640)
	assertMode(t, filepath.Join(root, "usr/local/nginx/logs"), 0o750)
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/nginx.service")); err != nil {
		t.Fatalf("unit missing: %v", err)
	}
}

func TestInstallCreatesStreamPlaceholder(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), Stream: true, NoService: true,
	}); err != nil {
		t.Fatalf("install failed: %v", err)
	}
	placeholder := filepath.Join(root, "etc/idleleo/conf/nginx/00-xray.conf")
	if _, err := os.Stat(placeholder); err != nil {
		t.Fatalf("stream include target not created: %v", err)
	}
	main, _ := os.ReadFile(filepath.Join(root, "usr/local/nginx/conf/nginx.conf"))
	if !strings.Contains(string(main), "include /etc/idleleo/conf/nginx/00-xray.conf;") {
		t.Fatalf("stream include missing:\n%s", main)
	}
}

func TestInstallRollsBackWhenConfigTestFails(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	oldTree := filepath.Join(root, "usr/local/nginx")
	if err := os.MkdirAll(oldTree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldTree, "previous.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	original := runConfigTest
	runConfigTest = func(context.Context, string, string, string) error {
		return errTestRejected
	}
	defer func() { runConfigTest = original }()

	_, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), NoService: true,
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("failed nginx -t must roll back: %v", err)
	}
	if b, readErr := os.ReadFile(filepath.Join(oldTree, "previous.txt")); readErr != nil || string(b) != "old" {
		t.Fatalf("previous tree was not restored: %v %q", readErr, b)
	}
	if _, statErr := os.Stat(filepath.Join(root, MetadataRel)); statErr == nil {
		t.Fatal("failed install left metadata behind")
	}
	if _, statErr := os.Stat(filepath.Join(root, "etc/idleleo/conf/nginx/nginx.default")); statErr == nil {
		t.Fatal("failed install left nginx.default behind")
	}
}

func TestInstallSkipsSameBuild(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	art := sampleArtifact(t)
	if _, err := Install(context.Background(), InstallSpec{Root: root, Artifact: art, NoService: true}); err != nil {
		t.Fatalf("first install: %v", err)
	}
	mainPath := filepath.Join(root, "usr/local/nginx/conf/nginx.conf")
	if err := os.WriteFile(mainPath, []byte("# operator edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Install(context.Background(), InstallSpec{Root: root, Artifact: art, NoService: true})
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !rep.AlreadyInstalled {
		t.Fatalf("same build must be reported as already installed: %+v", rep)
	}
	if b, _ := os.ReadFile(mainPath); string(b) != "# operator edit\n" {
		t.Fatalf("same-build reinstall overwrote the live config: %q", b)
	}
}

func TestUninstallRemovesManagedLayout(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{Root: root, Artifact: sampleArtifact(t), NoService: true}); err != nil {
		t.Fatal(err)
	}
	rep, err := Uninstall(context.Background(), UninstallSpec{Root: root, NoService: true})
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !rep.Installed || !rep.ConfigPreserved {
		t.Fatalf("unexpected report: %+v", rep)
	}
	for _, rel := range []string{"usr/local/nginx", UnitRel, MetadataRel} {
		if _, statErr := os.Stat(filepath.Join(root, rel)); statErr == nil {
			t.Fatalf("%s survived uninstall", rel)
		}
	}
	if _, statErr := os.Stat(filepath.Join(root, "etc/idleleo/conf/nginx/nginx.default")); statErr != nil {
		t.Fatalf("configuration should be preserved without purge: %v", statErr)
	}

	root = t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{Root: root, Artifact: sampleArtifact(t), NoService: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(context.Background(), UninstallSpec{Root: root, PurgeConf: true, NoService: true}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(root, ConfDirRel)); statErr == nil {
		t.Fatal("purge must remove the project configuration directory")
	}
}

var errTestRejected = &testError{"synthetic nginx -t failure"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func stubRuntime(t *testing.T) {
	t.Helper()
	origTest, origService, origQuery, origVersion := runConfigTest, runService, queryService, runVersion
	runConfigTest = func(context.Context, string, string, string) error { return nil }
	runService = func(context.Context, ...string) error { return nil }
	queryService = func(context.Context, ...string) string { return "inactive" }
	runVersion = func(context.Context, string) string { return "nginx version: nginx/1.30.6" }
	t.Cleanup(func() {
		runConfigTest, runService, queryService, runVersion = origTest, origService, origQuery, origVersion
	})
}

func sampleArtifact(t *testing.T) Artifact {
	t.Helper()
	bin := fakeELF("x86")
	conf := []byte(sampleMainConf)
	data := tarGz(t, []tarEntry{
		{name: "nginx/", typ: tar.TypeDir, mode: 0o755},
		{name: "nginx/sbin/", typ: tar.TypeDir, mode: 0o755},
		{name: "nginx/sbin/nginx", body: bin, mode: 0o755, typ: tar.TypeReg},
		{name: "nginx/conf/", typ: tar.TypeDir, mode: 0o755},
		{name: "nginx/conf/nginx.conf", body: conf, mode: 0o644, typ: tar.TypeReg},
		{name: "nginx/logs/", typ: tar.TypeDir, mode: 0o755},
		{name: "nginx/html/", typ: tar.TypeDir, mode: 0o755},
	})
	sum := sha256.Sum256(bin)
	return Artifact{
		Build:   "2026.10.15.7679",
		Version: Versions{NginxBuild: "2026.10.15.7679", Nginx: "1.30.6"},
		Asset:   Asset{Arch: "x86", BinarySHA256: hex.EncodeToString(sum[:])},
		Data:    data,
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode %o, want %o", path, got, want)
	}
}
