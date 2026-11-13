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
	managed, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := string(managed) + "# operator edit\n"
	if err := os.WriteFile(mainPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Install(context.Background(), InstallSpec{Root: root, Artifact: art, NoService: true})
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !rep.AlreadyInstalled {
		t.Fatalf("same build must be reported as already installed: %+v", rep)
	}
	if b, _ := os.ReadFile(mainPath); string(b) != edited {
		t.Fatalf("same-build reinstall must not rewrite an intact live config: %q", b)
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
	if !rep.Installed || rep.ConfigPreserved {
		t.Fatalf("unexpected report: %+v", rep)
	}
	for _, rel := range []string{"usr/local/nginx", UnitRel, MetadataRel, ConfDirRel} {
		if _, statErr := os.Stat(filepath.Join(root, rel)); statErr == nil {
			t.Fatalf("%s survived uninstall", rel)
		}
	}

	root = t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{Root: root, Artifact: sampleArtifact(t), NoService: true}); err != nil {
		t.Fatal(err)
	}
	kept, err := Uninstall(context.Background(), UninstallSpec{Root: root, KeepConf: true, NoService: true})
	if err != nil {
		t.Fatalf("uninstall with keep conf: %v", err)
	}
	if !kept.ConfigPreserved {
		t.Fatalf("keep-conf report: %+v", kept)
	}
	if _, statErr := os.Stat(filepath.Join(root, "etc/idleleo/conf/nginx/nginx.default")); statErr != nil {
		t.Fatalf("configuration should be preserved with KeepConf: %v", statErr)
	}

	root = t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{Root: root, Artifact: sampleArtifact(t), NoService: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(context.Background(), UninstallSpec{Root: root, NoService: true}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(root, ConfDirRel)); statErr == nil {
		t.Fatal("purge must remove the project configuration directory")
	}
}

func TestInstallAddsLocalIPGuard(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), LocalIP: "203.0.113.7", NoService: true,
	}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, InstallDirRel, "conf", "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "if ($host = '203.0.113.7') {") {
		t.Fatalf("local-IP guard missing:\n%s", b)
	}
}

func TestRewriteWarnsWhenAnchorMissing(t *testing.T) {
	_, warnings := RewriteMainConfigWithWarnings("http {\n}\n", ConfigOptions{LocalIP: "203.0.113.7"})
	if len(warnings) == 0 {
		t.Fatal("missing error_page anchor must produce a warning")
	}
}

func TestVerifyLayeredPermissionsDetectsDrift(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	if _, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), NoService: true,
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := VerifyLayeredPermissions(ctx, root); err != nil {
		t.Fatalf("fresh install must verify: %v", err)
	}

	confDir := filepath.Join(root, ConfDirRel)
	if err := os.Chmod(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLayeredPermissions(ctx, root); err == nil ||
		!strings.Contains(err.Error(), "want 0750") {
		t.Fatalf("mode drift must be reported, got %v", err)
	}
}

func TestInstallToleratesSymlinkInCertDir(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	certDir := filepath.Join(root, CertDirRel)
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/ssl/certs/ca-certificates.crt", filepath.Join(certDir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	rep, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), NoService: true,
	})
	if err != nil {
		t.Fatalf("an unrelated symlink must not abort the install: %v", err)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "skipped symlink") {
			found = true
		}
	}
	if !found {
		t.Fatalf("symlink skip must be reported as a warning: %v", rep.Warnings)
	}
}

func TestCertDirResolutionWarning(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/idleleo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, CertDirRel)); err != nil {
		t.Fatal(err)
	}
	rep, err := Install(context.Background(), InstallSpec{
		Root: root, Artifact: sampleArtifact(t), NoService: true,
	})
	if err != nil {
		t.Fatalf("install must tolerate an unresolvable cert dir: %v", err)
	}
	found := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "certificate directory unavailable") {
			found = true
		}
	}
	if !found {
		t.Fatalf("cert dir resolution failure must warn: %v", rep.Warnings)
	}
}

func TestRestoreKeepsGoingAfterDaemonReloadFailure(t *testing.T) {
	origService, origQuery := runService, queryService
	var calls []string
	runService = func(_ context.Context, args ...string) error {
		calls = append(calls, args[0])
		if args[0] == "daemon-reload" {
			return errTestRejected
		}
		return nil
	}
	queryService = func(context.Context, ...string) string { return "enabled" }
	t.Cleanup(func() { runService, queryService = origService, origQuery })

	err := restore(context.Background(), serviceSnapshot{
		managed: true, unitExisted: true, enabled: "enabled", active: "active",
	}, nil, &swapState{})
	if err == nil || !strings.Contains(err.Error(), "daemon-reload") {
		t.Fatalf("daemon-reload failure must surface: %v", err)
	}
	for _, want := range []string{"enable", "restart"} {
		found := false
		for _, call := range calls {
			if call == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("service state restore stopped early; %q not attempted: %v", want, calls)
		}
	}
}

func TestSameBuildRepairsMainConfigDrift(t *testing.T) {
	stubRuntime(t)
	root := t.TempDir()
	art := sampleArtifact(t)
	if _, err := Install(context.Background(), InstallSpec{Root: root, Artifact: art, NoService: true}); err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(root, InstallDirRel, "conf", "nginx.conf")
	if err := os.WriteFile(mainPath, []byte(sampleMainConf), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Install(context.Background(), InstallSpec{Root: root, Artifact: art, NoService: true})
	if err != nil {
		t.Fatalf("same-build reinstall: %v", err)
	}
	if !rep.AlreadyInstalled {
		t.Fatalf("same build must be reported as already installed: %+v", rep)
	}
	b, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "server_tokens off;") ||
		!strings.Contains(string(b), "include /etc/idleleo/conf/nginx/*.conf;") {
		t.Fatalf("drifted main config was not repaired:\n%s", b)
	}
}

func TestEnsureServiceSkipsRestartWhenUnchanged(t *testing.T) {
	stubRuntime(t)
	origService, origQuery := runService, queryService
	t.Cleanup(func() { runService, queryService = origService, origQuery })

	drive := func(changed bool) []string {
		var calls []string
		runService = func(_ context.Context, args ...string) error {
			calls = append(calls, args[0])
			return nil
		}
		queryService = func(_ context.Context, args ...string) string {
			if args[0] == "is-enabled" {
				return "enabled"
			}
			return "active"
		}
		rep := InstallReport{}
		if err := ensureService(context.Background(), "/", false, changed, &rep); err != nil {
			t.Fatalf("ensureService: %v", err)
		}
		return calls
	}

	for _, call := range drive(false) {
		if call == "restart" {
			t.Fatal("an unchanged same-build install must not restart an active service")
		}
	}
	found := false
	for _, call := range drive(true) {
		if call == "restart" {
			found = true
		}
	}
	if !found {
		t.Fatal("a repaired install must restart the active service")
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
