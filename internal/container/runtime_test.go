package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

func write(t *testing.T, path, body string, mode os.FileMode) {
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
	write(t, filepath.Join(root, host.SandboxMarker), host.SandboxMarkerValue+"\n", 0o644)
	return root
}

func metadata(t *testing.T, root, tls string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node",
		"tls": tls, "transport": "raw",
		"runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256":     strings.Repeat("b", 64),
		"updatedAt":         "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"), string(body)+"\n", 0o644)
}

func fakeServices(t *testing.T, root string) {
	t.Helper()
	write(t, filepath.Join(root, "usr/local/bin/xray"), "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n", 0o755)
	write(t, filepath.Join(root, "usr/local/nginx/sbin/nginx"), "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n", 0o755)
	write(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"), "{}\n", 0o644)
	write(t, filepath.Join(root, "usr/local/nginx/conf/nginx.conf"), "events {}\n", 0o644)
}

func TestStatusEmptyRootIsReadOnly(t *testing.T) {
	root := sandbox(t)
	report, err := Status(root)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if report.SchemaVersion != 1 || report.Root != root {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.InContainer != host.InContainer() || report.Mode != DetectMode() {
		t.Fatalf("mode mismatch: %+v", report)
	}
	if report.Xray.Alive || report.Nginx.Alive {
		t.Fatalf("empty root reports live services: %+v", report)
	}
	for _, rel := range []string{"run", "var"} {
		if _, err := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(err) {
			t.Fatalf("Status wrote %s", rel)
		}
	}
}

func TestUpDownDirectAndIdempotent(t *testing.T) {
	if DetectMode() != ModeDirect {
		t.Skip("systemd host: direct mode cannot be exercised")
	}
	root := sandbox(t)
	metadata(t, root, "TLS")
	fakeServices(t, root)
	ctx := context.Background()

	up, err := Up(ctx, Spec{Root: root})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(up.Started) != 2 || len(up.Skipped) != 0 {
		t.Fatalf("expected both services started: %+v", up)
	}
	if up.Pids["xray"] <= 0 || up.Pids["nginx"] <= 0 {
		t.Fatalf("missing pids: %+v", up)
	}
	if _, err := os.Stat(filepath.Join(root, logFileRel)); err != nil {
		t.Fatalf("log file missing: %v", err)
	}
	status, err := Status(root)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Xray.Alive || !status.Nginx.Alive {
		t.Fatalf("status reports dead services: %+v", status)
	}
	if status.Xray.Pid != up.Pids["xray"] || status.Nginx.Pid != up.Pids["nginx"] {
		t.Fatalf("status pid mismatch: %+v vs %+v", status, up)
	}

	again, err := Up(ctx, Spec{Root: root})
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if len(again.Started) != 0 || len(again.Skipped) != 2 {
		t.Fatalf("second Up was not idempotent: %+v", again)
	}
	if again.Pids["xray"] != up.Pids["xray"] {
		t.Fatalf("pid changed on repeat: %+v vs %+v", again.Pids, up.Pids)
	}

	down, err := Down(ctx, Spec{Root: root})
	if err != nil {
		t.Fatalf("Down: %v", err)
	}
	if len(down.Stopped) != 2 {
		t.Fatalf("expected both stopped: %+v", down)
	}
	status, _ = Status(root)
	if status.Xray.Alive || status.Nginx.Alive {
		t.Fatalf("services alive after Down: %+v", status)
	}
	second, err := Down(ctx, Spec{Root: root})
	if err != nil {
		t.Fatalf("second Down: %v", err)
	}
	if len(second.Stopped) != 0 {
		t.Fatalf("second Down was not a no-op: %+v", second)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	root := sandbox(t)
	metadata(t, root, "TLS")
	fakeServices(t, root)
	report, err := Up(context.Background(), Spec{Root: root, DryRun: true})
	if err != nil {
		t.Fatalf("Up dry-run: %v", err)
	}
	if len(report.Started) != 2 {
		t.Fatalf("dry-run should plan both services: %+v", report)
	}
	for _, rel := range []string{"run", "var"} {
		if _, err := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(err) {
			t.Fatalf("dry-run wrote %s", rel)
		}
	}
}

func TestMissingConfigIsSkipped(t *testing.T) {
	if DetectMode() != ModeDirect {
		t.Skip("systemd host")
	}
	root := sandbox(t)
	metadata(t, root, "TLS")
	write(t, filepath.Join(root, "usr/local/bin/xray"), "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n", 0o755)
	write(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"), "{}\n", 0o644)
	report, err := Up(context.Background(), Spec{Root: root})
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(report.Started) != 1 || report.Started[0] != "xray" {
		t.Fatalf("expected only xray: %+v", report)
	}
	if len(report.Skipped) != 1 || report.Skipped[0] != "nginx" {
		t.Fatalf("expected nginx skipped: %+v", report)
	}
	if _, err := Down(context.Background(), Spec{Root: root}); err != nil {
		t.Fatalf("Down: %v", err)
	}
}

func TestRealRootNeedsAcknowledgement(t *testing.T) {
	_, err := Up(context.Background(), Spec{Root: "/"})
	var usage *change.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestStalePidFileIsReported(t *testing.T) {
	root := sandbox(t)
	write(t, pidFile(root, "xray"), "999999\n", 0o644)
	report, err := Status(root)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if report.Xray.Alive {
		t.Fatalf("stale pid reported alive: %+v", report.Xray)
	}
	found := false
	for _, w := range report.Warnings {
		if w == "xray pid file is stale" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale pid warning missing: %+v", report.Warnings)
	}
}

func TestUnmarkedSandboxIsRefused(t *testing.T) {
	root := t.TempDir()
	_, err := Up(context.Background(), Spec{Root: root})
	var usage *change.UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestOwnedByRejectsForeignProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a probe process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	if ownedBy(cmd.Process.Pid, "/usr/local/bin/xray") {
		t.Fatal("a foreign process was claimed as a managed service")
	}
}
