package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

func sandbox(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func stubXray(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func stubService(t *testing.T, command func(context.Context, ...string) error, query func(context.Context, ...string) string) {
	t.Helper()
	oldCmd, oldQuery, oldManaged := serviceCommand, serviceQuery, serviceManaged
	serviceCommand, serviceQuery = command, query
	serviceManaged = func(string) bool { return true }
	t.Cleanup(func() {
		serviceCommand, serviceQuery, serviceManaged = oldCmd, oldQuery, oldManaged
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func seedReinstall(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{
		configRel:                      `{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}` + "\n",
		binaryRel:                      "old-binary\n",
		unitRel:                        "[Service]\nExecStart=/old/xray\n",
		"etc/idleleo/v1/metadata.json": `{"schemaVersion":1}` + "\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func assertRestored(t *testing.T, root string, want map[string]string) {
	t.Helper()
	for rel, body := range want {
		if got := readFile(t, filepath.Join(root, rel)); got != body {
			t.Fatalf("%s was not restored; got %q want %q", rel, got, body)
		}
	}
}

func TestReinstallRollbackRestoresFilesAndService(t *testing.T) {
	root := sandbox(t)
	previous := seedReinstall(t, root)
	var calls []string
	restartFailures := 1
	stubService(t,
		func(_ context.Context, args ...string) error {
			calls = append(calls, "cmd:"+strings.Join(args, " "))
			if args[0] == "restart" && restartFailures > 0 {
				restartFailures--
				return fmt.Errorf("injected restart failure")
			}
			return nil
		},
		func(_ context.Context, args ...string) string {
			switch args[0] {
			case "is-enabled":
				return "enabled"
			case "is-active":
				return "active"
			}
			return "unknown"
		},
	)
	_, err := Install(context.Background(), InstallSpec{
		Root: root, SourceBinary: stubXray(t), Mode: "none", KeepConfig: true,
	})
	if err == nil {
		t.Fatal("install must fail when the restart fails")
	}
	if !strings.Contains(err.Error(), "installation rolled back") {
		t.Fatalf("error must state that rollback happened: %v", err)
	}
	assertRestored(t, root, previous)
	if !strings.Contains(strings.Join(calls, "\n"), "cmd:enable xray") {
		t.Fatalf("service enable state was not restored; calls=%v", calls)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "cmd:restart xray\n") {
		t.Fatalf("service active state was not restored; calls=%v", calls)
	}
}

func TestFreshInstallRollbackRemovesNewFiles(t *testing.T) {
	root := sandbox(t)
	stubService(t,
		func(context.Context, ...string) error { return nil },
		func(_ context.Context, args ...string) string {
			if args[0] == "is-active" {
				return "failed"
			}
			return "disabled"
		},
	)
	_, err := Install(context.Background(), InstallSpec{Root: root, SourceBinary: stubXray(t), Mode: "none"})
	if err == nil {
		t.Fatal("install must fail when the service never becomes active")
	}
	if !strings.Contains(err.Error(), "installation rolled back") {
		t.Fatalf("error must state that rollback happened: %v", err)
	}
	for _, rel := range []string{configRel, binaryRel, unitRel, "etc/idleleo/v1/metadata.json"} {
		if _, statErr := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(statErr) {
			t.Fatalf("%s survived a rolled-back fresh install", rel)
		}
	}
}

func TestRollbackFailureIsReportedNotHidden(t *testing.T) {
	root := sandbox(t)
	seedReinstall(t, root)
	stubService(t,
		func(_ context.Context, args ...string) error {
			switch args[0] {
			case "restart":
				return fmt.Errorf("injected restart failure")
			case "daemon-reload":
				return fmt.Errorf("injected daemon-reload failure")
			}
			return nil
		},
		func(_ context.Context, args ...string) string {
			if args[0] == "is-active" {
				return "active"
			}
			return "enabled"
		},
	)
	_, err := Install(context.Background(), InstallSpec{
		Root: root, SourceBinary: stubXray(t), Mode: "none", KeepConfig: true,
	})
	if err == nil {
		t.Fatal("install must fail")
	}
	if !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("incomplete rollback must be reported: %v", err)
	}
	if !strings.Contains(err.Error(), "inspect") {
		t.Fatalf("incomplete rollback must name the manual work: %v", err)
	}
}
