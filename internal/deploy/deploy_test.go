package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	var calls []string
	stubService(t,
		func(_ context.Context, args ...string) error {
			calls = append(calls, "cmd:"+strings.Join(args, " "))
			return nil
		},
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
	for _, rel := range []string{logDirRel, "etc/idleleo/conf/xray"} {
		if _, statErr := os.Stat(filepath.Join(root, rel)); !os.IsNotExist(statErr) {
			t.Fatalf("%s was created by the install and survived rollback", rel)
		}
	}
	all := strings.Join(calls, "\n")
	if !strings.Contains(all, "cmd:disable xray") {
		t.Fatalf("fresh rollback must revoke the enable link; calls=%v", calls)
	}
	if !strings.Contains(all, "cmd:daemon-reload") {
		t.Fatalf("fresh rollback must reload systemd after removing the unit; calls=%v", calls)
	}
}

func TestCaptureRestorePreservesOwnershipAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := captureFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.exists || st.mode != 0o640 || st.uid < 0 || st.gid < 0 {
		t.Fatalf("capture missed mode/ownership: %+v", st)
	}

	// Simulate a root:xray 0640 file: the rollback must put the recorded
	// ownership back, otherwise User=xray cannot read the restored config.
	var gotUID, gotGID int
	oldChown := chownFile
	chownFile = func(_ string, uid, gid int) error {
		gotUID, gotGID = uid, gid
		return nil
	}
	t.Cleanup(func() { chownFile = oldChown })
	st.uid, st.gid = 0, 1001
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.restore(); err != nil {
		t.Fatal(err)
	}
	if gotUID != 0 || gotGID != 1001 {
		t.Fatalf("restore did not restore ownership: uid=%d gid=%d", gotUID, gotGID)
	}
	if body, _ := os.ReadFile(path); string(body) != "old\n" {
		t.Fatalf("restore did not restore content: %q", body)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("restore did not restore mode: %v", info.Mode())
	}
}

// TestRestoreRootXray0640ReadableByRuntimeUser is the concrete B4 case: after
// a failed reinstall overwrites a root:xray 0640 config, the rollback must put
// the group back so the unprivileged Xray account can still read it. It needs
// root and an xray account, so it skips in ordinary developer runs and is
// executed by tests/go-parity/deploy/run_deploy_owner_regression.sh.
func TestRestoreRootXray0640ReadableByRuntimeUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a root:xray 0640 file")
	}
	acc, err := user.Lookup("xray")
	if err != nil {
		t.Skip("no xray service account in this environment")
	}
	uid, _ := strconv.Atoi(acc.Uid)
	gid, _ := strconv.Atoi(acc.Gid)
	dir := t.TempDir()
	// t.TempDir is private (0700); the real config directory is traversable.
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	st, err := captureFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the failed reinstall: atomic replace as root produces root:root.
	if err := writeFileAtomic(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.restore(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode not restored: %v", info.Mode())
	}
	raw, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(raw.Uid) != 0 || int(raw.Gid) != gid {
		t.Fatalf("ownership not restored: %+v", info.Sys())
	}
	out, err := exec.Command("setpriv",
		fmt.Sprintf("--reuid=%d", uid), fmt.Sprintf("--regid=%d", gid),
		"--clear-groups", "cat", path).CombinedOutput()
	if err != nil {
		t.Fatalf("User=xray cannot read the restored config: %v (%s)", err, out)
	}
	if string(out) != "old\n" {
		t.Fatalf("User=xray read %q, want old content", out)
	}
}

func TestCaptureRestoreSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "config.json")
	if err := os.WriteFile(target, []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	st, err := captureFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.link != target {
		t.Fatalf("capture missed symlink target: %+v", st)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("replaced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.restore(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("restore did not recreate symlink: %q %v", got, err)
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
