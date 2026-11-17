package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
)

func stubLogrotate(t *testing.T, bin string, checkErr error) {
	t.Helper()
	oldLook, oldCheck, oldAccount := lookPathLogrotate, checkLogrotate, nginxLogAccount
	lookPathLogrotate = func() (string, error) {
		if bin == "" {
			return "", errors.New("executable file not found")
		}
		return bin, nil
	}
	checkLogrotate = func(context.Context, string, string) error { return checkErr }
	nginxLogAccount = func() (string, string) { return "idleleo-nginx", "idleleo-nginx" }
	t.Cleanup(func() {
		lookPathLogrotate, checkLogrotate, nginxLogAccount = oldLook, oldCheck, oldAccount
	})
}

func writeLog(t *testing.T, root, rel, body string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCleanLogsTruncatesOnlyRegularLogFiles(t *testing.T) {
	root := sandbox(t)
	access := writeLog(t, root, "var/log/xray/access.log", "0123456789")
	errorLog := writeLog(t, root, "var/log/xray/error.log", "12345")
	nested := writeLog(t, root, "var/log/xray/archive/old.log", "123")
	keep := writeLog(t, root, "var/log/xray/keep.txt", "keep")
	nginxLog := writeLog(t, root, filepath.Join(nginx.InstallDirRel, "logs/access.log"), "12")
	// A symlink must be skipped, exactly like Bash's `find -type f`.
	target := writeLog(t, root, "var/log/xray/real-target.txt", "untouched")
	link := filepath.Join(root, "var/log/xray/link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	report, err := CleanLogs(context.Background(), LogsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{access, errorLog, nested, nginxLog}
	sort.Strings(want)
	if strings.Join(report.Truncated, ",") != strings.Join(want, ",") {
		t.Fatalf("truncated = %v, want %v", report.Truncated, want)
	}
	if report.Freed != 20 {
		t.Fatalf("freed = %d, want 20", report.Freed)
	}
	for _, path := range want {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != 0 {
			t.Fatalf("%s was not truncated (size %d)", path, info.Size())
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode changed to %v", path, info.Mode())
		}
	}
	if body, _ := os.ReadFile(keep); string(body) != "keep" {
		t.Fatalf("non-log file was modified: %q", body)
	}
	if body, _ := os.ReadFile(target); string(body) != "untouched" {
		t.Fatalf("symlink target was truncated: %q", body)
	}
}

func TestCleanLogsWithoutLogDirectoriesIsNoop(t *testing.T) {
	root := sandbox(t)
	report, err := CleanLogs(context.Background(), LogsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Truncated) != 0 || len(report.Failed) != 0 || report.Freed != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestCleanLogsRefusesRealRootWithoutAck(t *testing.T) {
	if _, err := CleanLogs(context.Background(), LogsSpec{Root: "/"}); err == nil {
		t.Fatal("cleaning / without --container must be refused")
	}
}

func TestEnableLogRotationWritesBashBlockAndDropin(t *testing.T) {
	root := sandbox(t)
	stubLogrotate(t, "/usr/sbin/logrotate", nil)

	report, err := EnableLogRotation(context.Background(), LogsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Enabled || report.ConfigPath == "" || report.DropinPath == "" {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "sandbox") {
		t.Fatalf("warnings = %v", report.Warnings)
	}
	body, err := os.ReadFile(report.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(body)
	for _, want := range []string{
		filepath.Join(root, "var/log/xray") + "/*.log",
		filepath.Join(root, nginx.InstallDirRel) + "/logs/*.log",
		"    weekly\n",
		"    rotate 3\n",
		"    compress\n",
		"    copytruncate\n",
		"    create 640 idleleo-nginx idleleo-nginx\n",
		"-s reopen -c " + filepath.Join(root, nginx.InstallDirRel) + "/conf/nginx.conf",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("logrotate config missing %q:\n%s", want, conf)
		}
	}
	info, err := os.Stat(report.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("config mode = %v, want 0644", info.Mode())
	}
	dropin, err := os.ReadFile(report.DropinPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDropin := "[Service]\nReadWritePaths=-" + filepath.Join(root, nginx.InstallDirRel, "logs") + "\n"
	if string(dropin) != wantDropin {
		t.Fatalf("dropin = %q, want %q", dropin, wantDropin)
	}
}

func TestEnableLogRotationNeedsTheBinary(t *testing.T) {
	root := sandbox(t)
	stubLogrotate(t, "", nil)
	if _, err := EnableLogRotation(context.Background(), LogsSpec{Root: root}); err == nil ||
		!strings.Contains(err.Error(), "logrotate is not installed") {
		t.Fatalf("missing binary must fail with an actionable error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, logrotateConfRel)); !os.IsNotExist(statErr) {
		t.Fatal("a failed enable must not leave a config behind")
	}
}

func TestEnableLogRotationKeepsLiveConfigWhenCheckFails(t *testing.T) {
	root := sandbox(t)
	stubLogrotate(t, "/usr/sbin/logrotate", errors.New("syntax error"))
	if _, err := EnableLogRotation(context.Background(), LogsSpec{Root: root}); err == nil {
		t.Fatal("a config rejected by logrotate --debug must fail")
	}
	if _, statErr := os.Stat(filepath.Join(root, logrotateConfRel)); !os.IsNotExist(statErr) {
		t.Fatal("the rejected config must not be installed")
	}
	entries, err := os.ReadDir(filepath.Join(root, "etc/logrotate.d"))
	if err == nil {
		for _, entry := range entries {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestDisableLogRotationRemovesOnlyManagedFiles(t *testing.T) {
	root := sandbox(t)
	stubLogrotate(t, "/usr/sbin/logrotate", nil)
	report, err := EnableLogRotation(context.Background(), LogsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	other := writeLog(t, root, "etc/logrotate.d/nginx", "keep me")

	removed, err := DisableLogRotation(context.Background(), LogsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed.Removed) != 2 {
		t.Fatalf("removed = %v, want both managed files", removed.Removed)
	}
	for _, path := range []string{report.ConfigPath, report.DropinPath} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("%s survived disable", path)
		}
	}
	if body, _ := os.ReadFile(other); string(body) != "keep me" {
		t.Fatal("disable must not touch other logrotate files")
	}
}
