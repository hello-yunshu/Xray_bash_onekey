package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func markSandbox(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".idleleo-phase01-sandbox"),
		[]byte("I_ACCEPT_DISPOSABLE_SANDBOX\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBackupCreateVerifyRestoreRoundTrip(t *testing.T) {
	root := fixture(t)
	markSandbox(t, root)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")

	code, out, errOut := run(t, "--root", root, "backup", "create", "--out", archive, "--json")
	if code != 0 {
		t.Fatalf("create rc=%d stderr=%s", code, errOut)
	}
	var created struct {
		Archive string `json:"archive"`
		Files   int    `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create did not emit JSON: %v: %s", err, out)
	}
	if created.Files == 0 || created.Archive != archive {
		t.Fatalf("unexpected create report: %+v", created)
	}
	fi, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode=%04o, want 0600", fi.Mode().Perm())
	}

	code, out, errOut = run(t, "backup", "verify", "--archive", archive)
	if code != 0 || !strings.Contains(out, "files=") {
		t.Fatalf("verify rc=%d out=%q stderr=%s", code, out, errOut)
	}

	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	body, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}

	code, out, errOut = run(t, "--root", root, "backup", "restore", "--archive", archive)
	if code != 0 {
		t.Fatalf("restore rc=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "preBackup=") {
		t.Fatalf("restore did not report a pre-backup: %q", out)
	}
	restored, err := os.ReadFile(config)
	if err != nil {
		t.Fatalf("restored config missing: %v", err)
	}
	if string(restored) != string(body) {
		t.Fatalf("restored config differs")
	}
}

func TestBackupRefusesUnmarkedSandbox(t *testing.T) {
	root := fixture(t)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	code, _, errOut := run(t, "--root", root, "backup", "create", "--out", archive)
	if code != 2 || !strings.Contains(errOut, "sandbox") {
		t.Fatalf("create without marker: rc=%d stderr=%q", code, errOut)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("archive must not exist after a refused create")
	}
}

func TestBackupVerifyRejectsTamperedArchive(t *testing.T) {
	root := fixture(t)
	markSandbox(t, root)
	archive := filepath.Join(t.TempDir(), "state.tar.gz")
	if code, _, errOut := run(t, "--root", root, "backup", "create", "--out", archive); code != 0 {
		t.Fatalf("create rc=%d stderr=%s", code, errOut)
	}
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xff
	if err := os.WriteFile(archive, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := run(t, "backup", "verify", "--archive", archive); code == 0 {
		t.Fatalf("tampered archive passed verification")
	}
}

func TestRepairFixesModesAndReports(t *testing.T) {
	root := fixture(t)
	markSandbox(t, root)
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := run(t, "--root", root, "repair", "--json")
	if code != 0 && code != 1 {
		t.Fatalf("repair rc=%d stderr=%s", code, errOut)
	}
	var rep struct {
		Actions   []string `json:"actions"`
		Remaining []string `json:"remaining"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("repair did not emit JSON: %v: %s", err, out)
	}
	joined := strings.Join(rep.Actions, "\n")
	if !strings.Contains(joined, "set mode of etc/idleleo/conf/xray/config.json") {
		t.Fatalf("repair did not record the chmod: %v", rep.Actions)
	}
	fi, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("config mode=%04o, want 0640", fi.Mode().Perm())
	}
}

func TestRepairDryRunChangesNothing(t *testing.T) {
	root := fixture(t)
	markSandbox(t, root)
	config := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "--root", root, "repair", "--dry-run", "--json")
	if code != 0 && code != 1 {
		t.Fatalf("dry-run rc=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "would set mode") {
		t.Fatalf("dry run did not preview the chmod: %s", out)
	}
	fi, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("dry run changed the mode to %04o", fi.Mode().Perm())
	}
}

func TestDoctorHealthySandbox(t *testing.T) {
	root := fixture(t)
	markSandbox(t, root)
	if err := os.MkdirAll(filepath.Join(root, "etc/idleleo/backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/idleleo/backup/seed.tar.gz"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		p := filepath.Join(root, "etc/idleleo/share/xray", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("geo"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "etc/idleleo/conf/xray/config.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "--root", root, "doctor", "--json")
	if code != 0 {
		t.Fatalf("healthy sandbox reported rc=%d stderr=%s out=%s", code, errOut, out)
	}
}
