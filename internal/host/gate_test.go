package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withMarkers(t *testing.T, markers ...string) {
	t.Helper()
	old := containerMarkers
	containerMarkers = markers
	t.Cleanup(func() { containerMarkers = old })
}

func TestWriteModeHostIsAllowed(t *testing.T) {
	withMarkers(t, filepath.Join(t.TempDir(), "no-marker"))
	mode, err := writeMode(false)
	if err != nil || mode != "host" {
		t.Fatalf("host mode=%q err=%v", mode, err)
	}
}

func TestWriteModeContainerRequiresFlagAndEnv(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "containerenv")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	withMarkers(t, marker)
	if _, err := writeMode(false); err == nil || !strings.Contains(err.Error(), "--container") {
		t.Fatalf("expected --container error, got %v", err)
	}
	t.Setenv("IDLELEO_ALLOW_SYSTEM_WRITES", "")
	if _, err := writeMode(true); err == nil || !strings.Contains(err.Error(), "IDLELEO_ALLOW_SYSTEM_WRITES") {
		t.Fatalf("expected env error, got %v", err)
	}
	t.Setenv("IDLELEO_ALLOW_SYSTEM_WRITES", "I_ACCEPT_CONTAINER_ONLY")
	mode, err := writeMode(true)
	if err != nil || mode != "container" {
		t.Fatalf("container mode=%q err=%v", mode, err)
	}
}

func TestRecordSystemWriteIsAppendOnlyAndPrivate(t *testing.T) {
	root := t.TempDir()
	if err := recordSystemWrite(root, "host"); err != nil {
		t.Fatal(err)
	}
	if err := recordSystemWrite(root, "host"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, WriteAuditRel))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(b), "mode=host"); lines != 2 {
		t.Fatalf("audit lines=%d body=%q", lines, b)
	}
	fi, err := os.Stat(filepath.Join(root, WriteAuditRel))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode=%o", fi.Mode().Perm())
	}
}

func TestRecordSystemWriteRedactsSecretsAndUnknownFlags(t *testing.T) {
	root := t.TempDir()
	const canary = "CANARY-7c41d0e2b9a84f63"
	oldArgs := os.Args
	os.Args = []string{
		"idleleo", "xray", "install",
		"--mode", "tls", "--port", "443",
		"--private-key", canary,
		"--cert-key", canary,
		"--email", canary + "@example.invalid",
		"--unknown-flag", canary,
	}
	t.Cleanup(func() { os.Args = oldArgs })

	if err := recordSystemWrite(root, "host"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, WriteAuditRel))
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	if strings.Contains(body, canary) {
		t.Fatalf("audit trail leaked a sensitive canary: %q", body)
	}
	for _, want := range []string{
		`operation="xray install"`,
		"--mode=tls",
		"--port=443",
		"--private-key=<redacted>",
		"--cert-key=<redacted>",
		"--email=<redacted>",
		"--unknown-flag=<redacted>",
		"plan=",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit trail missing %q: %q", want, body)
		}
	}
}

func TestDescribeAuditOmitsFlagValuesForUnknownFlags(t *testing.T) {
	event := describeAudit([]string{"idleleo", "xray", "config", "edit", "--token", "abc123", "--bogus", "def456"})
	if event.Operation != "xray config edit" {
		t.Fatalf("operation=%q", event.Operation)
	}
	if strings.Contains(event.Flags, "abc123") || strings.Contains(event.Flags, "def456") {
		t.Fatalf("flag values leaked: %q", event.Flags)
	}
	if event.Fingerprint == "" {
		t.Fatal("missing plan fingerprint")
	}
}

func TestRequireSystemWriteSandboxNeedsMarker(t *testing.T) {
	root := t.TempDir()
	if err := RequireSystemWrite(root, false); err == nil {
		t.Fatal("unmarked sandbox was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, SandboxMarker), []byte(SandboxMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireSystemWrite(root, false); err != nil {
		t.Fatalf("marked sandbox rejected: %v", err)
	}
}

// The audit line is the permission record: if it cannot be written, the write
// must not happen at all.
func TestRequireSystemWriteRefusesWhenAuditFails(t *testing.T) {
	withMarkers(t, filepath.Join(t.TempDir(), "no-marker"))
	old := recordWrite
	recordWrite = func(string, string) error { return errors.New("disk full") }
	t.Cleanup(func() { recordWrite = old })

	err := RequireSystemWrite("/", false)
	if err == nil || !strings.Contains(err.Error(), "audit trail unavailable") {
		t.Fatalf("expected audit refusal, got %v", err)
	}
}

func TestRequireSystemWriteRecordsBeforeAllowing(t *testing.T) {
	withMarkers(t, filepath.Join(t.TempDir(), "no-marker"))
	var modes []string
	old := recordWrite
	recordWrite = func(_ string, mode string) error {
		modes = append(modes, mode)
		return nil
	}
	t.Cleanup(func() { recordWrite = old })

	if err := RequireSystemWrite("/", false); err != nil {
		t.Fatalf("host write rejected: %v", err)
	}
	if len(modes) != 1 || modes[0] != "host" {
		t.Fatalf("audit modes=%v", modes)
	}
}
