package host

import (
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
