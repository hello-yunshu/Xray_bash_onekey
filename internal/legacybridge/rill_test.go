package legacybridge

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeRillFile(t *testing.T, root, rel, body string) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return path
}

// The Rill observer stamps its snapshots with capturedAtEpochSeconds. The
// projection must use that field rather than the file mtime, otherwise a
// copied or touched file flips the freshness verdict.
func TestRillStatusUsesCapturedAtEpochSeconds(t *testing.T) {
	root := t.TempDir()
	writeRillFile(t, root, rillConfigRel, `{"schemaVersion":1,"mode":"normal"}`)
	old := time.Now().Add(-2 * time.Hour).Unix()
	obs := writeRillFile(t, root, rillObservationRel,
		fmt.Sprintf(`{"capturedAtEpochSeconds":%d,"xrayConfig":{},"services":[]}`, old))
	// A fresh mtime must not hide an old capturedAtEpochSeconds.
	now := time.Now()
	if err := os.Chtimes(obs, now, now); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	info := RillStatus(root)
	if !info.Installed {
		t.Fatalf("expected installed projection, got %+v", info)
	}
	if info.Status != "stale" {
		t.Fatalf("status = %q, want stale", info.Status)
	}
	if info.ObservationAgeSeconds < 6000 {
		t.Fatalf("observation age = %d, want about 7200", info.ObservationAgeSeconds)
	}
}

func TestRillStatusFreshCapturedAtWithOldMtime(t *testing.T) {
	root := t.TempDir()
	writeRillFile(t, root, rillConfigRel, `{"schemaVersion":1,"mode":"observe-only"}`)
	obs := writeRillFile(t, root, rillObservationRel,
		fmt.Sprintf(`{"capturedAtEpochSeconds":%d,"xrayConfig":{}}`, time.Now().Unix()))
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(obs, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	info := RillStatus(root)
	if info.Status != "active" {
		t.Fatalf("status = %q, want active", info.Status)
	}
	if info.Mode != "observe-only" {
		t.Fatalf("mode = %q", info.Mode)
	}
	if info.ObservationAgeSeconds > 60 {
		t.Fatalf("observation age = %d, want fresh", info.ObservationAgeSeconds)
	}
}

func TestRillStatusAbsentIsReadOnly(t *testing.T) {
	root := t.TempDir()
	info := RillStatus(root)
	if info.Installed || info.Status != "absent" || info.Enabled {
		t.Fatalf("unexpected absent projection: %+v", info)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("read-only projection created %d entries", len(entries))
	}
}

func TestRillStatusInstalledWithoutObservation(t *testing.T) {
	root := t.TempDir()
	writeRillFile(t, root, rillConfigRel, `{"schemaVersion":1,"mode":"normal"}`)
	writeRillFile(t, root, rillBinaryRel, "bin")
	info := RillStatus(root)
	if !info.Installed || info.Status != "installed-unobserved" {
		t.Fatalf("unexpected projection: %+v", info)
	}
	if info.Warning != "no xray-observation.json yet" {
		t.Fatalf("warning = %q", info.Warning)
	}
}

func TestRillStatusInvalidConfigDegrades(t *testing.T) {
	root := t.TempDir()
	writeRillFile(t, root, rillConfigRel, "{")
	writeRillFile(t, root, rillObservationRel, `{"capturedAtEpochSeconds":` +
		fmt.Sprint(time.Now().Unix()) + `}`)
	info := RillStatus(root)
	if !info.Installed || info.Status != "active" {
		t.Fatalf("unexpected projection: %+v", info)
	}
	if info.Warning != "config.json is not valid JSON" {
		t.Fatalf("warning = %q", info.Warning)
	}
}
