package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func preflightManifest(t *testing.T, dir, component, version string, data []byte) string {
	t.Helper()
	asset := filepath.Join(dir, component+"-"+version)
	if err := os.WriteFile(asset, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	body := map[string]any{
		"schemaVersion": 1,
		"component":     component,
		"version":       version,
		"sha256":        hex.EncodeToString(sum[:]),
		"sizeBytes":     len(data),
		"url":           asset,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, component+"-"+version+".json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUpdatePreflightReportsLevelsAndExitCodes(t *testing.T) {
	root := fixture(t)
	markSandbox(t, root)
	dir := t.TempDir()
	ok := []byte("#!/bin/sh\nif [ \"$1\" = -test ]; then exit 0; fi\nexit 0\n")
	bad := []byte("#!/bin/sh\nif [ \"$1\" = -test ]; then echo rejected >&2; exit 1; fi\nexit 0\n")

	manifest := preflightManifest(t, dir, "xray", "1.8.24", ok)
	code, out, errOut := run(t, "--root", root, "update", "preflight",
		"--component", "xray", "--manifest", manifest, "--json")
	if code != 0 {
		t.Fatalf("preflight rc=%d stderr=%s", code, errOut)
	}
	var report struct {
		Compatible bool `json:"compatible"`
		Levels     []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"levels"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("preflight did not emit JSON: %v: %s", err, out)
	}
	if !report.Compatible || len(report.Levels) != 4 {
		t.Fatalf("unexpected report: %s", out)
	}
	if report.Levels[2].Status != "not-run" || report.Levels[3].Status != "not-run" {
		t.Fatalf("service/client levels must stay not-run: %s", out)
	}

	badManifest := preflightManifest(t, dir, "xray", "1.8.25", bad)
	code, out, errOut = run(t, "--root", root, "update", "preflight",
		"--component", "xray", "--manifest", badManifest, "--json")
	if code != 7 || errOut == "" {
		t.Fatalf("incompatible preflight rc=%d stderr=%q", code, errOut)
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("failed preflight must still emit JSON: %v: %s", err, out)
	}
	if report.Compatible {
		t.Fatalf("incompatible candidate reported compatible: %s", out)
	}
}
