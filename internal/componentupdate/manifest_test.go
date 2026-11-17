package componentupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersionsTable(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.8.24", "1.8.24", 0},
		{"1.8", "1.8.0", 0},
		{"v1.8.24", "1.8.23", 1},
		{"1.8.9", "1.8.10", -1},
		{"2.0", "1.99.99", 1},
		{"1.0.0.1", "1.0", 1},
	}
	for _, c := range cases {
		got, err := CompareVersions(c.a, c.b)
		if err != nil {
			t.Fatalf("%s vs %s: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Fatalf("%s vs %s: got %d want %d", c.a, c.b, got, c.want)
		}
	}
	if _, err := CompareVersions("nightly", "1.0"); err == nil {
		t.Fatal("non-dotted version must be refused")
	}
}

func TestLoadManifestRejectsBadRecords(t *testing.T) {
	dir := t.TempDir()
	body := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		p := filepath.Join(dir, "m.json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := map[string]any{
		"schemaVersion": 1, "component": "xray", "version": "1.8.24",
		"sha256": strings.Repeat("a", 64), "sizeBytes": 12, "url": "/tmp/xray",
	}
	if _, err := LoadManifest(context.Background(), body(good)); err != nil {
		t.Fatalf("good manifest: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema":    func(m map[string]any) { m["schemaVersion"] = 2 },
		"component": func(m map[string]any) { m["component"] = "other" },
		"version":   func(m map[string]any) { m["version"] = "latest" },
		"sha":       func(m map[string]any) { m["sha256"] = "abc" },
		"url":       func(m map[string]any) { m["url"] = "" },
		"zeroSize":  func(m map[string]any) { m["sizeBytes"] = 0 },
		"negative":  func(m map[string]any) { m["sizeBytes"] = -1 },
	} {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		mutate(m)
		if _, err := LoadManifest(context.Background(), body(m)); !errors.Is(err, ErrManifest) {
			t.Fatalf("%s: expected ErrManifest, got %v", name, err)
		}
	}
}

func TestCompareVersionsMatchesBashTable(t *testing.T) {
	table := [][3]string{
		{"1.8.24", "1.8.24", "eq"},
		{"1.8.25", "1.8.24", "gt"},
		{"1.8.9", "1.8.10", "lt"},
		{"1.7.99", "1.8.0", "lt"},
		{"2.0", "1.99.99", "gt"},
	}
	for _, row := range table {
		got, err := CompareVersions(row[0], row[1])
		if err != nil {
			t.Fatal(err)
		}
		var gotLabel string
		switch {
		case got == 0:
			gotLabel = "eq"
		case got > 0:
			gotLabel = "gt"
		default:
			gotLabel = "lt"
		}
		if gotLabel != row[2] {
			t.Fatalf("%s vs %s: %s != %s", row[0], row[1], gotLabel, row[2])
		}
	}
}

func TestFetchAssetVerifiesDigestAndSize(t *testing.T) {
	dir := t.TempDir()
	asset := filepath.Join(dir, "asset")
	if err := os.WriteFile(asset, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	m := Manifest{Component: KindXray, Version: "1.0", URL: asset,
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: 7}
	if _, err := FetchAsset(context.Background(), m); err != nil {
		t.Fatalf("FetchAsset: %v", err)
	}
	m.SizeBytes = 8
	if _, err := FetchAsset(context.Background(), m); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("size mismatch: %v", err)
	}
	m.SizeBytes = 7
	m.SHA256 = strings.Repeat("0", 64)
	if _, err := FetchAsset(context.Background(), m); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("digest mismatch: %v", err)
	}
}
