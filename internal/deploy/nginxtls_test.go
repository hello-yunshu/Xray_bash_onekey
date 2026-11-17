package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

func seedTLSInstall(t *testing.T, tls string, files map[string]string) string {
	t.Helper()
	root := sandbox(t)
	meta := store.Metadata{
		SchemaVersion:     store.ManagerSchemaVersion,
		ActiveEngine:      "xray",
		Role:              "node",
		TLS:               tls,
		Transport:         "ws",
		RuntimeConfigPath: "usr/local/etc/xray/config.json",
		RuntimeSHA256:     strings.Repeat("a", 64),
		OwnedResources:    []string{},
		UpdatedAt:         "2026-01-01T00:00:00Z",
	}
	b, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, nginxDirRel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSetTLSProtocolsPinsTLS13(t *testing.T) {
	in := "server {\n    ssl_protocols         TLSv1.2 TLSv1.3;\n}\n"
	out, changed := setTLSProtocols(in)
	if !changed {
		t.Fatal("TLSv1.2 must be rewritten")
	}
	if !strings.Contains(out, "    ssl_protocols         TLSv1.3;") {
		t.Fatalf("indent/spacing must be preserved: %q", out)
	}
	if again, changedAgain := setTLSProtocols(out); changedAgain || again != out {
		t.Fatal("TLSv1.3 alone is already the target state")
	}
}

func TestSetRealityTLS12TogglesBothWays(t *testing.T) {
	in := "map $ssl_preread_protocol $is_valid_protocol {\n        #TLSv1.2    1;\n        TLSv1.3    1;\n}\n"
	on, changed := setRealityTLS12(in, true)
	if !changed || !strings.Contains(on, "\n        TLSv1.2    1;\n") {
		t.Fatalf("1.2+ must uncomment the map entry: %q", on)
	}
	off, changed := setRealityTLS12(on, false)
	if !changed || !strings.Contains(off, "\n        #TLSv1.2    1;\n") {
		t.Fatalf("1.3 must comment the map entry back: %q", off)
	}
	if again, changedAgain := setRealityTLS12(off, false); changedAgain || again != off {
		t.Fatal("already TLSv1.3 only must be a no-op")
	}
}

func TestSetTLSVersionRewritesAndReloads(t *testing.T) {
	root := seedTLSInstall(t, "TLS", map[string]string{
		"03-xray-https.conf": "server {\n    ssl_protocols         TLSv1.2 TLSv1.3;\n}\n",
	})
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	rep, err := SetTLSVersion(context.Background(), TLSSpec{Root: root, Version: TLSVersion13})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Changed || !rep.Reloaded || rep.Mode != "TLS" {
		t.Fatalf("unexpected report: %+v", rep)
	}
	body, err := os.ReadFile(filepath.Join(root, nginxDirRel, "03-xray-https.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "ssl_protocols         TLSv1.3;") {
		t.Fatalf("file not rewritten: %q", body)
	}
}

func TestSetTLSVersionRefusesTLS12OnTLSMode(t *testing.T) {
	root := seedTLSInstall(t, "TLS", map[string]string{
		"03-xray-https.conf": "server {\n    ssl_protocols TLSv1.3;\n}\n",
	})
	_, err := SetTLSVersion(context.Background(), TLSSpec{Root: root, Version: TLSVersion12Plus})
	if err == nil || !strings.Contains(err.Error(), "h3/quic") {
		t.Fatalf("TLS mode must refuse TLSv1.2: %v", err)
	}
}

func TestSetTLSVersionRestoresOnNginxFailure(t *testing.T) {
	original := "server {\n    ssl_protocols         TLSv1.2 TLSv1.3;\n}\n"
	root := seedTLSInstall(t, "TLS", map[string]string{"03-xray-https.conf": original})
	stubBalanceNginxTest(t, func(context.Context, string) error {
		return errors.New("nginx: configuration file test failed")
	})
	_, err := SetTLSVersion(context.Background(), TLSSpec{Root: root, Version: TLSVersion13})
	if err == nil || !strings.Contains(err.Error(), "was restored") {
		t.Fatalf("failed nginx -t must restore the file: %v", err)
	}
	body, readErr := os.ReadFile(filepath.Join(root, nginxDirRel, "03-xray-https.conf"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != original {
		t.Fatalf("file not restored: %q", body)
	}
}
