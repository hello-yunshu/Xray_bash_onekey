package release

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fakeELF(goarch string) []byte {
	machine := map[string]uint16{"amd64": 62, "arm64": 183}[goarch]
	b := make([]byte, 128)
	copy(b, "\x7fELF")
	b[4], b[5] = 2, 1
	binary.LittleEndian.PutUint16(b[18:20], machine)
	return b
}

func pinLinuxPlatform(t *testing.T) {
	t.Helper()
	old := platformKey
	platformKey = func() string { return "linux-" + runtime.GOARCH }
	t.Cleanup(func() { platformKey = old })
}

func serveRelease(t *testing.T, assetBytes []byte) *httptest.Server {
	t.Helper()
	key := installTestReleaseKey(t)
	body := signedManifestBytes(t, Manifest{
		SchemaVersion: SchemaVersion,
		Channel:       ChannelName,
		Version:       "0.5.0",
		Assets: map[string]Asset{
			platformKey(): {Name: "asset", SHA256: hashBytes(assetBytes), Size: int64(len(assetBytes))},
		},
	}, key)
	mux := http.NewServeMux()
	mux.HandleFunc("/go/manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/go/asset", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(assetBytes)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestManifestURLRequiresHTTPSOutsideLoopback(t *testing.T) {
	ok := []string{
		"https://example.com/go/manifest.json",
		"http://127.0.0.1:8080/go/manifest.json",
		"http://localhost:8080/go/manifest.json",
		"http://[::1]:8080/go/manifest.json",
	}
	for _, raw := range ok {
		if err := validateManifestURL(raw); err != nil {
			t.Fatalf("%s should be allowed: %v", raw, err)
		}
	}
	bad := []string{
		"http://example.com/go/manifest.json",
		"http://192.168.1.10/go/manifest.json",
		"ftp://example.com/go/manifest.json",
		"https://user:pass@example.com/go/manifest.json",
	}
	for _, raw := range bad {
		if err := validateManifestURL(raw); err == nil {
			t.Fatalf("%s should be rejected", raw)
		}
	}
}

func TestAssetURLMustStayOnTrustedOrigin(t *testing.T) {
	base := "https://releases.example.com/go/manifest.json"
	if _, err := assetURL(base, Asset{Name: "../asset"}); err != nil {
		t.Fatalf("same-origin asset rejected: %v", err)
	}
	if _, err := assetURL(base, Asset{Name: "https://evil.example.net/asset"}); err == nil {
		t.Fatal("cross-origin asset must be rejected")
	}
	if _, err := assetURL(base, Asset{Name: "http://releases.example.com/asset"}); err == nil {
		t.Fatal("plain HTTP asset must be rejected on an HTTPS manifest")
	}
	if _, err := assetURL("http://127.0.0.1:8080/go/manifest.json", Asset{Name: "asset"}); err != nil {
		t.Fatalf("loopback test asset rejected: %v", err)
	}
}

func TestApplyRestoresPreviousBinaryWhenStateCannotBeWritten(t *testing.T) {
	pinLinuxPlatform(t)
	root := t.TempDir()
	asset := fakeELF(runtime.GOARCH)
	srv := serveRelease(t, asset)
	if _, err := Configure(context.Background(), root, srv.URL+"/go/manifest.json", "opt/idleleo/bin/idleleo"); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(root, "opt/idleleo/bin/idleleo")
	if err := os.MkdirAll(filepath.Dir(install), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(install, []byte("old binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldHealth, oldWrite := healthCheckBinary, writeStateFile
	healthCheckBinary = func(context.Context, string, string) (string, error) { return "idleleo 0.5.0", nil }
	writeStateFile = func(string, State) error { return errors.New("injected state write failure") }
	t.Cleanup(func() { healthCheckBinary, writeStateFile = oldHealth, oldWrite })

	rep, err := Apply(context.Background(), root, "", nil)
	if err == nil {
		t.Fatal("apply must fail when the state cannot be recorded")
	}
	if rep.Action != "rolled-back" {
		t.Fatalf("err=%v action=%q, want rolled-back", err, rep.Action)
	}
	b, err := os.ReadFile(install)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old binary\n" {
		t.Fatalf("previous binary was not restored: %q", string(b))
	}
}

func TestApplyRejectsTamperedManifest(t *testing.T) {
	pinLinuxPlatform(t)
	root := t.TempDir()
	asset := fakeELF(runtime.GOARCH)
	key := installTestReleaseKey(t)
	body := signedManifestBytes(t, Manifest{
		SchemaVersion: SchemaVersion,
		Channel:       ChannelName,
		Version:       "0.5.0",
		Assets: map[string]Asset{
			platformKey(): {Name: "asset", SHA256: hashBytes(asset), Size: int64(len(asset))},
		},
	}, key)
	// The asset bytes and their digests stay valid; only the signed document is
	// altered. A caller that skips verification would happily install this.
	tampered := strings.Replace(string(body), `"0.5.0"`, `"0.5.1"`, 1)
	if tampered == string(body) {
		t.Fatal("tamper fixture did not change the manifest")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/go/manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(tampered))
	})
	mux.HandleFunc("/go/asset", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(asset)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if _, err := Configure(context.Background(), root, srv.URL+"/go/manifest.json", "opt/idleleo/bin/idleleo"); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(root, "opt/idleleo/bin/idleleo")
	if err := os.MkdirAll(filepath.Dir(install), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(install, []byte("old binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	rep, err := Apply(context.Background(), root, "", nil)
	if err == nil {
		t.Fatal("apply must reject a manifest whose signature no longer covers its content")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("refusal must name the signature, got: %v", err)
	}
	if rep.NewVersion != "" {
		t.Fatalf("tampered manifest must not reach the install stage: %+v", rep)
	}
	b, readErr := os.ReadFile(install)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(b) != "old binary\n" {
		t.Fatalf("tampered manifest changed the installed binary: %q", string(b))
	}
}

func TestApplyCanceledDownloadLeavesPreviousBinary(t *testing.T) {
	pinLinuxPlatform(t)
	root := t.TempDir()
	asset := fakeELF(runtime.GOARCH)
	key := installTestReleaseKey(t)
	body := signedManifestBytes(t, Manifest{
		SchemaVersion: SchemaVersion,
		Channel:       ChannelName,
		Version:       "0.5.0",
		Assets: map[string]Asset{
			platformKey(): {Name: "idleleo", SHA256: hashBytes(asset), Size: int64(len(asset))},
		},
	}, key)
	mux := http.NewServeMux()
	mux.HandleFunc("/go/manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/go/asset", func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if _, err := Configure(context.Background(), root, srv.URL+"/go/manifest.json", "opt/idleleo/bin/idleleo"); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(root, "opt/idleleo/bin/idleleo")
	if err := os.MkdirAll(filepath.Dir(install), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(install, []byte("old binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Apply(ctx, root, "", nil); err == nil {
		t.Fatal("apply must fail when the download is interrupted")
	}
	b, err := os.ReadFile(install)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old binary\n" {
		t.Fatalf("interrupted download changed the installed binary: %q", string(b))
	}
}
