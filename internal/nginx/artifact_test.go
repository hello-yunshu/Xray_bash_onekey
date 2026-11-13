package nginx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeELF(arch string) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1})
	machine := uint16(183)
	if arch == "x86" {
		machine = 62
	}
	b[18] = byte(machine)
	b[19] = byte(machine >> 8)
	copy(b[20:], []byte("fake-nginx-binary"))
	return b
}

func tarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Typeflag: e.typ}
		if e.link != "" {
			hdr.Linkname = e.link
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg && len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	name string
	body []byte
	mode int64
	typ  byte
	link string
}

func manifestFor(t *testing.T, arch string, artifact []byte, bin []byte) Manifest {
	t.Helper()
	sum := sha256.Sum256(artifact)
	binSum := sha256.Sum256(bin)
	return Manifest{
		SchemaVersion: 1,
		Tag:           "v2026.10.15.7679",
		Versions:      Versions{NginxBuild: "2026.10.15.7679", Nginx: "1.30.6"},
		Assets: []Asset{{
			Arch:         arch,
			Filename:     "xray-nginx-custom-" + arch + ".tar.gz",
			SHA256:       hex.EncodeToString(sum[:]),
			SizeBytes:    int64(len(artifact)),
			BinarySHA256: hex.EncodeToString(binSum[:]),
			LinkMode:     "glibc",
		}},
	}
}

func TestParseManifestRejectsInvalidRecords(t *testing.T) {
	base := Manifest{
		SchemaVersion: 1,
		Tag:           "v2026.10.15.7679",
		Versions:      Versions{NginxBuild: "2026.10.15.7679"},
		Assets:        []Asset{{Arch: "arm"}},
	}
	raw, _ := json.Marshal(base)
	if _, err := ParseManifest(raw); err != nil {
		t.Fatalf("baseline manifest should parse: %v", err)
	}
	cases := map[string]func(*Manifest){
		"schema": func(m *Manifest) { m.SchemaVersion = 2 },
		"tag":    func(m *Manifest) { m.Tag = "v2026.10.15.0" },
		"build":  func(m *Manifest) { m.Versions.NginxBuild = "../escape" },
		"dup":    func(m *Manifest) { m.Assets = append(m.Assets, Asset{Arch: "arm"}) },
		"noarch": func(m *Manifest) { m.Assets[0].Arch = "" },
	}
	for name, mutate := range cases {
		m := base
		m.Assets = append([]Asset(nil), base.Assets...)
		mutate(&m)
		raw, _ := json.Marshal(m)
		if _, err := ParseManifest(raw); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestResolveDownloadsAndVerifies(t *testing.T) {
	bin := fakeELF("arm")
	artifact := tarGz(t, []tarEntry{
		{name: "nginx/", typ: tar.TypeDir, mode: 0o755},
		{name: "nginx/sbin/", typ: tar.TypeDir, mode: 0o755},
		{name: "nginx/sbin/nginx", typ: tar.TypeReg, mode: 0o755, body: bin},
		{name: "nginx/conf/nginx.conf", typ: tar.TypeReg, mode: 0o644, body: []byte("events {}\n")},
	})
	m := manifestFor(t, "arm", artifact, bin)
	mRaw, _ := json.Marshal(m)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/versions.json":
			io.WriteString(w, `{"nginx_build_online_version":"2026.10.15.7679"}`)
		case r.URL.Path == "/releases/v2026.10.15.7679/release-manifest.json":
			w.Write(mRaw)
		case r.URL.Path == "/releases/v2026.10.15.7679/xray-nginx-custom-arm.tar.gz":
			w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	art, err := Resolve(context.Background(), Options{
		VersionsURLs:   []string{srv.URL + "/versions.json"},
		ReleaseBaseURL: srv.URL + "/releases",
		Arch:           "arm",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if art.Build != "2026.10.15.7679" || art.Version.Nginx != "1.30.6" {
		t.Fatalf("unexpected artifact: %+v", art)
	}
	dest := t.TempDir()
	if err := Extract(art.Data, dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "nginx/sbin/nginx"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bin) {
		t.Fatal("extracted binary differs")
	}
	if err := VerifyBinary(filepath.Join(dest, "nginx/sbin/nginx"), art.Asset.BinarySHA256, "arm"); err != nil {
		t.Fatalf("VerifyBinary: %v", err)
	}
}

func TestResolveRejectsBadDigest(t *testing.T) {
	bin := fakeELF("x86")
	artifact := tarGz(t, []tarEntry{{name: "nginx/sbin/nginx", typ: tar.TypeReg, mode: 0o755, body: bin}})
	m := manifestFor(t, "x86", artifact, bin)
	m.Assets[0].SHA256 = strings.Repeat("0", 64)
	mRaw, _ := json.Marshal(m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "versions.json"):
			io.WriteString(w, `{"nginx_build_online_version":"2026.10.15.7679"}`)
		case strings.HasSuffix(r.URL.Path, "release-manifest.json"):
			w.Write(mRaw)
		default:
			w.Write(artifact)
		}
	}))
	defer srv.Close()
	if _, err := Resolve(context.Background(), Options{
		VersionsURLs:   []string{srv.URL + "/versions.json"},
		ReleaseBaseURL: srv.URL,
		Arch:           "x86",
	}); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch, got %v", err)
	}
}

func TestExtractRejectsUnsafeEntries(t *testing.T) {
	cases := map[string][]tarEntry{
		"traversal":  {{name: "nginx/../../etc/passwd", typ: tar.TypeReg, mode: 0o644, body: []byte("x")}},
		"absolute":   {{name: "/etc/passwd", typ: tar.TypeReg, mode: 0o644, body: []byte("x")}},
		"outside":    {{name: "other/file", typ: tar.TypeReg, mode: 0o644, body: []byte("x")}},
		"symlink":    {{name: "nginx/link", typ: tar.TypeSymlink, link: "/etc/passwd"}},
		"hardlink":   {{name: "nginx/link", typ: tar.TypeLink, link: "nginx/sbin/nginx"}},
		"charDevice": {{name: "nginx/dev", typ: tar.TypeChar}},
	}
	for name, entries := range cases {
		err := Extract(tarGz(t, entries), t.TempDir())
		if err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestVerifyBinaryRejectsWrongArchAndDigest(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nginx")
	if err := os.WriteFile(p, fakeELF("arm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinary(p, "", "arm"); err != nil {
		t.Fatalf("arm binary should verify: %v", err)
	}
	if err := VerifyBinary(p, "", "x86"); err == nil {
		t.Fatal("arm binary must fail the x86 machine check")
	}
	if err := VerifyBinary(p, strings.Repeat("a", 64), "arm"); err == nil {
		t.Fatal("wrong digest must fail")
	}
	if err := os.WriteFile(p, []byte("not elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinary(p, "", "arm"); err == nil {
		t.Fatal("non-ELF must fail")
	}
}

func TestArchMapping(t *testing.T) {
	got, err := Arch()
	if err != nil {
		t.Fatal(err)
	}
	if got != "arm" && got != "x86" {
		t.Fatalf("unexpected arch %q", got)
	}
}
