package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var fixture = map[string][]byte{
	"geoip.dat":   []byte("geoip-fixture-bytes"),
	"geosite.dat": []byte("geosite-fixture-bytes"),
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func origin(t *testing.T, broken map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasSuffix(name, ".sha256sum") {
			asset := strings.TrimSuffix(name, ".sha256sum")
			data, ok := fixture[asset]
			if !ok {
				http.NotFound(w, r)
				return
			}
			// The checksum stays honest even when the payload is broken: the
			// test is about detecting tampering, not about a missing file.
			fmt.Fprintf(w, "%s  %s\n", checksum(data), asset)
			return
		}
		data, ok := fixture[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if broken[name] {
			w.Write([]byte("tampered"))
			return
		}
		w.Write(data)
	}))
}

func TestFetchVerifiesEveryAsset(t *testing.T) {
	srv := origin(t, nil)
	defer srv.Close()
	got, err := Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Assets {
		if string(got[name]) != string(fixture[name]) {
			t.Fatalf("%s payload = %q", name, got[name])
		}
	}
}

// A checksum mismatch must abort the whole fetch, matching geo_update.sh:
// a partially updated pair is worse than keeping the old files.
func TestFetchRejectsTamperedAsset(t *testing.T) {
	srv := origin(t, map[string]bool{"geoip.dat": true})
	defer srv.Close()
	got, err := Fetch(context.Background(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected mismatch, got %v (payloads=%d)", err, len(got))
	}
	if got != nil {
		t.Fatalf("nothing may be returned on failure, got %d assets", len(got))
	}
}

func TestFetchRejectsMissingChecksum(t *testing.T) {
	// The checksum file exists but has no line for geosite.dat: fetch must not
	// fall back to "no checksum, just write the bytes".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "geoip.dat.sha256sum" {
			fmt.Fprintf(w, "%s  geoip.dat\n", checksum(fixture["geoip.dat"]))
			return
		}
		if name == "geosite.dat.sha256sum" {
			// Present but without the geosite.dat line.
			fmt.Fprintf(w, "%s  geoip.dat\n", checksum(fixture["geoip.dat"]))
			return
		}
		if data, ok := fixture[name]; ok {
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.URL); err == nil ||
		!strings.Contains(err.Error(), "no entry for geosite.dat") {
		t.Fatalf("expected missing checksum error, got %v", err)
	}
}
