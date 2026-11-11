package speedtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func payloadServer(t *testing.T, size int, status int, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if r.URL.Path != "/__down" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		time.Sleep(delay)
		_, _ = w.Write([]byte(strings.Repeat("x", size)))
	}))
}

func TestRunMeasuresThroughput(t *testing.T) {
	server := payloadServer(t, 64*1024, http.StatusOK, 0)
	defer server.Close()

	result, err := Run(context.Background(), Options{Server: server.URL, Bytes: 64 * 1024, Samples: 3})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Samples) != 3 {
		t.Fatalf("samples = %d, want 3", len(result.Samples))
	}
	if result.Bytes != 3*64*1024 {
		t.Fatalf("bytes = %d, want %d", result.Bytes, 3*64*1024)
	}
	if result.DownMbps <= 0 {
		t.Fatalf("downMbps = %v, want > 0", result.DownMbps)
	}
	if result.Server != server.URL {
		t.Fatalf("server = %q, want %q", result.Server, server.URL)
	}
}

func TestRunFailsWhenEverySampleFails(t *testing.T) {
	server := payloadServer(t, 1024, http.StatusInternalServerError, 0)
	defer server.Close()

	if _, err := Run(context.Background(), Options{Server: server.URL, Samples: 2}); err == nil {
		t.Fatal("Run accepted an endpoint that always returns 500")
	}
}

func TestRunHonoursTimeout(t *testing.T) {
	server := payloadServer(t, 1024, http.StatusOK, 200*time.Millisecond)
	defer server.Close()

	start := time.Now()
	if _, err := Run(context.Background(), Options{
		Server:  server.URL,
		Samples: 1,
		Timeout: 20 * time.Millisecond,
	}); err == nil {
		t.Fatal("Run ignored the per-sample timeout")
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("timeout was not enforced quickly enough: %v", elapsed)
	}
}

func TestRunRejectsInvalidOptions(t *testing.T) {
	if _, err := Run(context.Background(), Options{Server: "ftp://example.com"}); err == nil {
		t.Fatal("Run accepted a non-HTTP server")
	}
	if _, err := Run(context.Background(), Options{Server: "not a url"}); err == nil {
		t.Fatal("Run accepted a malformed server URL")
	}
}

func TestRunKeepsPartialSamples(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("y", 2048)))
	}))
	defer server.Close()

	result, err := Run(context.Background(), Options{Server: server.URL, Bytes: 2048, Samples: 2})
	if err != nil {
		t.Fatalf("Run dropped a run with one healthy sample: %v", err)
	}
	if len(result.Samples) != 1 {
		t.Fatalf("samples = %d, want 1", len(result.Samples))
	}
}
