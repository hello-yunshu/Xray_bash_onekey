package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func speedtestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("z", 4096)))
	}))
}

func TestSpeedtestJSONSchema(t *testing.T) {
	server := speedtestServer(t)
	defer server.Close()

	code, out, errOut := run(t, "speedtest", "--json", "--server", server.URL, "--bytes", "4096", "--samples", "2")
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, out)
	}
	for _, key := range []string{"server", "downMbps", "bytes", "durationMs", "samplesMbps", "startedAt"} {
		if _, ok := payload[key]; !ok {
			t.Fatalf("missing %q in %v", key, payload)
		}
	}
	if got := payload["server"]; got != server.URL {
		t.Fatalf("server = %v, want %v", got, server.URL)
	}
	samples, ok := payload["samplesMbps"].([]any)
	if !ok || len(samples) != 2 {
		t.Fatalf("samplesMbps = %v, want 2 entries", payload["samplesMbps"])
	}
}

func TestSpeedtestFailsClosed(t *testing.T) {
	code, _, errOut := run(t, "speedtest", "--server", "ftp://example.com")
	if code == 0 {
		t.Fatalf("exit = 0 for a non-HTTP server (stderr = %s)", errOut)
	}
	code, _, errOut = run(t, "speedtest", "--bytes", "not-a-number")
	if code == 0 {
		t.Fatalf("exit = 0 for a malformed --bytes (stderr = %s)", errOut)
	}
}

func TestSpeedtestReportsUnreachableServer(t *testing.T) {
	server := speedtestServer(t)
	url := server.URL
	server.Close()

	code, _, errOut := run(t, "speedtest", "--server", url, "--samples", "1", "--timeout", "200ms")
	if code == 0 {
		t.Fatalf("exit = 0 for an unreachable server (stderr = %s)", errOut)
	}
}
