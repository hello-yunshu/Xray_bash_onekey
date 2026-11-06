package schedule

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sandbox(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".idleleo-phase01-sandbox"), []byte("I_ACCEPT_DISPOSABLE_SANDBOX\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func write(t *testing.T, root, rel, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestRunRecordsDegradedAndSkippedJobs(t *testing.T) {
	root := sandbox(t)
	write(t, root, ConfigRel, `{"schemaVersion":1,"intervalSeconds":3600,"jobs":["auto-update","cert-renew","stats-collect"]}`, 0o600)
	rep, err := Run(context.Background(), RunOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 3 {
		t.Fatalf("results=%d", len(rep.Results))
	}
	if rep.Results[0].Result != "degraded" || !strings.Contains(rep.Results[0].Detail, "explicit") {
		t.Fatalf("auto-update=%+v", rep.Results[0])
	}
	if rep.Results[1].Result != "skipped" {
		t.Fatalf("cert-renew=%+v", rep.Results[1])
	}
	if rep.Results[2].Result != "skipped" {
		t.Fatalf("stats=%+v", rep.Results[2])
	}
	log, err := os.ReadFile(filepath.Join(root, LogRel))
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range []string{"auto-update", "cert-renew", "stats-collect"} {
		if !strings.Contains(string(log), "job="+job) {
			t.Fatalf("log missing %s: %s", job, log)
		}
	}
	var st State
	b, _ := os.ReadFile(filepath.Join(root, StateRel))
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Runs != 1 || st.Jobs["auto-update"].Result != "degraded" {
		t.Fatalf("state=%+v", st)
	}
}

func TestGeodataInterruptedDownloadKeepsOldAssets(t *testing.T) {
	root := sandbox(t)
	write(t, root, filepath.Join(GeodataDirRel, "geoip.dat"), "OLD-GEOIP", 0o644)
	write(t, root, filepath.Join(GeodataDirRel, "geosite.dat"), "OLD-GEOSITE", 0o644)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "geoip") {
			w.Header().Set("Content-Length", "999999")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PARTIAL"))
			return
		}
		_, _ = w.Write([]byte("GEOSITE-NEW"))
	}))
	defer ts.Close()
	write(t, root, ConfigRel, `{"schemaVersion":1,"intervalSeconds":3600,"jobs":["geodata-refresh"],"geodataUrl":"`+ts.URL+`","geodataDir":"`+GeodataDirRel+`"}`, 0o600)
	rep, err := Run(context.Background(), RunOptions{Root: root, Jobs: []string{"geodata-refresh"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Result != "failed" {
		t.Fatalf("result=%+v", rep.Results[0])
	}
	b, _ := os.ReadFile(filepath.Join(root, GeodataDirRel, "geoip.dat"))
	if string(b) != "OLD-GEOIP" {
		t.Fatalf("geoip changed: %q", b)
	}
	b, _ = os.ReadFile(filepath.Join(root, GeodataDirRel, "geosite.dat"))
	if string(b) != "OLD-GEOSITE" {
		t.Fatalf("geosite changed: %q", b)
	}
}

func TestGeodataDownloadReplacesBothAssetsAtomically(t *testing.T) {
	root := sandbox(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "geoip"):
			_, _ = w.Write([]byte("GEOIP-NEW"))
		case strings.Contains(r.URL.Path, "geosite"):
			_, _ = w.Write([]byte("GEOSITE-NEW"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	write(t, root, ConfigRel, `{"schemaVersion":1,"intervalSeconds":3600,"jobs":["geodata-refresh"],"geodataUrl":"`+ts.URL+`"}`, 0o600)
	rep, err := Run(context.Background(), RunOptions{Root: root, Jobs: []string{"geodata-refresh"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Results[0].Result != "ok" {
		t.Fatalf("result=%+v", rep.Results[0])
	}
	for name, want := range map[string]string{"geoip.dat": "GEOIP-NEW", "geosite.dat": "GEOSITE-NEW"} {
		b, _ := os.ReadFile(filepath.Join(root, GeodataDirRel, name))
		if string(b) != want {
			t.Fatalf("%s=%q", name, b)
		}
	}
}

func TestInstallAndRemoveUnitsInSandbox(t *testing.T) {
	root := sandbox(t)
	rep, err := Install(context.Background(), InstallOptions{Root: root, IntervalSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Systemd != "sandbox-not-queried" {
		t.Fatalf("systemd=%s", rep.Systemd)
	}
	if _, err := os.Stat(filepath.Join(root, TimerRel)); err != nil {
		t.Fatal(err)
	}
	timer, _ := os.ReadFile(filepath.Join(root, TimerRel))
	if !strings.Contains(string(timer), "OnActiveSec=30s") {
		t.Fatalf("timer=%s", timer)
	}
	actions, err := Remove(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("sandbox actions=%v", actions)
	}
	if _, err := os.Stat(filepath.Join(root, TimerRel)); !os.IsNotExist(err) {
		t.Fatalf("timer still exists")
	}
}

func TestRunRejectsUnknownJobAndMissingRoot(t *testing.T) {
	root := sandbox(t)
	if _, err := Run(context.Background(), RunOptions{Root: root, Jobs: []string{"nope"}}); err == nil {
		t.Fatal("unknown job accepted")
	}
	if _, err := Run(context.Background(), RunOptions{Root: filepath.Join(root, "missing")}); err == nil {
		t.Fatal("missing root accepted")
	}
}

func TestStatusDefaultsAndLastLog(t *testing.T) {
	root := sandbox(t)
	write(t, root, LogRel, "2026-11-06T00:00:00Z job=auto-update result=degraded detail=x\n", 0o640)
	rep, err := Status(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.IntervalSeconds != DefaultIntervalSeconds || rep.Installed {
		t.Fatalf("status=%+v", rep)
	}
	if !strings.Contains(rep.LastLogLine, "job=auto-update") {
		t.Fatalf("last=%q", rep.LastLogLine)
	}
	if len(rep.DegradedJobs) != 2 {
		t.Fatalf("degraded=%v", rep.DegradedJobs)
	}
}
