package schedule

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
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
	if len(rep.DegradedJobs) != 1 {
		t.Fatalf("degraded=%v", rep.DegradedJobs)
	}
}

func writeCert(t *testing.T, root, rel string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, rel, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
}

func testCertConfig() Config {
	cfg := Config{
		CertDomain: "example.com", CertWebroot: "etc/idleleo/conf",
		CertFile: CertDirRel + "/xray.crt", CertKeyFile: CertDirRel + "/xray.key",
		ACMEDirectory: ACMEStagingDirectory,
	}
	cfg.applyDefaults()
	return cfg
}

func restoreCertHooks(t *testing.T) {
	t.Helper()
	renew, reload := renewCertificate, reloadServices
	t.Cleanup(func() { renewCertificate, reloadServices = renew, reload })
}

// TestCertRenewJobRenewsInsideWindow is the red test for P0-2: deleting the
// renewCertificate call leaves the fingerprint unchanged and fails this test.
func TestCertRenewJobRenewsInsideWindow(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(20*24*time.Hour))
	cfg := testCertConfig()
	restoreCertHooks(t)

	calls, reloads := 0, 0
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		calls++
		if spec.Domain != "example.com" {
			t.Errorf("domain=%q", spec.Domain)
		}
		if spec.DirectoryURL != ACMEStagingDirectory {
			t.Errorf("directory=%q", spec.DirectoryURL)
		}
		if spec.RenewBefore != CertRenewWindow {
			t.Errorf("renewBefore=%s", spec.RenewBefore)
		}
		writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(60*24*time.Hour))
		return acme.Result{Issued: true, Domain: spec.Domain}, nil
	}
	reloadServices = func(ctx context.Context, gotRoot string) (string, error) {
		reloads++
		if gotRoot != root {
			t.Errorf("root=%q", gotRoot)
		}
		return "xray restarted", nil
	}

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "ok" {
		t.Fatalf("result=%+v", res)
	}
	if calls != 1 || reloads != 1 {
		t.Fatalf("renew calls=%d reloads=%d", calls, reloads)
	}
	if !strings.Contains(res.Detail, "renewed") {
		t.Fatalf("detail=%q", res.Detail)
	}
	obs, err := scanCert(filepath.Join(root, CertDirRel))
	if err != nil {
		t.Fatal(err)
	}
	state := loadCertState(root)
	if state.Fingerprint == "" || state.Fingerprint != obs.Fingerprint {
		t.Fatalf("state fingerprint=%q cert fingerprint=%q", state.Fingerprint, obs.Fingerprint)
	}
	if time.Until(obs.NotAfter) < 40*24*time.Hour {
		t.Fatalf("certificate was not replaced: notAfter=%s", obs.NotAfter)
	}
}

func TestCertRenewJobFailureWritesAlertAndPostsWebhook(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(20*24*time.Hour))
	cfg := testCertConfig()
	restoreCertHooks(t)

	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			t.Errorf("content-type=%q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	cfg.AlertWebhook = ts.URL
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		return acme.Result{}, errors.New("acme boom")
	}

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "failed" || !strings.Contains(res.Detail, "acme boom") {
		t.Fatalf("result=%+v", res)
	}
	b, err := os.ReadFile(filepath.Join(root, AlertsDirRel, "cert-renew.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a Alert
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	if a.Job != "cert-renew" || a.Result != "failed" || a.Webhook != "posted" {
		t.Fatalf("alert=%+v", a)
	}
	if hits != 1 {
		t.Fatalf("webhook hits=%d", hits)
	}
}

func TestCertRenewJobStaysFailedWhenAlertCannotBePersisted(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(20*24*time.Hour))
	cfg := testCertConfig()
	restoreCertHooks(t)

	// A regular file where the alerts directory should be makes persistence
	// fail even when the tests run as root (chmod alone would be bypassed).
	write(t, root, AlertsDirRel, "not a directory", 0o600)
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		return acme.Result{}, errors.New("acme boom")
	}

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "failed" {
		t.Fatalf("alert persistence failure changed the job result: %+v", res)
	}
	if !strings.Contains(res.Detail, "acme boom") {
		t.Fatalf("detail=%q", res.Detail)
	}
	// A lost alert used to be invisible outside the journal; the job detail
	// must now carry the persistence failure.
	if !strings.Contains(res.Detail, "alert not persisted") {
		t.Fatalf("persistence failure was swallowed: detail=%q", res.Detail)
	}
}

func TestCertRenewJobSuccessClearsAlert(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(20*24*time.Hour))
	write(t, root, AlertsDirRel+"/cert-renew.json",
		`{"schemaVersion":1,"job":"cert-renew","result":"failed","detail":"old","at":"2026-11-01T00:00:00Z"}`, 0o640)
	cfg := testCertConfig()
	restoreCertHooks(t)
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(60*24*time.Hour))
		return acme.Result{Issued: true}, nil
	}
	reloadServices = func(ctx context.Context, root string) (string, error) { return "ok", nil }

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "ok" {
		t.Fatalf("result=%+v", res)
	}
	if _, err := os.Stat(filepath.Join(root, AlertsDirRel, "cert-renew.json")); !os.IsNotExist(err) {
		t.Fatalf("alert was not cleared: %v", err)
	}
}

func TestCertRenewJobRequiresDomain(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(20*24*time.Hour))
	cfg := testCertConfig()
	cfg.CertDomain = ""
	restoreCertHooks(t)
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		t.Fatal("renewal must not run without certDomain")
		return acme.Result{}, nil
	}

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "failed" || !strings.Contains(res.Detail, "certDomain") {
		t.Fatalf("result=%+v", res)
	}
	if _, err := os.Stat(filepath.Join(root, AlertsDirRel, "cert-renew.json")); err != nil {
		t.Fatalf("alert missing: %v", err)
	}
}

func TestDegradedJobsExcludesCertRenew(t *testing.T) {
	for _, d := range DegradedJobs {
		if strings.HasPrefix(d, "cert-renew") {
			t.Fatalf("cert-renew is still degraded: %s", d)
		}
	}
}

func TestInstallWritesOnFailureAndAlertUnit(t *testing.T) {
	root := sandbox(t)
	rep, err := Install(context.Background(), InstallOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(root, UnitRel))
	if err != nil {
		t.Fatal(err)
	}
	// OnFailure is a [Unit] directive; in [Service] systemd logs
	// "Unknown key name 'OnFailure'" and ignores it, so a failed run would
	// never start the alert unit.
	unitSection, _, found := strings.Cut(string(service), "[Service]")
	if !found {
		t.Fatalf("service has no [Service] section: %s", service)
	}
	if !strings.Contains(unitSection, "OnFailure=idleleo-alert.service") {
		t.Fatalf("OnFailure is not in the [Unit] section: %s", service)
	}
	alertUnit, err := os.ReadFile(rep.AlertServicePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(alertUnit), "schedule alert") {
		t.Fatalf("alert unit=%s", alertUnit)
	}
}

func TestStatusReturnsAlertsWhenConfigIsBroken(t *testing.T) {
	root := sandbox(t)
	write(t, root, ConfigRel, "not-json", 0o600)
	write(t, root, AlertsDirRel+"/cert-renew.json",
		`{"schemaVersion":1,"job":"cert-renew","result":"failed","detail":"renewal failed","at":"2026-11-12T00:00:00Z"}`, 0o640)
	rep, err := Status(context.Background(), root)
	if err == nil {
		t.Fatal("broken config was accepted")
	}
	if len(rep.Alerts) != 1 || rep.Alerts[0].Job != "cert-renew" {
		t.Fatalf("alerts=%+v", rep.Alerts)
	}
	lines := rep.SummaryLines()
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "alert=cert-renew") {
		t.Fatalf("summary=%v", lines)
	}
}

// TestWriteAlertReturnsPersistenceError is the red test for the swallowed
// error: with persistence forced to fail, WriteAlert must report it instead of
// returning a healthy alert and leaving the caller to guess.
func TestWriteAlertReturnsPersistenceError(t *testing.T) {
	root := sandbox(t)
	// A regular file where the alerts directory belongs makes MkdirAll fail
	// even when the tests run as root (chmod alone would be bypassed).
	write(t, root, AlertsDirRel, "not a directory", 0o600)

	a, err := WriteAlert(context.Background(), root, Config{}, "cert-renew", "failed", "boom", "2026-11-12T00:00:00Z")
	if err == nil {
		t.Fatal("WriteAlert swallowed the persistence failure")
	}
	if !strings.Contains(err.Error(), "persist alert cert-renew") {
		t.Fatalf("err=%q", err)
	}
	// The in-memory alert is still returned so callers can log or forward it.
	if a.Job != "cert-renew" || a.Result != "failed" || a.Detail != "boom" {
		t.Fatalf("alert=%+v", a)
	}
}

// TestAlertsDistinguishesMissingFromUnreadable covers the three states that
// `idleleo status` has to tell apart: no alerts yet, alerts present, and a
// store that failed to read. Dropping the error return makes the third case
// look identical to the first.
func TestAlertsDistinguishesMissingFromUnreadable(t *testing.T) {
	if got, err := Alerts(sandbox(t)); err != nil || len(got) != 0 {
		t.Fatalf("missing directory must mean no alerts: alerts=%+v err=%v", got, err)
	}

	root := sandbox(t)
	write(t, root, AlertsDirRel+"/cert-renew.json",
		`{"schemaVersion":1,"job":"cert-renew","result":"failed","detail":"x","at":"2026-11-12T00:00:00Z"}`, 0o640)
	got, err := Alerts(root)
	if err != nil || len(got) != 1 || got[0].Job != "cert-renew" {
		t.Fatalf("healthy store: alerts=%+v err=%v", got, err)
	}

	root = sandbox(t)
	write(t, root, AlertsDirRel+"/cert-renew.json",
		`{"schemaVersion":1,"job":"cert-renew","result":"failed","detail":"x","at":"2026-11-12T00:00:00Z"}`, 0o640)
	write(t, root, AlertsDirRel+"/stats-collect.json", "{not json", 0o640)
	got, err = Alerts(root)
	if err == nil {
		t.Fatal("corrupt alert file was silently skipped")
	}
	if !strings.Contains(err.Error(), "parse alert stats-collect.json") {
		t.Fatalf("err=%q", err)
	}
	if len(got) != 1 || got[0].Job != "cert-renew" {
		t.Fatalf("readable alerts must survive: %+v", got)
	}

	root = sandbox(t)
	write(t, root, AlertsDirRel, "not a directory", 0o600)
	if got, err := Alerts(root); err == nil || !strings.Contains(err.Error(), "read alerts directory") {
		t.Fatalf("unreadable directory: alerts=%+v err=%v", got, err)
	}
}

// TestStatusMarksUnreadableAlertStore keeps the healthy status output intact
// while making a broken alert store visible to scripts.
func TestStatusMarksUnreadableAlertStore(t *testing.T) {
	healthy := sandbox(t)
	rep, err := Status(context.Background(), healthy)
	if err != nil {
		t.Fatal(err)
	}
	if rep.AlertsUnreadable || rep.AlertsError != "" {
		t.Fatalf("healthy store flagged: %+v", rep)
	}
	for _, line := range rep.SummaryLines() {
		if strings.HasPrefix(line, "alerts=unreadable") {
			t.Fatalf("healthy summary says unreadable: %v", rep.SummaryLines())
		}
	}

	broken := sandbox(t)
	write(t, broken, AlertsDirRel, "not a directory", 0o600)
	rep, err = Status(context.Background(), broken)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.AlertsUnreadable || rep.AlertsError == "" {
		t.Fatalf("unreadable store not reported: %+v", rep)
	}
	lines := rep.SummaryLines()
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "alerts=unreadable ") {
		t.Fatalf("summary=%v", lines)
	}
}
