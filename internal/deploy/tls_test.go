package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

// writeTestPair creates a self-signed pair for domain. The key is written 0600
// unless mode is passed explicitly.
func writeTestPair(t *testing.T, dir, domain string, notBefore, notAfter time.Time, mode os.FileMode) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, domain+".crt")
	keyPath := filepath.Join(dir, domain+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), mode); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestInspectTLSPairAcceptsMatchingPair(t *testing.T) {
	cert, key := writeTestPair(t, t.TempDir(), "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), 0o600)
	info, warnings, err := inspectTLSPair("example.com", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.LeafDER) == 0 || info.NotAfter.IsZero() {
		t.Fatalf("incomplete observation: %+v", info)
	}
	if len(info.SANs) != 1 || info.SANs[0] != "example.com" {
		t.Fatalf("SANs = %v", info.SANs)
	}
	if len(warnings) != 0 {
		t.Fatalf("a healthy pair must not warn: %v", warnings)
	}
}

func TestInspectTLSPairRejectsDomainMismatch(t *testing.T) {
	cert, key := writeTestPair(t, t.TempDir(), "old.example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), 0o600)
	_, _, err := inspectTLSPair("new.example.com", cert, key)
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("a domain edit without a covering certificate must be refused, got %v", err)
	}
}

func TestInspectTLSPairRejectsExpired(t *testing.T) {
	cert, key := writeTestPair(t, t.TempDir(), "example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), 0o600)
	_, _, err := inspectTLSPair("example.com", cert, key)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired pair must be refused, got %v", err)
	}
}

func TestInspectTLSPairRejectsKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	cert, _ := writeTestPair(t, dir, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), 0o600)
	_, otherKey := writeTestPair(t, dir, "other.example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), 0o600)
	_, _, err := inspectTLSPair("example.com", cert, otherKey)
	if err == nil || !strings.Contains(err.Error(), "not a valid certificate/key pair") {
		t.Fatalf("a mismatched key must be refused, got %v", err)
	}
}

func TestInspectTLSPairWarnsNearExpiryAndLooseKey(t *testing.T) {
	cert, key := writeTestPair(t, t.TempDir(), "example.com", time.Now().Add(-time.Hour), time.Now().Add(10*24*time.Hour), 0o644)
	_, warnings, err := inspectTLSPair("example.com", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "expires in") {
		t.Fatalf("a certificate inside the renewal window must warn: %v", warnings)
	}
	if !strings.Contains(joined, "world-readable") {
		t.Fatalf("a world-readable key must warn: %v", warnings)
	}
}

func stubTLSProbe(t *testing.T, fn func(ctx context.Context, addr, serverName string, wantDER []byte) (tlsProbeResult, error)) {
	t.Helper()
	old := probeTLSServer
	probeTLSServer = fn
	t.Cleanup(func() { probeTLSServer = old })
}

func TestProbeLocalTLSRetriesTheReloadRace(t *testing.T) {
	calls := 0
	stubTLSProbe(t, func(_ context.Context, addr, serverName string, _ []byte) (tlsProbeResult, error) {
		calls++
		if calls < 3 {
			return tlsProbeResult{}, certMismatchError{addr: addr}
		}
		return tlsProbeResult{ServerName: serverName, Version: "TLS 1.3"}, nil
	})
	report := EditReport{}
	if err := probeLocalTLS(context.Background(), &report, probeAddress(443), "example.com", []byte("leaf")); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("probe calls = %d, want 3 (the reload window must retry)", calls)
	}
	if report.TLSProbe != "ok" {
		t.Fatalf("TLSProbe = %q, want ok", report.TLSProbe)
	}
}

func TestProbeLocalTLSCancelStopsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stubTLSProbe(t, func(_ context.Context, addr, _ string, _ []byte) (tlsProbeResult, error) {
		cancel()
		return tlsProbeResult{}, certMismatchError{addr: addr}
	})
	report := EditReport{}
	if err := probeLocalTLS(ctx, &report, probeAddress(443), "example.com", []byte("leaf")); err == nil {
		t.Fatal("a cancelled probe must not report a pass")
	}
}

func TestProbeLocalTLSRecordsVerifiedHandshake(t *testing.T) {
	var gotAddr, gotSNI string
	stubTLSProbe(t, func(_ context.Context, addr, serverName string, wantDER []byte) (tlsProbeResult, error) {
		gotAddr, gotSNI = addr, serverName
		if len(wantDER) == 0 {
			t.Fatal("probe must pin the configured leaf")
		}
		return tlsProbeResult{ServerName: serverName, Version: "TLS 1.3", SystemTrusted: true}, nil
	})
	report := EditReport{}
	if err := probeLocalTLS(context.Background(), &report, probeAddress(8443), "example.com", []byte("leaf")); err != nil {
		t.Fatal(err)
	}
	if gotAddr != "127.0.0.1:8443" || gotSNI != "example.com" {
		t.Fatalf("probe target = %s SNI %s", gotAddr, gotSNI)
	}
	if report.TLSProbe != "ok" || report.TLSVersion != "TLS 1.3" || !report.TLSTrusted {
		t.Fatalf("report = %+v", report)
	}
}

func TestProbeLocalTLSUnreachableIsAWarningNotAPass(t *testing.T) {
	stubTLSProbe(t, func(context.Context, string, string, []byte) (tlsProbeResult, error) {
		return tlsProbeResult{}, errTLSServiceInactive
	})
	report := EditReport{}
	if err := probeLocalTLS(context.Background(), &report, probeAddress(443), "example.com", nil); err != nil {
		t.Fatalf("an inactive front must not fail the edit: %v", err)
	}
	if report.TLSProbe == "ok" || !strings.Contains(report.TLSProbe, "unreachable") {
		t.Fatalf("TLSProbe = %q", report.TLSProbe)
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "not verified") {
		t.Fatalf("warnings = %v", report.Warnings)
	}
}

func TestProbeLocalTLSHandshakeFailureFailsTheEdit(t *testing.T) {
	stubTLSProbe(t, func(context.Context, string, string, []byte) (tlsProbeResult, error) {
		return tlsProbeResult{}, context.DeadlineExceeded
	})
	report := EditReport{}
	if err := probeLocalTLS(context.Background(), &report, probeAddress(443), "example.com", nil); err == nil {
		t.Fatal("a served-certificate mismatch must fail the edit")
	}
}

func TestWriteEditBackupKeepsTheTLSPairAndSchedule(t *testing.T) {
	root, configPath, raw := editSandbox(t)
	dir := t.TempDir()
	cert, key := writeTestPair(t, dir, "example.com", time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), 0o600)
	scheduleFile := filepath.Join(root, "etc/idleleo/schedule/jobs.json")
	if err := os.MkdirAll(filepath.Dir(scheduleFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scheduleFile, []byte(`{"schemaVersion":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := writeEditBackup(paths, configPath, raw, "", xraycfg.EditResult{
		Changed: []string{"cert-file"}, Domain: "new.example.com",
		CertFile: "/etc/idleleo/cert/new.crt", KeyFile: "/etc/idleleo/cert/new.key",
	}, editBackupExtras{CertFile: cert, KeyFile: key, ScheduleFile: scheduleFile})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls-cert.pem", "tls-key.pem", "schedule-jobs.json", "manifest.json"} {
		info, err := os.Stat(filepath.Join(backup, name))
		if err != nil {
			t.Fatalf("%s missing from the backup: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", name, info.Mode().Perm())
		}
	}
	// The saved pair must be the pre-edit one, and the manifest must still name
	// the pair that replaced it so an operator can tell the two apart.
	saved, err := os.ReadFile(filepath.Join(backup, "tls-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != string(want) {
		t.Fatal("the backup must contain the certificate that was serving before the edit")
	}
	manifest, err := os.ReadFile(filepath.Join(backup, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), `"tlsCertSaved": true`) {
		t.Fatalf("manifest must record the saved pair: %s", manifest)
	}
	if !strings.Contains(string(manifest), `"tlsNewCertFile": "/etc/idleleo/cert/new.crt"`) {
		t.Fatalf("manifest must name the newly configured pair: %s", manifest)
	}
}
