package schedule

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeScheduleCert(t *testing.T, path, domain string, notAfter time.Time, keyMode os.FileMode) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".key"
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), keyMode); err != nil {
		t.Fatal(err)
	}
}

func TestSetCertTargetRewritesTheRenewalTarget(t *testing.T) {
	root := t.TempDir()
	jobsPath := filepath.Join(root, ConfigRel)
	if err := os.MkdirAll(filepath.Dir(jobsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"schemaVersion":1,"intervalSeconds":900,"jobs":["cert-renew"],` +
		`"certDomain":"old.example.com","certFile":"etc/idleleo/cert/xray.crt",` +
		`"certKeyFile":"etc/idleleo/cert/xray.key"}` + "\n"
	if err := os.WriteFile(jobsPath, []byte(seed), 0o640); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(root, "etc/idleleo/cert/new.example.com.crt")
	key := filepath.Join(root, "etc/idleleo/cert/new.example.com.key")
	updated, warnings, err := SetCertTarget(root, "new.example.com", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if !updated || len(warnings) != 0 {
		t.Fatalf("updated=%v warnings=%v", updated, warnings)
	}
	body, err := os.ReadFile(jobsPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["certDomain"] != "new.example.com" {
		t.Fatalf("certDomain = %v", raw["certDomain"])
	}
	if raw["certFile"] != "etc/idleleo/cert/new.example.com.crt" {
		t.Fatalf("certFile = %v", raw["certFile"])
	}
	if raw["certKeyFile"] != "etc/idleleo/cert/new.example.com.key" {
		t.Fatalf("certKeyFile = %v", raw["certKeyFile"])
	}
	info, err := os.Stat(jobsPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("jobs.json mode changed to %04o", info.Mode().Perm())
	}
}

func TestSetCertTargetReportsPathsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	jobsPath := filepath.Join(root, ConfigRel)
	if err := os.MkdirAll(filepath.Dir(jobsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jobsPath, []byte(`{"schemaVersion":1,"certFile":"etc/idleleo/cert/xray.crt"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	updated, warnings, err := SetCertTarget(root, "example.com", "/var/lib/other/site.crt", "")
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("the domain update should still be written")
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "outside the install root") {
		t.Fatalf("warnings = %v", warnings)
	}
	body, _ := os.ReadFile(jobsPath)
	if !strings.Contains(string(body), `"certFile": "etc/idleleo/cert/xray.crt"`) {
		t.Fatalf("an unexpressible path must not be written: %s", body)
	}
}

func TestSetCertTargetWithoutScheduleIsANoOp(t *testing.T) {
	updated, warnings, err := SetCertTarget(t.TempDir(), "example.com", "/etc/idleleo/cert/xray.crt", "")
	if err != nil || updated || len(warnings) != 0 {
		t.Fatalf("updated=%v warnings=%v err=%v", updated, warnings, err)
	}
}

func TestObserveCertPrefersTheConfiguredFile(t *testing.T) {
	root := t.TempDir()
	custom := filepath.Join(root, "etc/idleleo/cert2/site.crt")
	writeScheduleCert(t, custom, "new.example.com", time.Now().Add(200*24*time.Hour), 0o600)
	legacy := filepath.Join(root, CertDirRel, "xray.crt")
	writeScheduleCert(t, legacy, "old.example.com", time.Now().Add(5*24*time.Hour), 0o600)

	cfg := Config{CertFile: "etc/idleleo/cert2/site.crt", CertKeyFile: "etc/idleleo/cert2/site.key"}
	obs, err := observeCert(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Path != custom {
		t.Fatalf("observed %s, want the configured %s", obs.Path, custom)
	}
	if obs.Name != "site.crt" {
		t.Fatalf("name = %s", obs.Name)
	}
}

func TestObserveCertFallsBackToTheLegacyDirectory(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, CertDirRel, "xray.crt")
	writeScheduleCert(t, legacy, "example.com", time.Now().Add(60*24*time.Hour), 0o644)
	cfg := Config{CertFile: "etc/idleleo/cert/missing.crt", CertKeyFile: "etc/idleleo/cert/missing.key"}
	obs, err := observeCert(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Path != legacy {
		t.Fatalf("fallback observed %s, want %s", obs.Path, legacy)
	}
}

func TestObserveCertChecksTheConfiguredKeyMode(t *testing.T) {
	root := t.TempDir()
	cert := filepath.Join(root, "custom/site.crt")
	writeScheduleCert(t, cert, "example.com", time.Now().Add(200*24*time.Hour), 0o644)
	cfg := Config{CertFile: "custom/site.crt", CertKeyFile: "custom/site.key"}
	obs, err := observeCert(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.InsecureKey) != 1 || !strings.Contains(obs.InsecureKey[0], "world-readable") {
		t.Fatalf("insecure keys = %v", obs.InsecureKey)
	}
}
