package deploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writeOwnedPair creates a realistic project pair plus the identity-bound
// ownership marker the manager writes after a successful issuance.
func writeOwnedPair(t *testing.T, dir, certName, keyName string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM := selfSignedPair(t, notAfter)
	certPath = filepath.Join(dir, certName)
	keyPath = filepath.Join(dir, keyName)
	writeGuardTestFile(t, certPath, certPEM)
	writeGuardTestFile(t, keyPath, keyPEM)
	writeManagedMarkerHashes(t, dir, certPath, keyPath)
	return certPath, keyPath
}

func selfSignedPair(t *testing.T, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "owned.example.com"},
		DNSNames:     []string{"owned.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func writeManagedMarkerHashes(t *testing.T, dir string, files ...string) {
	t.Helper()
	body := "managed-by=idleleo\n"
	for _, f := range files {
		body += "sha256=" + fileDigest(t, f) + "\n"
	}
	writeGuardTestFile(t, filepath.Join(dir, ".managed-by-idleleo"), []byte(body))
}

// D01: a `${var}` certificate path used to fall outside the directive regex, so
// the scanner saw no reference at all and deleted the live pair.
func TestClearCertificatesFailsClosedOnBraceVariablePath(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeOwnedPair(t, certDir, "xray.crt", "xray.key", time.Now().Add(90*24*time.Hour))
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/conf/nginx/00-site.conf"),
		[]byte("server {\n    listen 9443 ssl;\n    ssl_certificate /etc/idleleo/cert/${cert_name}.crt;\n    ssl_certificate_key /etc/idleleo/cert/${cert_name}.key;\n}\n"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("a ${var} certificate path must fail closed, removed %v", rep.Removed)
	}
	if _, err := os.Stat(filepath.Join(certDir, "xray.crt")); err != nil {
		t.Fatalf("the certificate must survive: %v", err)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("the operator must be told that the path could not be resolved")
	}
}

// A file name, the managed directory, or an old marker without a content hash
// is not ownership proof. Only the identity-bound marker is.
func TestClearCertificatesRequiresIdentityBoundOwnership(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), []byte("projectish cert"))
	writeGuardTestFile(t, filepath.Join(certDir, "xray.key"), []byte("projectish key"))
	// The legacy marker recorded only a label, never the file identity.
	writeGuardTestFile(t, filepath.Join(certDir, ".managed-by-idleleo"), []byte("managed-by=idleleo\n"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("unidentified files must be preserved, removed %v", rep.Removed)
	}
	for _, name := range []string{"xray.crt", "xray.key"} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			t.Fatalf("%s must be preserved: %v", name, err)
		}
	}
}

func TestClearCertificatesRemovesIdentityBoundUnusedPair(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeOwnedPair(t, certDir, "xray.crt", "xray.key", time.Now().Add(90*24*time.Hour))
	writeGuardTestFile(t, filepath.Join(certDir, "third-party.pem"), []byte("third party"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 2 {
		t.Fatalf("the owned unused pair must be removed, got %v", rep.Removed)
	}
	if _, err := os.Stat(filepath.Join(certDir, "third-party.pem")); err != nil {
		t.Fatalf("the unowned file must survive: %v", err)
	}
}

// D02: a user-managed certificate sharing the acme.sh domain must never turn
// ~/.acme.sh/<domain>_ecc into project property.
func TestClearCertificatesKeepsThirdPartyACMESameDomain(t *testing.T) {
	root := sandbox(t)
	home := t.TempDir()
	certDir := filepath.Join(root, "etc/idleleo/cert")
	certPEM, keyPEM := selfSignedPair(t, time.Now().Add(90*24*time.Hour))
	writeGuardTestFile(t, filepath.Join(certDir, "xray.crt"), certPEM)
	writeGuardTestFile(t, filepath.Join(certDir, "xray.key"), keyPEM)
	writeGuardTestFile(t, filepath.Join(certDir, ".user-managed"), []byte("managed-by=user\n"))
	acmeDir := filepath.Join(home, ".acme.sh", "owned.example.com_ecc")
	writeGuardTestFile(t, filepath.Join(acmeDir, "owned.example.com.cer"), certPEM)
	writeGuardTestFile(t, filepath.Join(acmeDir, "owned.example.com.key"), keyPEM)

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("nothing may be removed here, got %v", rep.Removed)
	}
	if _, err := os.Stat(acmeDir); err != nil {
		t.Fatalf("third-party ACME state must be preserved: %v", err)
	}
	assertPlanned(t, rep, acmeDir, certActionKeep, false)
}

// D02: even a project-owned certificate must not authorize deleting acme.sh
// state that cannot be matched to the same certificate identity.
func TestClearCertificatesKeepsUnmatchedACMEState(t *testing.T) {
	root := sandbox(t)
	home := t.TempDir()
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeOwnedPair(t, certDir, "xray.crt", "xray.key", time.Now().Add(90*24*time.Hour))
	otherPEM, otherKey := selfSignedPair(t, time.Now().Add(90*24*time.Hour))
	acmeDir := filepath.Join(home, ".acme.sh", "owned.example.com_ecc")
	writeGuardTestFile(t, filepath.Join(acmeDir, "owned.example.com.cer"), otherPEM)
	writeGuardTestFile(t, filepath.Join(acmeDir, "owned.example.com.key"), otherKey)

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(acmeDir); err != nil {
		t.Fatalf("ACME state without an identity match must be preserved: %v", err)
	}
	assertPlanned(t, rep, acmeDir, certActionKeep, false)
}

// A directory marker must not claim every file placed under it.
func TestClearCertificatesDirectoryMarkerIsNotBlanketOwnership(t *testing.T) {
	root := sandbox(t)
	archive := filepath.Join(root, "etc/idleleo/cert/archive")
	writeGuardTestFile(t, filepath.Join(archive, "xray.crt"), []byte("someone else cert"))
	writeGuardTestFile(t, filepath.Join(archive, "third-party.pem"), []byte("third party"))
	writeGuardTestFile(t, filepath.Join(archive, ".managed-by-idleleo"), []byte("managed-by=idleleo\n"))

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("a directory marker alone must not delete anything: %v", rep.Removed)
	}
	if _, err := os.Stat(filepath.Join(archive, "third-party.pem")); err != nil {
		t.Fatalf("the canary must survive: %v", err)
	}
}

// Deep include chains past the recursion limit must fail closed instead of
// silently treating the unseen tail as unreferenced.
func TestClearCertificatesFailsClosedOnDeepIncludeChain(t *testing.T) {
	root := sandbox(t)
	certDir := filepath.Join(root, "etc/idleleo/cert")
	writeOwnedPair(t, certDir, "xray.crt", "xray.key", time.Now().Add(90*24*time.Hour))
	// The chain lives outside every directory the shallow walk visits, so only
	// the include recursion can reach the certificate reference at the tail.
	writeGuardTestFile(t, filepath.Join(root, "usr/local/nginx/conf/nginx.conf"),
		[]byte("http {\n    include /opt/chain/level0.conf;\n}\n"))
	for i := 0; i < 20; i++ {
		body := "include /opt/chain/level" + strconv.Itoa(i+1) + ".conf;\n"
		if i == 19 {
			body = "ssl_certificate /etc/idleleo/cert/xray.crt;\n"
		}
		writeGuardTestFile(t, filepath.Join(root, "opt/chain/level"+strconv.Itoa(i)+".conf"), []byte(body))
	}

	rep, err := ClearCertificates(context.Background(), ClearCertsSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 0 {
		t.Fatalf("an unbounded include chain must fail closed, removed %v", rep.Removed)
	}
	if _, err := os.Stat(filepath.Join(certDir, "xray.crt")); err != nil {
		t.Fatalf("the certificate must survive: %v", err)
	}
	found := false
	for _, warning := range rep.Warnings {
		if strings.Contains(warning, "depth") || strings.Contains(warning, "nest") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the operator must be told the include chain was too deep: %v", rep.Warnings)
	}
}
