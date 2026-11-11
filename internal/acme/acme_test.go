package acme

import (
	"bytes"
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

	legoacme "github.com/go-acme/lego/v5/acme"
)

func testPair(t *testing.T, serial int64, commonName string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyDER
}

func TestValidTokenRejectsTraversal(t *testing.T) {
	for _, token := range []string{"", "../escape", "a/b", "a b", "a.b", "line\nbreak"} {
		if validToken(token) {
			t.Fatalf("token %q must be rejected", token)
		}
	}
	for _, token := range []string{"abcDEF123", "a-b_c", "A1"} {
		if !validToken(token) {
			t.Fatalf("token %q must be accepted", token)
		}
	}
}

func TestReplacePairInstallsModes(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	chain, keyDER := testPair(t, 1, "example.com")
	if err := replacePair(certPath, keyPath, chain, keyDER); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{certPath: 0o644, keyPath: 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	installed, err := os.ReadFile(certPath)
	if err != nil || !bytes.Equal(installed, chain) {
		t.Fatal("installed certificate does not match the issued chain")
	}
	if _, err := firstCertificate(chain); err != nil {
		t.Fatal(err)
	}
}

func TestReplacePairRejectsNonPEM(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	_, keyDER := testPair(t, 1, "example.com")
	if err := replacePair(certPath, keyPath, []byte("not a certificate"), keyDER); err == nil {
		t.Fatal("non-PEM chain must be rejected before writing")
	}
	if _, err := os.Stat(certPath); err == nil {
		t.Fatal("rejected chain left a certificate behind")
	}
}

func TestReplacePairRestoresOldCertificateWhenKeyCannotBeInstalled(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	oldChain, oldKey := testPair(t, 1, "old.example.com")
	if err := replacePair(certPath, keyPath, oldChain, oldKey); err != nil {
		t.Fatal(err)
	}

	// Turn the key destination into a directory: the certificate rename will
	// succeed but the key rename cannot, which must roll the certificate back.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	newChain, newKey := testPair(t, 2, "new.example.com")
	if err := replacePair(certPath, keyPath, newChain, newKey); err == nil {
		t.Fatal("replacePair must fail when the key destination is not writable")
	}
	got, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldChain) {
		t.Fatal("failed key install did not restore the previous certificate")
	}
}

func TestReloadFailureRestoresPreviousPair(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	oldChain, oldKeyDER := testPair(t, 1, "old.example.com")
	if err := replacePair(certPath, keyPath, oldChain, oldKeyDER); err != nil {
		t.Fatal(err)
	}
	oldCertOnDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	oldKeyOnDisk, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a successful install of a new pair, then a reload that fails.
	oldCert, oldKey, hadCert, hadKey := readPair(certPath, keyPath)
	newChain, newKeyDER := testPair(t, 2, "new.example.com")
	if err := replacePair(certPath, keyPath, newChain, newKeyDER); err != nil {
		t.Fatal(err)
	}
	cfg := Config{CertFile: certPath, KeyFile: keyPath, ReloadCommand: "exit 1"}
	err = reloadOrRestore(context.Background(), cfg, oldCert, oldKey, hadCert, hadKey)
	if err == nil || !strings.Contains(err.Error(), "previous pair restored") {
		t.Fatalf("reload failure = %v, want a previous-pair-restored error", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCert, oldCertOnDisk) {
		t.Fatal("reload failure did not restore the previous certificate")
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotKey, oldKeyOnDisk) {
		t.Fatal("reload failure did not restore the previous private key")
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored key mode = %v, %v; want 0600", info, err)
	}
}

func TestWebrootProviderRejectsUnsafeToken(t *testing.T) {
	root := t.TempDir()
	p := &webrootProvider{root: root}
	if err := p.Present(context.Background(), "example.com", "../escape", "key-auth"); err == nil {
		t.Fatal("unsafe token must be rejected before writing")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape")); err == nil {
		t.Fatal("unsafe token escaped the webroot")
	}
}

func TestWebrootProviderWritesAndRemovesToken(t *testing.T) {
	root := t.TempDir()
	p := &webrootProvider{root: root}
	const token = "abcDEF_123-"
	if err := p.Present(context.Background(), "example.com", token, "key-auth"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".well-known", "acme-challenge", token)
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "key-auth" {
		t.Fatalf("token file = %q, %v", got, err)
	}
	if err := p.CleanUp(context.Background(), "example.com", token, "key-auth"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("challenge file was not removed")
	}
}

func TestIssueRequiresExplicitDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := Issue(context.Background(), Config{
		Domain: "example.com", Webroot: dir,
		CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "directory URL") {
		t.Fatalf("Issue without a directory URL = %v, want explicit-directory error", err)
	}
}

func TestIsAccountMissing(t *testing.T) {
	if !isAccountMissing(&legoacme.ProblemDetails{Type: legoacme.AccountDoesNotExistErrorType}) {
		t.Fatal("accountDoesNotExist problem must be recognised")
	}
	if isAccountMissing(&legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:badNonce"}) {
		t.Fatal("badNonce must not be treated as a missing account")
	}
}
