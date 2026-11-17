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
	"os/user"
	"path/filepath"
	"strconv"
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
	old := snapshotPair(certPath, keyPath)
	newChain, newKeyDER := testPair(t, 2, "new.example.com")
	if err := replacePair(certPath, keyPath, newChain, newKeyDER); err != nil {
		t.Fatal(err)
	}
	cfg := Config{CertFile: certPath, KeyFile: keyPath, ReloadCommand: "exit 1"}
	err = reloadOrRestore(context.Background(), cfg, old)
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

func TestApplyPairPermissionsLayered(t *testing.T) {
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("lookup current group: %v", err)
	}
	dir := t.TempDir()
	// A non-managed directory must keep its own mode (0755) instead of being
	// tightened to 0750 by the certificate permission pass.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	chain, keyDER := testPair(t, 1, "example.com")
	if err := replacePair(certPath, keyPath, chain, keyDER); err != nil {
		t.Fatal(err)
	}
	if err := applyPairPermissions(certPath, keyPath, g.Name); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{dir: 0o755, certPath: 0o640, keyPath: 0o640}
	for path, mode := range want {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
}

func TestUserManagedCertificateIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "xray.crt")
	keyPath := filepath.Join(dir, "xray.key")
	if err := MarkUserManaged(certPath); err != nil {
		t.Fatal(err)
	}
	if !IsUserManaged(certPath) {
		t.Fatal("marker was not created")
	}
	cfg := Config{
		DirectoryURL: StagingDirectory,
		Domain:       "example.com",
		Webroot:      dir,
		CertFile:     certPath,
		KeyFile:      keyPath,
	}
	if _, err := Issue(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "user-managed") {
		t.Fatalf("Issue on a user-managed certificate = %v, want refusal", err)
	}
	res, err := Renew(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || !strings.Contains(res.Reason, "user-managed") {
		t.Fatalf("Renew = %+v, want a user-managed skip", res)
	}
}

func TestMigrateLegacyAccountMovesState(t *testing.T) {
	root := t.TempDir()
	certDir := filepath.Join(root, "etc", "idleleo", "cert")
	legacy := filepath.Join(certDir, "acme")
	if err := os.MkdirAll(legacy, 0o750); err != nil {
		t.Fatal(err)
	}
	// Simulate the Bash layered pass: the legacy account key was group-readable
	// inside the certificate tree.
	if err := os.WriteFile(filepath.Join(legacy, "account.key"), []byte("key"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "account.json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	accountDir := filepath.Join(root, "etc", "idleleo", "acme")
	// A pre-existing, too-open target directory must be tightened as well.
	if err := os.MkdirAll(accountDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		CertFile:       filepath.Join(certDir, "xray.crt"),
		AccountKeyFile: filepath.Join(accountDir, "account.key"),
		StateFile:      filepath.Join(accountDir, "account.json"),
	}
	if err := migrateLegacyAccount(cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"account.key", "account.json"} {
		info, err := os.Stat(filepath.Join(accountDir, name))
		if err != nil {
			t.Fatalf("%s not migrated: %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", name, info.Mode().Perm())
		}
	}
	if info, err := os.Stat(accountDir); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o700 {
		t.Fatalf("account dir mode = %o, want 0700", info.Mode().Perm())
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy account directory still exists: %v", err)
	}
}

func TestMarkManagedWritesOwnershipMarker(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "xray.crt")
	if err := markManaged(certPath, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ManagedMarker(certPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("marker mode = %o, want 0644", info.Mode().Perm())
	}
	if IsUserManaged(certPath) {
		t.Fatal("managed marker must not read as user-managed")
	}
}

func TestMigrateLegacyAccountRefusesUnexpectedEntries(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "cert", "acme")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "notes.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := migrateLegacyAccount(Config{
		CertFile:       filepath.Join(root, "cert", "xray.crt"),
		AccountKeyFile: filepath.Join(root, "acme", "account.key"),
		StateFile:      filepath.Join(root, "acme", "account.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected entry") {
		t.Fatalf("migration = %v, want a refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(legacy, "notes.txt")); statErr != nil {
		t.Fatal("refused migration must leave the source untouched")
	}
}

func TestAccountStateKeepsOneURLPerDirectory(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "account.json")
	if err := writeAccountURL(stateFile, StagingDirectory, "https://staging/acct/1"); err != nil {
		t.Fatal(err)
	}
	if err := writeAccountURL(stateFile, ProductionDirectory, "https://prod/acct/2"); err != nil {
		t.Fatal(err)
	}
	if got := readAccountURL(stateFile, StagingDirectory); got != "https://staging/acct/1" {
		t.Fatalf("staging KID=%q", got)
	}
	if got := readAccountURL(stateFile, ProductionDirectory); got != "https://prod/acct/2" {
		t.Fatalf("production KID=%q", got)
	}
}

func TestInspectReportsMissingCertificate(t *testing.T) {
	ins, err := Inspect(filepath.Join(t.TempDir(), "absent.crt"), 720*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ins.Missing || !ins.Due {
		t.Fatalf("inspection = %+v, want missing+due", ins)
	}
}
