package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const expectedCanonical = `{"assets":{"linux-amd64":{"name":"idleleo-linux-amd64","sha256":"2222222222222222222222222222222222222222222222222222222222222222","size":1234},"linux-arm64":{"name":"idleleo-linux-arm64","sha256":"1111111111111111111111111111111111111111111111111111111111111111","size":1234}},"channel":"go","schemaVersion":1,"version":"0.6.0"}`

// installTestReleaseKey writes a throwaway PKIX public key to a temporary PEM
// file and points IDLELEO_RELEASE_PUBKEY_FILE at it. It returns the matching
// private key so a test can sign manifests with it.
func installTestReleaseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release.pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDLELEO_RELEASE_PUBKEY_FILE", path)
	return priv
}

// signedManifestBytes marshals m, signs the canonical form and returns the
// manifest with its signature member set.
func signedManifestBytes(t *testing.T, m Manifest, key ed25519.PrivateKey) []byte {
	t.Helper()
	m.Signature = ""
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(key, canonical)
	m.Signature = signaturePrefix + base64.StdEncoding.EncodeToString(sig)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", ".github", "test", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCanonicalManifestMatchesJQ(t *testing.T) {
	got, err := CanonicalManifest(readFixture(t, "release-manifest.unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != expectedCanonical {
		t.Fatalf("canonical form does not match jq -cS:\n got: %s\nwant: %s", got, expectedCanonical)
	}
}

func TestVerifyManifestAcceptsScriptSignature(t *testing.T) {
	t.Setenv("IDLELEO_RELEASE_PUBKEY_FILE", filepath.Join("..", "..", ".github", "test", "fixtures", "release-manifest.pub.pem"))
	if err := VerifyManifest(readFixture(t, "release-manifest.signed.json")); err != nil {
		t.Fatalf("signature produced by scripts/sign_json_ed25519.sh was rejected: %v", err)
	}
}

func TestVerifyManifestRejectsTampering(t *testing.T) {
	t.Setenv("IDLELEO_RELEASE_PUBKEY_FILE", filepath.Join("..", "..", ".github", "test", "fixtures", "release-manifest.pub.pem"))
	raw := strings.Replace(string(readFixture(t, "release-manifest.signed.json")), `"0.6.0"`, `"0.6.1"`, 1)
	if err := VerifyManifest([]byte(raw)); err == nil {
		t.Fatal("tampered manifest must be rejected")
	}
}

func TestVerifyManifestRequiresSignature(t *testing.T) {
	if err := VerifyManifest(readFixture(t, "release-manifest.unsigned.json")); err == nil {
		t.Fatal("unsigned manifest must be rejected")
	}
}

func TestVerifyManifestRejectsWrongPrefix(t *testing.T) {
	raw := strings.Replace(string(readFixture(t, "release-manifest.signed.json")), `"ed25519:`, `"rsa:`, 1)
	if err := VerifyManifest([]byte(raw)); err == nil {
		t.Fatal("signature with an unsupported prefix must be rejected")
	}
}

func TestVerifyManifestRejectsTruncatedSignature(t *testing.T) {
	raw := string(readFixture(t, "release-manifest.signed.json"))
	start := strings.Index(raw, "ed25519:") + len("ed25519:")
	end := strings.Index(raw[start:], `"`) + start
	encoded := raw[start:end]
	truncated := raw[:start] + encoded[:len(encoded)/2] + raw[end:]
	if err := VerifyManifest([]byte(truncated)); err == nil {
		t.Fatal("truncated signature must be rejected")
	}
}

func TestCanonicalManifestDoesNotEscapeHTML(t *testing.T) {
	got, err := CanonicalManifest([]byte(`{"name":"a<b&c>d"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "a<b&c>d") {
		t.Fatalf("canonical form escaped HTML characters: %s", got)
	}
	if strings.Contains(string(got), `\u003c`) || strings.Contains(string(got), `\u0026`) {
		t.Fatalf("canonical form contains HTML escapes: %s", got)
	}
}

func TestVerifyManifestRejectsMalformedJSON(t *testing.T) {
	if err := VerifyManifest([]byte(`{"a":1} trailing`)); err == nil {
		t.Fatal("manifest with trailing data must be rejected")
	}
}
