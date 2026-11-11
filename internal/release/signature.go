package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// SignatureField is the manifest member that carries the detached Ed25519
// signature. It is removed before canonicalisation.
const SignatureField = "signature"

// signaturePrefix marks the signature algorithm so a future format change is
// rejected instead of silently misparsed.
const signaturePrefix = "ed25519:"

// releasePublicKeyPEM is the trusted Ed25519 public key for the Go release
// manifest. It is the same anchor install.sh uses for its metadata signature
// (shell_versions_pubkey_pem). Override only for tests and operations with
// IDLELEO_RELEASE_PUBKEY_FILE.
const releasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAiQVZy38jQPyS7lKDtM0vk+jSNSgavB/60UtVeFcw1t4=
-----END PUBLIC KEY-----
`

// CanonicalManifest returns the exact byte sequence that is signed: the JSON
// object with the signature member removed, keys recursively sorted,
// whitespace stripped and no trailing newline.
//
// This must stay byte-for-byte identical to the output of
// `jq -cS --arg field signature 'del(.[$field])'` in
// scripts/sign_json_ed25519.sh. Changing either side without the other breaks
// every previously published signature, so both must be updated together.
func CanonicalManifest(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("manifest is not a JSON object: %w", err)
	}
	if obj == nil {
		return nil, errors.New("manifest is not a JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("manifest has trailing JSON data")
		}
		return nil, fmt.Errorf("manifest has trailing data: %w", err)
	}
	delete(obj, SignatureField)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, fmt.Errorf("canonicalise manifest: %w", err)
	}
	// Encoder.Encode terminates with a newline; jq's `-c` output has none.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// VerifyManifest verifies the detached Ed25519 signature embedded in the raw
// manifest. It is fail-closed: a missing, malformed or unsupported signature
// is an error, never a pass.
func VerifyManifest(raw []byte) error {
	var envelope struct {
		Signature json.RawMessage `json:"signature"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if len(envelope.Signature) == 0 || string(envelope.Signature) == "null" {
		return errors.New("manifest has no signature")
	}
	var sigValue string
	if err := json.Unmarshal(envelope.Signature, &sigValue); err != nil {
		return fmt.Errorf("manifest signature is not a string: %w", err)
	}
	if !strings.HasPrefix(sigValue, signaturePrefix) {
		return fmt.Errorf("unsupported signature prefix in %q; want %q", sigValue, signaturePrefix)
	}
	encoded := strings.TrimPrefix(sigValue, signaturePrefix)
	sig, err := decodeSignature(encoded)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("manifest signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	pub, err := releasePublicKey()
	if err != nil {
		return err
	}
	canonical, err := CanonicalManifest(raw)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

func decodeSignature(s string) ([]byte, error) {
	if sig, err := base64.StdEncoding.DecodeString(s); err == nil {
		return sig, nil
	}
	sig, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("manifest signature is not valid base64: %w", err)
	}
	return sig, nil
}

// releasePublicKey returns the verification key, preferring an explicit PEM
// file from the environment so tests and break-glass operations can pin a
// different anchor.
func releasePublicKey() (ed25519.PublicKey, error) {
	pemBytes := []byte(releasePublicKeyPEM)
	if path := os.Getenv("IDLELEO_RELEASE_PUBKEY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read release public key: %w", err)
		}
		pemBytes = b
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("release public key is not valid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse release public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("release public key is %T, want ed25519.PublicKey", key)
	}
	return pub, nil
}
