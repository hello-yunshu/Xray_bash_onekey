// verify_cert.go is a test-only helper: it parses an issued certificate chain,
// verifies it against the Pebble local root, checks the SAN, and optionally
// proves the installed private key matches the leaf public key.
//
// Usage: go run verify_cert.go <fullchain.pem> <root.pem> <domain> [key.pem]
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

type report struct {
	Subject     string   `json:"subject"`
	DNSNames    []string `json:"dnsNames"`
	Serial      string   `json:"serial"`
	NotBefore   string   `json:"notBefore"`
	NotAfter    string   `json:"notAfter"`
	ValidDays   float64  `json:"validDays"`
	Verified    bool     `json:"verifiedToLocalRoot"`
	HostnameOK  bool     `json:"hostnameVerified"`
	KeyMatches  bool     `json:"privateKeyMatches"`
	VerifyError string   `json:"verifyError,omitempty"`
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: verify_cert.go <fullchain.pem> <root.pem> <domain> [key.pem]")
		os.Exit(2)
	}
	certPath, rootPath, domain := os.Args[1], os.Args[2], os.Args[3]
	chain, err := parsePEMCerts(certPath)
	if err != nil {
		fail(err)
	}
	if len(chain) == 0 {
		fail(fmt.Errorf("no certificates in %s", certPath))
	}
	leaf := chain[0]
	roots, err := parsePEMCerts(rootPath)
	if err != nil {
		fail(err)
	}
	pool := x509.NewCertPool()
	for _, c := range roots {
		pool.AddCert(c)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	out := report{
		Subject:   leaf.Subject.String(),
		DNSNames:  leaf.DNSNames,
		Serial:    leaf.SerialNumber.Text(16),
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  leaf.NotAfter.UTC().Format(time.RFC3339),
		ValidDays: leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24,
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: domain}); err != nil {
		out.VerifyError = err.Error()
	} else {
		out.Verified = true
		out.HostnameOK = true
	}
	if len(os.Args) >= 5 {
		key, err := parsePrivateKey(os.Args[4])
		if err != nil {
			fail(err)
		}
		pub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			fail(err)
		}
		want, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			fail(err)
		}
		out.KeyMatches = bytes.Equal(pub, want)
	}
	raw, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(raw))
}

func parsePEMCerts(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func parsePrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("key %s is not PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key %s is not ECDSA", path)
	}
	return ec, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
