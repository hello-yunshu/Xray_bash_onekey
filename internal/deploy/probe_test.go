package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

func stubProbe(t *testing.T, fn func(ctx context.Context, target, sni string) error) *int {
	t.Helper()
	old := probeOrigin
	calls := 0
	probeOrigin = func(ctx context.Context, target, sni string) error {
		calls++
		return fn(ctx, target, sni)
	}
	t.Cleanup(func() { probeOrigin = old })
	return &calls
}

func TestEditTargetProbesEffectiveOrigin(t *testing.T) {
	root, configPath, old := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	var gotTarget, gotSNI string
	stubProbe(t, func(_ context.Context, target, sni string) error {
		gotTarget, gotSNI = target, sni
		return nil
	})
	report, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{ServerNames: []string{"www.example.org"}}, NoRestart: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotSNI != "www.example.org" {
		t.Fatalf("sni = %q", gotSNI)
	}
	if gotTarget != "example.com:443" {
		t.Fatalf("target = %q, want the installed target unchanged", gotTarget)
	}
	if report.OriginProbe == "" {
		t.Fatal("report must record the successful probe")
	}
	newBody, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(newBody) == string(old) {
		t.Fatal("config should have changed")
	}
}

func TestEditTargetProbeFailureWritesNothing(t *testing.T) {
	root, configPath, old := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	stubProbe(t, func(context.Context, string, string) error {
		return ErrOriginUnreachable
	})
	_, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Target: "origin.invalid:443"}, NoRestart: true,
	})
	if !errors.Is(err, ErrOriginUnreachable) {
		t.Fatalf("err = %v, want ErrOriginUnreachable", err)
	}
	body, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != string(old) {
		t.Fatal("probe failure must not modify the live config")
	}
	entries, _ := os.ReadDir(root + "/etc/idleleo/backup")
	if len(entries) != 0 {
		t.Fatalf("probe failure must not write a backup, got %d entries", len(entries))
	}
}

func TestEditPortDoesNotProbeOrigin(t *testing.T) {
	root, _, _ := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	calls := stubProbe(t, func(context.Context, string, string) error {
		return errors.New("must not be called")
	})
	if _, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8080}, NoRestart: true,
	}); err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("port edit probed the origin %d times", *calls)
	}
}

func TestEditNoProbeSkipsOriginProbe(t *testing.T) {
	root, _, _ := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	calls := stubProbe(t, func(context.Context, string, string) error {
		return errors.New("must not be called")
	})
	report, err := EditConfig(context.Background(), EditSpec{
		Root:      root,
		Request:   xraycfg.EditRequest{Target: "origin.example.org:443"},
		NoRestart: true,
		NoProbe:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if *calls != 0 {
		t.Fatalf("--no-probe still probed the origin %d times", *calls)
	}
	if report.OriginProbe != "skipped: --no-probe" {
		t.Fatalf("originProbe = %q, want skipped: --no-probe", report.OriginProbe)
	}
}

func TestDefaultProbeOriginRejectsUntrustedChain(t *testing.T) {
	srv := tlsListener(t, nil, "example.com")
	defer srv.Close()
	err := defaultProbeOrigin(context.Background(), srv.Addr().String(), "example.com")
	if !errors.Is(err, ErrOriginUnreachable) {
		t.Fatalf("self-signed origin err = %v, want ErrOriginUnreachable", err)
	}
	if err := defaultProbeOrigin(context.Background(), "127.0.0.1:1", ""); !errors.Is(err, ErrOriginUnreachable) {
		t.Fatalf("closed port err = %v", err)
	}
}

func TestDefaultProbeOriginTrustedCA(t *testing.T) {
	ca := newTestCA(t)
	trustCA(t, ca)
	srv := tlsListener(t, ca, "local.test")
	defer srv.Close()
	addr := srv.Addr().String()
	if err := defaultProbeOrigin(context.Background(), addr, "local.test"); err != nil {
		t.Fatalf("probe against CA-signed origin: %v", err)
	}
	// The certificate names local.test only, so a different SNI must fail the
	// hostname check.
	if err := defaultProbeOrigin(context.Background(), addr, "other.test"); !errors.Is(err, ErrOriginUnreachable) {
		t.Fatalf("hostname mismatch err = %v, want ErrOriginUnreachable", err)
	}
}

// TestProbeTLSConfigIsOrdinaryClient guards the bar the probe holds the origin
// to: full chain and hostname verification, but nothing Reality itself does not
// require (no insecure skip, no pinned minimum version).
func TestProbeTLSConfigIsOrdinaryClient(t *testing.T) {
	cfg := probeTLSConfig("www.example.com")
	if cfg.InsecureSkipVerify {
		t.Fatal("probe must verify the origin certificate chain")
	}
	if cfg.RootCAs != nil {
		t.Fatal("probe must use the system roots, not a private pool")
	}
	if cfg.MinVersion != 0 {
		t.Fatalf("probe must not pin a TLS version, got %#x", cfg.MinVersion)
	}
	if cfg.ServerName != "www.example.com" {
		t.Fatalf("server name = %q", cfg.ServerName)
	}
}

// testCA is a throwaway certificate authority used to prove the probe accepts
// a chain it can verify without touching the host trust store.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := generateKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "e2e local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) leaf(t *testing.T, dnsNames ...string) tls.Certificate {
	t.Helper()
	key := generateKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func trustCA(t *testing.T, ca *testCA) {
	t.Helper()
	old := probeTLSConfig
	probeTLSConfig = func(sni string) *tls.Config {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca.pem) {
			t.Fatal("cannot load test CA")
		}
		return &tls.Config{ServerName: sni, RootCAs: pool}
	}
	t.Cleanup(func() { probeTLSConfig = old })
}

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// tlsListener starts a local TLS server so the probe can be exercised without
// external network access. A nil ca produces a self-signed certificate.
func tlsListener(t *testing.T, ca *testCA, dnsNames ...string) net.Listener {
	t.Helper()
	var cert tls.Certificate
	if ca != nil {
		cert = ca.leaf(t, dnsNames...)
	} else {
		key := generateKey(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: dnsNames[0]},
			DNSNames:     dnsNames,
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln
}
