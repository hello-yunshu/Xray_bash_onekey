package doctor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/clientprobe"
)

func writeFile(t *testing.T, root, rel string, body []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func healthyRoot(t *testing.T) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	config := []byte(`{"inbounds":[{"port":443,"tag":"inbound","protocol":"vless"}]}`)
	writeFile(t, root, "etc/idleleo/conf/xray/config.json", config, 0o600)
	sum := sha256.Sum256(config)
	meta := map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node", "tls": "Reality",
		"transport": "tcp", "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256": hex.EncodeToString(sum[:]), "ownedResources": []string{"xray"},
		"updatedAt": "2026-11-18T00:00:00Z",
	}
	body, _ := json.Marshal(meta)
	writeFile(t, root, "etc/idleleo/v1/metadata.json", body, 0o600)
	writeFile(t, root, "etc/idleleo/backup/edit-1/config.json", []byte("{}"), 0o600)
	writeFile(t, root, "etc/idleleo/share/xray/geoip.dat", []byte("x"), 0o644)
	writeFile(t, root, "etc/idleleo/share/xray/geosite.dat", []byte("x"), 0o644)
	writeCert(t, root, time.Now().Add(365*24*time.Hour), 0o600)
	return root, config
}

func writeCert(t *testing.T, root string, notAfter time.Time, mode os.FileMode) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "doctor.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"doctor.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeFile(t, root, "etc/idleleo/cert/xray.crt", body, 0o644)
	writeFile(t, root, "etc/idleleo/cert/xray.key", []byte("test-key"), mode)
}

func TestRunHealthySandbox(t *testing.T) {
	root, _ := healthyRoot(t)
	rep := RunWith(context.Background(), root, Options{
		Validate: func(context.Context, string) error { return nil },
	})
	if !rep.Healthy {
		t.Fatalf("expected healthy report, got %+v", rep)
	}
	for _, id := range []string{"layout", "metadata", "validator", "permissions", "certificate", "backup", "disk", "geodata"} {
		if find(rep, id).Status != StatusOK {
			t.Fatalf("%s = %+v", id, find(rep, id))
		}
	}
	if find(rep, "services").Status != StatusSkip {
		t.Fatalf("sandbox service check should skip: %+v", find(rep, "services"))
	}
}

func TestRunFindsExpiredCertificateAndLooseModes(t *testing.T) {
	root, _ := healthyRoot(t)
	writeCert(t, root, time.Now().Add(-time.Hour), 0o644)
	if err := os.Chmod(filepath.Join(root, "etc/idleleo/conf/xray/config.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := RunWith(context.Background(), root, Options{Validate: func(context.Context, string) error { return nil }})
	if rep.Healthy {
		t.Fatalf("expected unhealthy report: %+v", rep)
	}
	if find(rep, "certificate").Status != StatusFail {
		t.Fatalf("certificate = %+v", find(rep, "certificate"))
	}
	if find(rep, "permissions").Status != StatusFail {
		t.Fatalf("permissions = %+v", find(rep, "permissions"))
	}
}

func rootWithRealityClient(t *testing.T, port int) string {
	t.Helper()
	root, _ := healthyRoot(t)
	// A fixed 32-byte seed is a valid X25519 scalar for a test key.
	priv := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	config := []byte(fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"tag":"in","protocol":"vless","settings":{"clients":[{"id":"11111111-1111-1111-1111-111111111111"}]},"streamSettings":{"network":"ws","security":"reality","wsSettings":{"path":"/probe"},"realitySettings":{"privateKey":%q,"shortIds":["0123456789abcdef"],"serverNames":["doctor.example"]}}}]}`, port, priv))
	writeFile(t, root, "etc/idleleo/conf/xray/config.json", config, 0o600)
	// The probe seam is injected, so a placeholder binary is enough to pass the
	// installed-binary precondition.
	writeFile(t, root, "usr/local/bin/xray", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	sum := sha256.Sum256(config)
	meta := map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node", "tls": "Reality",
		"transport": "ws", "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256": hex.EncodeToString(sum[:]), "ownedResources": []string{"xray"},
		"updatedAt": "2026-11-18T00:00:00Z",
	}
	body, _ := json.Marshal(meta)
	writeFile(t, root, "etc/idleleo/v1/metadata.json", body, 0o600)
	return root
}

// TestClientProbeReportsRealClientPass proves the strongest evidence level is
// only reported after the probe seam actually succeeded.
func TestClientProbeReportsRealClientPass(t *testing.T) {
	root := rootWithRealityClient(t, 24443)
	var gotLink clientprobe.Link
	var gotAddr string
	rep := RunWith(context.Background(), root, Options{
		ClientProbe: true,
		ProbeURL:    "http://origin.example/fast",
		Validate:    func(context.Context, string) error { return nil },
		Probe: func(_ context.Context, _ string, link clientprobe.Link, addr, origin, marker string) (clientprobe.Result, error) {
			gotLink, gotAddr = link, addr
			if origin != "http://origin.example/fast" || marker != "" {
				t.Fatalf("origin=%q marker=%q", origin, marker)
			}
			return clientprobe.Result{StatusLine: "HTTP/1.1 200 OK", BodyBytes: 42}, nil
		},
	})
	check := find(rep, "client-probe")
	if check.Status != StatusOK || check.Evidence != EvidenceRealClient {
		t.Fatalf("client-probe = %+v", check)
	}
	if rep.EvidenceLevel != EvidenceRealClient {
		t.Fatalf("evidenceLevel=%q", rep.EvidenceLevel)
	}
	if gotAddr != "127.0.0.1:24443" {
		t.Fatalf("addr=%q", gotAddr)
	}
	if gotLink.UUID != "11111111-1111-1111-1111-111111111111" || gotLink.Network != "ws" ||
		gotLink.SNI != "doctor.example" || gotLink.Path != "/probe" ||
		gotLink.ShortID != "0123456789abcdef" || gotLink.PublicKey == "" {
		t.Fatalf("link=%+v", gotLink)
	}
}

func TestClientProbeFailureIsFailNotUnknown(t *testing.T) {
	root := rootWithRealityClient(t, 24444)
	rep := RunWith(context.Background(), root, Options{
		ClientProbe: true,
		ProbeURL:    "http://origin.example/",
		Validate:    func(context.Context, string) error { return nil },
		Probe: func(context.Context, string, clientprobe.Link, string, string, string) (clientprobe.Result, error) {
			return clientprobe.Result{}, fmt.Errorf("origin returned 502")
		},
	})
	check := find(rep, "client-probe")
	if check.Status != StatusFail || check.Evidence != EvidenceRealClient {
		t.Fatalf("client-probe = %+v", check)
	}
	if rep.Healthy {
		t.Fatal("a failed client probe must not report healthy")
	}
}

func TestClientProbeWithoutURLIsNotRun(t *testing.T) {
	root := rootWithRealityClient(t, 24445)
	rep := RunWith(context.Background(), root, Options{
		ClientProbe: true,
		Validate:    func(context.Context, string) error { return nil },
	})
	check := find(rep, "client-probe")
	if check.Status != StatusSkip || check.Evidence != EvidenceNotRun {
		t.Fatalf("client-probe = %+v", check)
	}
}

func rootWithInbound(t *testing.T, port int, security string) string {
	t.Helper()
	root, _ := healthyRoot(t)
	config := []byte(fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"tag":"in","protocol":"vless","streamSettings":{"security":%q,"tlsSettings":{"serverName":"doctor.example"}}}]}`, port, security))
	writeFile(t, root, "etc/idleleo/conf/xray/config.json", config, 0o600)
	sum := sha256.Sum256(config)
	meta := map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node", "tls": "TLS",
		"transport": "tcp", "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256": hex.EncodeToString(sum[:]), "ownedResources": []string{"xray"},
		"updatedAt": "2026-11-18T00:00:00Z",
	}
	body, _ := json.Marshal(meta)
	writeFile(t, root, "etc/idleleo/v1/metadata.json", body, 0o600)
	return root
}

func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "doctor.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"doctor.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestDeepTLSHandshake(t *testing.T) {
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedTLS(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if c, ok := conn.(*tls.Conn); ok {
				_ = c.Handshake()
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	root := rootWithInbound(t, port, "tls")
	rep := RunWith(context.Background(), root, Options{Deep: true, Validate: func(context.Context, string) error { return nil }})
	check := find(rep, "connectivity")
	if check.Status != StatusOK || check.Evidence != EvidenceTLS {
		t.Fatalf("connectivity = %+v", check)
	}
}

func TestDeepRealityIsUnknownNotFaked(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	root := rootWithInbound(t, port, "reality")
	rep := RunWith(context.Background(), root, Options{Deep: true, Validate: func(context.Context, string) error { return nil }})
	check := find(rep, "connectivity")
	if check.Status != StatusUnknown || check.Evidence != EvidenceTCP {
		t.Fatalf("connectivity = %+v", check)
	}
}

func TestDeepClosedPortFails(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	root := rootWithInbound(t, port, "none")
	rep := RunWith(context.Background(), root, Options{Deep: true, Validate: func(context.Context, string) error { return nil }})
	check := find(rep, "connectivity")
	if check.Status != StatusFail {
		t.Fatalf("connectivity = %+v", check)
	}
}

func TestRunMissingInstall(t *testing.T) {
	rep := Run(context.Background(), t.TempDir())
	if rep.Healthy || find(rep, "layout").Status != StatusFail || find(rep, "runtime-config").Status != StatusFail {
		t.Fatalf("missing install was not diagnosed: %+v", rep)
	}
}

func find(rep Report, id string) Check {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{ID: id, Status: Status("missing")}
}
