package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	if check.Status != StatusOK || check.Evidence != "tls-handshake" {
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
	if check.Status != StatusUnknown || check.Evidence != "tcp-connect" {
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
