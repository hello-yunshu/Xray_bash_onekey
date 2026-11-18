package ops

import (
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

	"github.com/hello-yunshu/Xray_bash_onekey/internal/app"
)

func TestParsePortsSkipsZeroAndKeepsOrder(t *testing.T) {
	raw := []byte(`{"inbounds":[
	  {"listen":"0.0.0.0","port":443,"protocol":"vless","tag":"reality"},
	  {"listen":"127.0.0.1","port":0,"protocol":"dokodemo-door","tag":"api"},
	  {"port":8443,"protocol":"trojan","tag":"tr"}
	]}`)
	ports := parsePorts(raw)
	if len(ports) != 2 {
		t.Fatalf("ports = %+v", ports)
	}
	if ports[0].Port != 443 || ports[0].Tag != "reality" {
		t.Fatalf("first port = %+v", ports[0])
	}
	if ports[1].Protocol != "trojan" || ports[1].Listen != "" {
		t.Fatalf("second port = %+v", ports[1])
	}
	if got := parsePorts([]byte("not json")); len(got) != 0 {
		t.Fatalf("invalid json produced %+v", got)
	}
}

func TestJournalReadsArrayAndJSONL(t *testing.T) {
	dir := t.TempDir()
	array := filepath.Join(dir, "phase01.json")
	body := `[{"id":"1","state":"COMMITTED"},{"id":"2","state":"FAILED"}]`
	if err := os.WriteFile(array, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := journal(array)
	if len(entries) != 2 || entries[1].State != "FAILED" {
		t.Fatalf("array entries = %+v", entries)
	}
	lines := filepath.Join(dir, "lines.jsonl")
	body = "{\"id\":\"a\",\"state\":\"COMMITTED\"}\n\n{\"id\":\"b\",\"state\":\"ROLLED_BACK\"}\n"
	if err := os.WriteFile(lines, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	entries = journal(lines)
	if len(entries) != 2 || entries[1].State != "ROLLED_BACK" {
		t.Fatalf("jsonl entries = %+v", entries)
	}
	if got := journal(filepath.Join(dir, "missing.json")); len(got) != 0 {
		t.Fatalf("missing file produced %+v", got)
	}
}

func TestCertificateReportsExpiryAndSANs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xray.crt")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBody, 0o644); err != nil {
		t.Fatal(err)
	}
	cert := certificate(path)
	if !cert.Present {
		t.Fatal("certificate not recognised")
	}
	if cert.DaysLeft < 28 || cert.DaysLeft > 30 {
		t.Fatalf("daysLeft = %d", cert.DaysLeft)
	}
	if len(cert.SANs) != 1 || cert.SANs[0] != "example.test" {
		t.Fatalf("sans = %v", cert.SANs)
	}
	if missing := certificate(filepath.Join(dir, "nope.crt")); missing.Present {
		t.Fatal("missing certificate reported as present")
	}
}

func reportStatusStub() app.StatusReport {
	return app.StatusReport{SchemaVersion: 1, Installed: true, Engine: "xray", Role: "reality", TLS: "reality"}
}

func TestTextRendersCoreLines(t *testing.T) {
	out := Text(Report{
		Status:       reportStatusStub(),
		Ports:        []Port{{Protocol: "vless", Port: 443, Tag: "reality"}},
		Certificate:  Certificate{Path: "/etc/idleleo/cert/xray.crt", Present: true, NotAfter: "2027-01-01T00:00:00Z", DaysLeft: 42},
		RestartCount: 3,
	})
	for _, want := range []string{"port=443 protocol=vless", "daysLeft=42", "recentFailures=0 restartCount=3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}
