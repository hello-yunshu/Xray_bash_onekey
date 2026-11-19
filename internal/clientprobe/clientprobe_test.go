package clientprobe

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseShareURIRealityTransports(t *testing.T) {
	cases := []struct {
		name, raw, network, path, service string
	}{
		{"raw", "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?encryption=none&security=reality&sni=www.example.com&pbk=abc&sid=0123&fp=chrome&type=tcp#n", "raw", "", ""},
		{"ws", "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=reality&sni=www.example.com&pbk=abc&sid=0123&type=ws&path=%2Fws#n", "ws", "/ws", ""},
		{"grpc", "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=reality&sni=www.example.com&pbk=abc&sid=0123&type=grpc&serviceName=gun#n", "grpc", "", "gun"},
		{"xhttp", "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=reality&sni=www.example.com&pbk=abc&sid=0123&type=xhttp&path=%2Fx#n", "xhttp", "/x", ""},
		{"tls", "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=tls&sni=www.example.com&type=ws&path=%2Fws#n", "ws", "/ws", ""},
		{"none", "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:80?security=none&type=tcp#n", "raw", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link, err := ParseShareURI(tc.raw)
			if err != nil {
				t.Fatalf("ParseShareURI: %v", err)
			}
			if link.Network != tc.network || link.Path != tc.path || link.ServiceName != tc.service {
				t.Fatalf("link=%+v", link)
			}
			if link.UUID != "11111111-1111-1111-1111-111111111111" {
				t.Fatalf("uuid=%q", link.UUID)
			}
			if link.Fingerprint != "chrome" {
				t.Fatalf("fingerprint=%q", link.Fingerprint)
			}
		})
	}
}

func TestParseShareURIRejectsUnsupported(t *testing.T) {
	cases := []string{
		"vmess://abc",
		"vless://@203.0.113.10:443?security=reality&sni=x&pbk=k&type=ws",
		"vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=reality&sni=x&type=kcp",
		"vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=reality&sni=x&type=grpc",
		"vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?security=xtls&type=tcp",
	}
	for _, raw := range cases {
		if _, err := ParseShareURI(raw); err == nil {
			t.Fatalf("expected %q to be refused", raw)
		}
	}
}

// TestWriteClientConfigIsPrivateAndComplete checks the temporary client file is
// 0600 and carries the transport and Reality fields unchanged.
func TestWriteClientConfigIsPrivateAndComplete(t *testing.T) {
	link := Link{
		UUID: "11111111-1111-1111-1111-111111111111", SNI: "www.example.com",
		PublicKey: "pub", ShortID: "0123", Fingerprint: "chrome",
		Network: "ws", Path: "/ws", Security: "reality",
	}
	path, cleanup, err := writeClientConfig(link, "127.0.0.1:24443", 1080)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", fi.Mode().Perm())
	}
	body, _ := os.ReadFile(path)
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	out := cfg["outbounds"].([]any)[0].(map[string]any)
	stream := out["streamSettings"].(map[string]any)
	if stream["network"] != "ws" || stream["security"] != "reality" {
		t.Fatalf("stream=%v", stream)
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["serverName"] != "www.example.com" || reality["publicKey"] != "pub" || reality["shortId"] != "0123" {
		t.Fatalf("reality=%v", reality)
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if int(in["port"].(float64)) != 1080 {
		t.Fatalf("socks port=%v", in["port"])
	}
}

func TestProbeRefusesMissingBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Probe(ctx, "/nonexistent/xray", Link{UUID: "id", Network: "raw", Security: "none"}, "127.0.0.1:1", "http://127.0.0.1/", "")
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("err=%v", err)
	}
}

func TestProbeRefusesTLSOrigin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Probe(ctx, "/bin/true", Link{UUID: "id", Network: "raw", Security: "none"}, "127.0.0.1:1", "https://origin.example/", "")
	if err == nil || !strings.Contains(err.Error(), "must use http") {
		t.Fatalf("err=%v", err)
	}
}

// serveRelayOnce answers one HTTP request with a fixed body so the relay probe
// can be tested without Docker or nginx.
func serveRelayOnce(t *testing.T, body string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 2048)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body))
	}()
	return l.Addr().String()
}

func TestProbeForwardReachesTheOrigin(t *testing.T) {
	addr := serveRelayOnce(t, "relay-ok\n")
	res, err := ProbeForward(context.Background(), addr, "http://origin.example/", "relay-ok")
	if err != nil {
		t.Fatalf("ProbeForward: %v", err)
	}
	if res.StatusLine != "HTTP/1.1 200 OK" || res.BodyBytes == 0 || res.Marker != "relay-ok" {
		t.Fatalf("result=%+v", res)
	}
}

func TestProbeForwardMarkerMismatchFails(t *testing.T) {
	addr := serveRelayOnce(t, "something-else\n")
	if _, err := ProbeForward(context.Background(), addr, "http://origin.example/", "relay-ok"); err == nil ||
		!strings.Contains(err.Error(), "relay-ok") {
		t.Fatalf("err=%v", err)
	}
}

func TestProbeForwardRejectsTLSOrigin(t *testing.T) {
	if _, err := ProbeForward(context.Background(), "127.0.0.1:1", "https://origin.example/", ""); err == nil ||
		!strings.Contains(err.Error(), "must use http") {
		t.Fatalf("err=%v", err)
	}
}
