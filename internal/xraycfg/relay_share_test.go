package xraycfg

import (
	"strings"
	"testing"
)

func TestRelayConfKeepsExplicitListenAddress(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"127.0.0.1", "listen 127.0.0.1:8443;"},
		{"0.0.0.0", "listen 0.0.0.0:8443;"},
		{"::1", "listen [::1]:8443;"},
		{"2001:db8::1", "listen [2001:db8::1]:8443;"},
		{"", "listen 0.0.0.0:8443;"},
	}
	for _, tc := range cases {
		conf, err := RelayConf(RelaySpec{ListenAddress: tc.addr, ListenPort: 8443, BackendHost: "example.org", BackendPort: 9443})
		if err != nil {
			t.Fatalf("%q: %v", tc.addr, err)
		}
		if !strings.Contains(conf, tc.want) {
			t.Fatalf("%q: missing %q in:\n%s", tc.addr, tc.want, conf)
		}
		if !strings.Contains(conf, "proxy_timeout 720m;") || !strings.Contains(conf, "proxy_socket_keepalive on;") ||
			!strings.Contains(conf, "proxy_connect_timeout 10s;") {
			t.Fatalf("%q: bash parity directives missing:\n%s", tc.addr, conf)
		}
	}
}

func TestRelayConfBracketsIPv6Backend(t *testing.T) {
	conf, err := RelayConf(RelaySpec{ListenAddress: "::", ListenPort: 443, BackendHost: "2001:db8::2", BackendPort: 9443})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "proxy_pass [2001:db8::2]:9443;") {
		t.Fatalf("IPv6 backend not bracketed:\n%s", conf)
	}
}

func TestRelayConfRejectsInvalidInput(t *testing.T) {
	bad := []RelaySpec{
		{ListenAddress: "localhost", ListenPort: 8443, BackendHost: "example.org", BackendPort: 9443},
		{ListenAddress: "[::1]", ListenPort: 8443, BackendHost: "example.org", BackendPort: 9443},
		{ListenAddress: "127.0.0.1", ListenPort: 0, BackendHost: "example.org", BackendPort: 9443},
		{ListenAddress: "127.0.0.1", ListenPort: 8443, BackendHost: "example.org", BackendPort: 65536},
		{ListenAddress: "127.0.0.1", ListenPort: 8443, BackendHost: "", BackendPort: 9443},
	}
	for i, spec := range bad {
		if _, err := RelayConf(spec); err == nil {
			t.Fatalf("case %d: invalid spec accepted: %+v", i, spec)
		}
	}
}

func TestShareRefusesAmbiguousLoopbackNone(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Transport: TransportWS, Domain: "example.com", Port: 10086})
	if err != nil {
		t.Fatal(err)
	}
	// Generated TLS backends keep security=none on loopback, exactly like Bash.
	if _, err := Share(g.Config, 0, "example.com", 443); err == nil {
		t.Fatal("ambiguous loopback security=none config must be refused without --public-security")
	}
}

func TestSharePublicSecurityTLS(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Transport: TransportWS, Domain: "example.com", Port: 10086})
	if err != nil {
		t.Fatal(err)
	}
	info, err := ShareConfig(g.Config, ShareOptions{Host: "example.com", PublicPort: 443, PublicSecurity: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode != ModeTLS || !strings.Contains(info.ShareURI, "security=tls") {
		t.Fatalf("TLS public link not rendered: %+v", info)
	}
	if !strings.Contains(info.ShareURI, "sni=example.com") || !strings.Contains(info.ShareURI, ":443") {
		t.Fatalf("public host/port lost: %s", info.ShareURI)
	}
}

func TestSharePublicSecurityNone(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeNone, Transport: TransportWS, Port: 10086})
	if err != nil {
		t.Fatal(err)
	}
	info, err := ShareConfig(g.Config, ShareOptions{Host: "203.0.113.9", PublicPort: 10086, PublicSecurity: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode != ModeNone || !strings.Contains(info.ShareURI, "security=none") {
		t.Fatalf("none link not rendered: %+v", info)
	}
}

func TestShareSelectsUserByEmailAndUUID(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second := AddUserSpec{UUID: "f0ca9bf0-07d9-44c0-9371-035e4160aa2b", Email: "second@example.com"}
	cfg, _, err := AddUser(g.Config, 0, second)
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"second@example.com", second.UUID} {
		info, err := ShareConfig(cfg, ShareOptions{User: selector, Host: "198.51.100.25"})
		if err != nil {
			t.Fatalf("%q: %v", selector, err)
		}
		if info.UUID != second.UUID {
			t.Fatalf("%q selected %s, want %s", selector, info.UUID, second.UUID)
		}
	}
	if _, err := ShareConfig(cfg, ShareOptions{User: "missing@example.com", Host: "198.51.100.25"}); err == nil {
		t.Fatal("unknown user must be refused")
	}
}

func TestShareRealityRequiresExplicitHost(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "www.example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ShareConfig(g.Config, ShareOptions{}); err == nil ||
		!strings.Contains(err.Error(), "--host is required") {
		t.Fatalf("Reality SNI must not become the connection host: %v", err)
	}
	info, err := ShareConfig(g.Config, ShareOptions{Host: "198.51.100.25"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(info.ShareURI, "vless://") || !strings.Contains(info.ShareURI, "@198.51.100.25:443?") {
		t.Fatalf("connection host not used: %s", info.ShareURI)
	}
	if !strings.Contains(info.ShareURI, "sni=www.example.com") {
		t.Fatalf("SNI lost: %s", info.ShareURI)
	}
	if strings.Contains(info.ShareURI, "@www.example.com") {
		t.Fatalf("camouflage SNI leaked into the dial address: %s", info.ShareURI)
	}
}
