package xraycfg

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestPortAvailableSeesOccupiedLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if PortAvailable("127.0.0.1", port) {
		t.Fatal("a listening port must be reported as unavailable")
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if !PortAvailable("127.0.0.1", port) {
		t.Fatal("a released port must be reported as available")
	}
}

func TestGenerateReality(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(g.Config, &root); err != nil {
		t.Fatalf("generated config is not JSON: %v", err)
	}
	if len(g.Users) != 1 || !g.Users[0].Primary {
		t.Fatalf("expected one primary user, got %+v", g.Users)
	}
	if _, err := DerivePublicKey(g.PrivateKey); err != nil {
		t.Fatalf("private key is not usable: %v", err)
	}
	if g.PublicKey == "" || g.ShortID == "" {
		t.Fatalf("missing reality secrets: %+v", g)
	}
	if !strings.Contains(g.ShareURI, "security=reality") || !strings.Contains(g.ShareURI, "pbk="+g.PublicKey) {
		t.Fatalf("share URI missing reality fields: %s", g.ShareURI)
	}
	if !strings.Contains(string(g.Config), `"minClientVer": "1.0.0"`) {
		t.Fatalf("minClientVer missing")
	}
	if !strings.Contains(string(g.Config), `"flow": "xtls-rprx-vision"`) {
		t.Fatalf("flow missing")
	}
}

func TestGenerateTLSRequiresDomainAndLoopback(t *testing.T) {
	if _, err := Generate(Spec{Mode: ModeTLS}); err == nil {
		t.Fatal("expected domain requirement")
	}
	_, err := Generate(Spec{Mode: ModeNone, Listen: "0.0.0.0"})
	if err == nil {
		t.Fatal("expected non-loopback refusal")
	}
	if _, err := Generate(Spec{Mode: ModeNone, Listen: "0.0.0.0", AllowNonLoopback: true}); err != nil {
		t.Fatalf("explicit allow should pass: %v", err)
	}
}

func TestGenerateXHTTPClashIsExplicit(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", Transport: TransportXHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if g.ClashYAML != "" {
		t.Fatalf("xhttp must not produce a fake clash proxy")
	}
	if len(g.Warnings) == 0 || g.Warnings[0] != "clash-xhttp-unsupported" {
		t.Fatalf("expected explicit xhttp warning, got %v", g.Warnings)
	}
	if !strings.Contains(g.NginxConf, "location /ray/") {
		t.Fatalf("nginx snippet missing location: %s", g.NginxConf)
	}
}

func TestGenerateXHTTPPathMatchesNginxSlashNormalization(t *testing.T) {
	g, err := Generate(Spec{
		Mode: ModeTLS, Domain: "example.com", Transport: TransportXHTTP,
		Path: "//ray//custom//",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(g.Config), `"path": "/ray/custom/"`) {
		t.Fatalf("Xray config did not normalize repeated XHTTP slashes: %s", g.Config)
	}
	if !strings.Contains(g.NginxConf, "location /ray/custom/ {") {
		t.Fatalf("Nginx location does not match normalized XHTTP path: %s", g.NginxConf)
	}
}

func multiInbounds(t *testing.T, g Generated) []map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(g.Config, &root); err != nil {
		t.Fatalf("generated config is not JSON: %v", err)
	}
	raw, _ := root["inbounds"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		out = append(out, item.(map[string]any))
	}
	return out
}

func TestGenerateMultiTransportNone(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeNone, Transport: TransportMulti, Port: 10080})
	if err != nil {
		t.Fatalf("multi transport must be accepted: %v", err)
	}
	in := multiInbounds(t, g)
	if len(in) != 3 {
		t.Fatalf("expected three inbounds, got %d", len(in))
	}
	want := []string{"ws", "grpc", "xhttp"}
	seenPorts := map[int]bool{}
	for i, d := range in {
		st := d["streamSettings"].(map[string]any)
		if st["network"] != want[i] {
			t.Fatalf("inbound %d network = %v, want %s", i, st["network"], want[i])
		}
		seenPorts[int(d["port"].(float64))] = true
	}
	if len(seenPorts) != 3 {
		t.Fatalf("inbound ports must be distinct: %v", seenPorts)
	}
	if _, ok := seenPorts[10080]; !ok {
		t.Fatalf("primary inbound must use the requested port: %v", seenPorts)
	}
	if g.Transport != TransportMulti {
		t.Fatalf("generated transport = %q", g.Transport)
	}
	var root map[string]any
	if err := json.Unmarshal(g.Config, &root); err != nil {
		t.Fatal(err)
	}
	rule := root["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if len(rule["inboundTag"].([]any)) != 3 {
		t.Fatalf("routing must cover all inbound tags: %v", rule["inboundTag"])
	}
}

// TestGenerateNoneMultiTransportHonoursListen keeps every added inbound on the
// operator's listen address: Bash rewrites ws/gRPC/xHTTP to the same resolved
// address for the no-TLS branch, so only the primary following --listen would
// silently leave the other transports on loopback.
func TestGenerateNoneMultiTransportHonoursListen(t *testing.T) {
	g, err := Generate(Spec{
		Mode: ModeNone, Transport: TransportMulti, Port: 12086,
		Listen: "10.10.0.5", AllowNonLoopback: true, SkipPortProbe: true,
		GRPCPort: 12444, XHTTPPort: 12445,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range multiInbounds(t, g) {
		if in["listen"] != "10.10.0.5" {
			t.Fatalf("inbound %v listen = %v, want 10.10.0.5", in["tag"], in["listen"])
		}
	}
	defaults, err := Generate(Spec{Mode: ModeNone, Transport: TransportMulti, SkipPortProbe: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range multiInbounds(t, defaults) {
		if in["listen"] != "127.0.0.1" {
			t.Fatalf("default inbound %v listen = %v, want 127.0.0.1", in["tag"], in["listen"])
		}
	}
}

func TestGenerateMultiTransportTLSRoutesEachInbound(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", Transport: TransportMulti, Port: 10080, WSPort: 10080})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"proxy_pass http://xray-ws-server;",
		"grpc_pass grpc://xray-grpc-server;",
		"grpc_pass grpc://xray-xhttp-server;",
		"location /xhttp/",
	} {
		if !strings.Contains(g.NginxConf, needle) {
			t.Fatalf("nginx snippet missing %q:\n%s", needle, g.NginxConf)
		}
	}
	if got := g.NginxFragments["127.0.0.1.wsServers"]; !strings.Contains(got, "server 127.0.0.1:10080 weight=50") {
		t.Fatalf("ws upstream fragment = %q", got)
	}
	if got := g.NginxFragments["02-xray-server.conf"]; !strings.Contains(got, "upstream xray-ws-server {") {
		t.Fatalf("upstream conf missing ws block: %q", got)
	}
}

func TestGenerateTLSMatchesBashFront(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", Transport: TransportWS, Port: 10080, WSPort: 10080})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{
		"listen 443 ssl reuseport;",
		"listen [::]:443 ssl reuseport;",
		"listen 443 quic reuseport;",
		"http2 on;",
		"real_ip_header        X-Forwarded-For;",
		"ssl_certificate       /etc/idleleo/cert/xray.crt;",
		"ssl_certificate_key   /etc/idleleo/cert/xray.key;",
		"ssl_protocols         TLSv1.3;",
		"ssl_early_data on;",
		"proxy_pass http://xray-ws-server;",
		"proxy_set_header Host $http_host;",
		"client_max_body_size 0;",
		"location / {\n        return 403;",
	} {
		if !strings.Contains(g.NginxConf, needle) {
			t.Fatalf("tls site missing %q:\n%s", needle, g.NginxConf)
		}
	}
	redirect := g.NginxFragments["01-xray-80.conf"]
	for _, needle := range []string{
		"listen 80;",
		"listen [::]:80;",
		"server_name example.com;",
		"location ^~ /.well-known/acme-challenge/",
		"return 301 https://example.com$request_uri;",
	} {
		if !strings.Contains(redirect, needle) {
			t.Fatalf("acme site missing %q:\n%s", needle, redirect)
		}
	}
	upstream := g.NginxFragments["02-xray-server.conf"]
	if !strings.Contains(upstream, "upstream xray-ws-server {") ||
		!strings.Contains(upstream, "include /etc/idleleo/conf/nginx/*.wsServers;") {
		t.Fatalf("upstream file mismatch:\n%s", upstream)
	}
	if got := g.NginxFragments["127.0.0.1.wsServers"]; got != "server 127.0.0.1:10080 weight=50 max_fails=2 fail_timeout=10;\n" {
		t.Fatalf("ws server fragment = %q", got)
	}
}

func TestGenerateTLSHonoursPublicPort(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", Port: 10080, PublicPort: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.NginxConf, "listen 8443 ssl reuseport;") {
		t.Fatalf("public port not applied:\n%s", g.NginxConf)
	}
	if !strings.Contains(g.NginxFragments["01-xray-80.conf"], "return 301 https://example.com:8443$request_uri;") {
		t.Fatalf("redirect must keep the non-standard port: %s", g.NginxFragments["01-xray-80.conf"])
	}
}

// TestGenerateTLSReportsBackendPort guards the reported backend port: TLS has
// no fixed inbound port before the picker runs, and reporting zero made
// `xray generate` print `port=0` for a fully configured backend.
func TestGenerateTLSReportsBackendPort(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	in := multiInbounds(t, g)
	if len(in) != 1 {
		t.Fatalf("inbounds = %v", in)
	}
	port := int(in[0]["port"].(float64))
	if g.Port != port || g.Port == 0 {
		t.Fatalf("reported port = %d, inbound port = %d", g.Port, port)
	}
	pinned, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", WSPort: 10080})
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Port != 10080 {
		t.Fatalf("pinned reported port = %d", pinned.Port)
	}
}

func TestGenerateRealityNginxFrontsBackendPort(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeRealityNginx, Domain: "example.com", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	if g.Port != 9443 || g.PublicPort != 8443 {
		t.Fatalf("ports: inbound=%d public=%d", g.Port, g.PublicPort)
	}
	in := multiInbounds(t, g)
	if len(in) != 1 || in[0]["port"].(float64) != 9443 {
		t.Fatalf("reality inbound must stay on 9443: %v", in)
	}
	for _, needle := range []string{
		"include /etc/idleleo/conf/nginx/*.serverNames;",
		"include /etc/idleleo/conf/nginx/*.realityServers;",
		"listen 8443 reuseport so_keepalive=on backlog=65535;",
		"ssl_preread on;",
		"default deny;",
		"server 127.0.0.1:9403;",
	} {
		if !strings.Contains(g.NginxConf, needle) {
			t.Fatalf("stream front missing %q:\n%s", needle, g.NginxConf)
		}
	}
	if got := g.NginxFragments["127.0.0.1.realityServers"]; got != "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n" {
		t.Fatalf("realityServers fragment = %q", got)
	}
	if got := g.NginxFragments["example.com.serverNames"]; got != "example.com reality;\n" {
		t.Fatalf("serverNames fragment = %q", got)
	}
	if _, ok := g.NginxFragments["03-isolate.conf"]; !ok {
		t.Fatal("isolate site fragment missing")
	}
}

func TestGenerateMultiTransportRealityKeepsRawPrimary(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportMulti, Port: 10080})
	if err != nil {
		t.Fatal(err)
	}
	in := multiInbounds(t, g)
	if len(in) != 4 {
		t.Fatalf("reality multi expected four inbounds, got %d", len(in))
	}
	if in[0]["streamSettings"].(map[string]any)["network"] != TransportRaw {
		t.Fatalf("reality primary must stay raw: %v", in[0]["streamSettings"])
	}
	if in[0]["tag"] != "VLESS-Reality-in" {
		t.Fatalf("reality primary tag = %v", in[0]["tag"])
	}
	for _, d := range in[1:] {
		if d["listen"] != "0.0.0.0" {
			t.Fatalf("reality added inbounds must follow the primary listen address: %v", d["listen"])
		}
	}
}

func TestGenerateIPv6ShareAuthority(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.ShareURI, "@[2001:db8::1]:443") {
		t.Fatalf("ipv6 authority is not bracketed: %s", g.ShareURI)
	}
}

func TestRemoveUserKeepsUnattributableShortIDs(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	added, _, err := AddUser(g.Config, 0, AddUserSpec{
		UUID: "11111111-2222-4333-8444-555555555555", Email: "u2@idleleo", ShortID: "abcd1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	before := realityShortIDs(t, added)
	removed, _, err := RemoveUser(added, 0, "u2@idleleo")
	if err != nil {
		t.Fatal(err)
	}
	after := realityShortIDs(t, removed)
	if len(before) != len(after) {
		t.Fatalf("shortIds must not be guessed away: before=%v after=%v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("shortIds changed on removal: before=%v after=%v", before, after)
		}
	}
	if ShortIDRemovalNotice(removed, 0) == "" {
		t.Fatal("removal must explain that inbound-level shortIds were retained")
	}
}

func realityShortIDs(t *testing.T, raw []byte) []string {
	t.Helper()
	root, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	in, err := inboundAt(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	stream, _ := in["streamSettings"].(map[string]any)
	reality, _ := stream["realitySettings"].(map[string]any)
	ids, _ := reality["shortIds"].([]any)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if s, ok := id.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestUserLifecyclePreservesCustomFields(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	raw := g.Config
	added, view, err := AddUser(raw, 0, AddUserSpec{UUID: "11111111-2222-4333-8444-555555555555", Email: "u2@idleleo", Flow: "xtls-rprx-vision"})
	if err != nil {
		t.Fatal(err)
	}
	if view.Primary || view.UUID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("unexpected user view: %+v", view)
	}
	users, err := ListUsers(added, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[1].Email != "u2@idleleo" {
		t.Fatalf("unexpected users: %+v", users)
	}
	var before, after map[string]any
	_ = json.Unmarshal(raw, &before)
	_ = json.Unmarshal(added, &after)
	if _, ok := after["routing"]; !ok {
		t.Fatal("routing was dropped")
	}
	if _, ok := before["dns"]; !ok {
		t.Fatal("dns missing in original fixture")
	}
	if _, _, err := RemoveUser(added, 0, "me@hey.run"); err == nil {
		t.Fatal("primary user removal must be refused")
	}
	removed, _, err := RemoveUser(added, 0, "u2@idleleo")
	if err != nil {
		t.Fatal(err)
	}
	users, _ = ListUsers(removed, 0)
	if len(users) != 1 || !users[0].Primary {
		t.Fatalf("primary user lost after removal: %+v", users)
	}
}

func TestA1HostnameValidation(t *testing.T) {
	bad := []string{"bad host", "../escape", "host/name", "a b.example.com"}
	for _, domain := range bad {
		if _, err := Generate(Spec{Mode: ModeTLS, Domain: domain}); err == nil {
			t.Fatalf("tls domain %q must be rejected", domain)
		}
		if _, err := Generate(Spec{Mode: ModeNone, Domain: domain}); err == nil {
			t.Fatalf("none domain %q must be rejected", domain)
		}
	}
	good := []string{"example.com", "sub.example.com", "203.0.113.9", "2001:db8::1"}
	for _, domain := range good {
		if _, err := Generate(Spec{Mode: ModeTLS, Domain: domain}); err != nil {
			t.Fatalf("tls domain %q must be accepted: %v", domain, err)
		}
	}
	if _, err := Generate(Spec{Mode: ModeReality, ServerNames: []string{"bad/name"}}); err == nil {
		t.Fatal("invalid reality server name must be rejected")
	}
}

func TestA1BindIPv4IPv6(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		listen  string
		allow   bool
		wantErr bool
	}{
		{"reality ipv4 any", ModeReality, "0.0.0.0", false, false},
		{"reality ipv6 any", ModeReality, "::", false, false},
		{"reality ipv6 loopback", ModeReality, "::1", false, false},
		{"tls ipv4 any", ModeTLS, "0.0.0.0", false, false},
		{"none ipv6 loopback", ModeNone, "::1", false, false},
		{"none ipv6 global denied", ModeNone, "2001:db8::1", false, true},
		{"none ipv6 global allowed", ModeNone, "2001:db8::1", true, false},
	}
	for _, tc := range cases {
		spec := Spec{Mode: tc.mode, Domain: "example.com", Listen: tc.listen, AllowNonLoopback: tc.allow}
		g, err := Generate(spec)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected refusal for %s", tc.name, tc.listen)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		in := multiInbounds(t, g)[0]
		if in["listen"] != tc.listen {
			t.Fatalf("%s: listen = %v, want %s", tc.name, in["listen"], tc.listen)
		}
	}
}

func TestA1UserScaleOneFourTwenty(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	raw := g.Config
	for _, want := range []int{1, 4, 20} {
		for i := len(mustList(t, raw)) + 1; i <= want; i++ {
			uid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
			raw, _, err = AddUser(raw, 0, AddUserSpec{UUID: uid, Email: fmt.Sprintf("u%d@example.com", i)})
			if err != nil {
				t.Fatalf("add user %d: %v", i, err)
			}
		}
		if got := len(mustList(t, raw)); got != want {
			t.Fatalf("user count = %d, want %d", got, want)
		}
	}
	info, err := ShareConfig(raw, ShareOptions{Host: "example.com", PublicPort: 443,
		PublicSecurity: "tls", User: "u20@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.ShareURI, "00000000-0000-4000-8000-000000000020") {
		t.Fatalf("share for user 20 lost its uuid: %s", info.ShareURI)
	}
}

func mustList(t *testing.T, raw []byte) []UserView {
	t.Helper()
	users, err := ListUsers(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	return users
}

func TestUserRejectsDuplicate(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddUser(g.Config, 0, AddUserSpec{UUID: g.UUID}); err == nil {
		t.Fatal("duplicate uuid must be refused")
	}
}

func TestAdoptRuntimePreservesEveryValue(t *testing.T) {
	raw := []byte(`{"log":{"loglevel":"warning"},"inbounds":[` +
		`{"tag":"custom-in","listen":"127.0.0.1","port":10805,"protocol":"vless",` +
		`"settings":{"clients":[{"id":"7a4ab30c-b199-4840-a31e-316f4f73a72b","flow":"xtls-rprx-vision"}],"decryption":"none"},` +
		`"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/custom-path"}}},` +
		`{"tag":"r2","listen":"::","port":9443,"protocol":"vless","settings":{"clients":[{"id":"f0ca9bf0-07d9-44c0-9371-035e4160aa2b"}]},` +
		`"streamSettings":{"network":"raw","security":"reality","realitySettings":{"privateKey":"` + testRealityKey(t) + `","shortIds":["abcd"],"serverNames":["example.com"]}}}` +
		`],"outbounds":[{"protocol":"freedom"}],"customField":{"keep":true}}`)
	adopted, err := AdoptRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	_ = json.Unmarshal(raw, &before)
	_ = json.Unmarshal(adopted, &after)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("adoption changed values:\nbefore=%v\nafter=%v", before, after)
	}
	if !strings.Contains(string(adopted), `"path": "/custom-path"`) || !strings.Contains(string(adopted), `"port": 10805`) {
		t.Fatalf("adoption lost explicit values: %s", adopted)
	}
}

func testRealityKey(t *testing.T) string {
	t.Helper()
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return g.PrivateKey
}

func TestAdoptRuntimeRefusesUnusableConfig(t *testing.T) {
	bad := []string{
		`{"inbounds":[]}`,
		`{"inbounds":[{"port":0,"protocol":"vless"}]}`,
		`{"inbounds":[{"port":443,"protocol":"vless"},{"port":443,"protocol":"vless"}]}`,
		`{"inbounds":[{"port":443,"protocol":"vless","tag":"x"},{"port":8443,"protocol":"vless","tag":"x"}]}`,
		`{"inbounds":[{"port":443,"protocol":"vless","settings":{"clients":[{"id":"not-a-uuid"}]}}]}`,
		`{"inbounds":[{"port":443,"protocol":"vless","streamSettings":{"security":"bogus"}}]}`,
		`{"inbounds":[{"port":443,"protocol":"vless","streamSettings":{"network":"raw","security":"reality","realitySettings":{"privateKey":"short"}}}]}`,
	}
	for _, raw := range bad {
		if _, err := AdoptRuntime([]byte(raw)); err == nil {
			t.Fatalf("adoption must refuse %s", raw)
		}
	}
}

func TestShareFromExistingConfig(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Share(g.Config, 0, "example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != ModeReality || s.ShareURI != g.ShareURI {
		t.Fatalf("share mismatch:\n got %s\nwant %s", s.ShareURI, g.ShareURI)
	}
}

func TestGenerateRealityBalancePrimary(t *testing.T) {
	g, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
		ServerNames: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if g.BalanceRole != BalanceRolePrimary {
		t.Fatalf("balance role = %q", g.BalanceRole)
	}
	if g.Port != 9443 || g.PublicPort != 8443 {
		t.Fatalf("primary ports: inbound=%d public=%d", g.Port, g.PublicPort)
	}
	in := multiInbounds(t, g)
	if len(in) != 1 {
		t.Fatalf("primary must have one backend inbound, got %d", len(in))
	}
	if in[0]["port"].(float64) != 9443 || in[0]["listen"] != "0.0.0.0" {
		t.Fatalf("primary backend must be 9443/0.0.0.0: %v", in[0])
	}
	for _, needle := range []string{
		"include /etc/idleleo/conf/nginx/*.serverNames;",
		"include /etc/idleleo/conf/nginx/*.realityServers;",
		"listen 8443 reuseport so_keepalive=on backlog=65535;",
		"ssl_preread on;",
		"default deny;",
		"server 127.0.0.1:9403;",
		`TLSv1.3    1;`,
	} {
		if !strings.Contains(g.NginxConf, needle) {
			t.Fatalf("nginx conf missing %q:\n%s", needle, g.NginxConf)
		}
	}
	if got := g.NginxFragments["127.0.0.1.realityServers"]; got != "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n" {
		t.Fatalf("realityServers fragment = %q", got)
	}
	if got := g.NginxFragments["example.com.serverNames"]; got != "example.com reality;\n" {
		t.Fatalf("serverNames fragment = %q", got)
	}
	if _, ok := g.NginxFragments["03-isolate.conf"]; !ok {
		t.Fatal("isolate site fragment missing")
	}
}

func TestGenerateRealityBalanceSecondary(t *testing.T) {
	g, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRoleSecondary, Port: 8443,
		ServerNames: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if g.Port != 8443 || g.PublicPort != 8443 || g.Listen != "0.0.0.0" {
		t.Fatalf("secondary ports: %d/%d/%s", g.Port, g.PublicPort, g.Listen)
	}
	in := multiInbounds(t, g)
	if len(in) != 1 || in[0]["port"].(float64) != 8443 {
		t.Fatalf("secondary inbound must use the public port: %v", in)
	}
	if g.NginxConf != "" || len(g.NginxFragments) != 0 {
		t.Fatal("secondary must not generate a Nginx front")
	}
}

// TestGenerateRejectsReservedPublicPort pins the front-port guard: an explicit
// --public-port equal to the Reality internal ports would make Nginx listen on
// the same port as the Xray backend / SNI guard and fail at bind time.
func TestGenerateRejectsReservedPublicPort(t *testing.T) {
	for _, port := range []int{9403, 9404, 9443, 9444} {
		if _, err := Generate(Spec{
			Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
			PublicPort: port, ServerNames: []string{"example.com"},
		}); err == nil || !strings.Contains(err.Error(), "public port") {
			t.Fatalf("balance primary public port %d must be refused: %v", port, err)
		}
		if _, err := Generate(Spec{
			Mode: ModeRealityNginx, Domain: "example.com", Port: 8443, PublicPort: port,
		}); err == nil || !strings.Contains(err.Error(), "public port") {
			t.Fatalf("reality-nginx public port %d must be refused: %v", port, err)
		}
	}
	if _, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
		PublicPort: 8444, ServerNames: []string{"example.com"},
	}); err != nil {
		t.Fatalf("a normal public port must keep working: %v", err)
	}
	// A secondary has no Nginx front; --public-port only shapes the client view.
	if _, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRoleSecondary, Port: 8443,
		PublicPort: 9443, ServerNames: []string{"example.com"},
	}); err != nil {
		t.Fatalf("secondary public port must not be rejected: %v", err)
	}
}

func TestGenerateRealityBalanceBackendsAndRefusals(t *testing.T) {
	g, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
		ServerNames: []string{"example.com"},
		Backends:    []string{"127.0.0.1:9443", "10.0.0.2:9443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Bash keeps one fragment per host: the local front line stays alone and the
	// added backend gets its own file.
	if got, want := g.NginxFragments["127.0.0.1.realityServers"], "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n"; got != want {
		t.Fatalf("local fragment = %q, want %q", got, want)
	}
	if got, want := g.NginxFragments["10.0.0.2.realityServers"], "server 10.0.0.2:9443 weight=50 max_fails=2 fail_timeout=10;\n"; got != want {
		t.Fatalf("added backend fragment = %q, want %q", got, want)
	}
	if _, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
		ServerNames: []string{"example.com"},
		Backends:    []string{"10.0.0.2:9443", "10.0.0.2:9444"},
	}); err == nil || !strings.Contains(err.Error(), "one file per host") {
		t.Fatalf("two ports on one host must be refused: %v", err)
	}
	for _, backend := range []string{"10.0.0.2/../etc:9443", "bad host:9443", "10.0.0..2:9443"} {
		if _, err := Generate(Spec{
			Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
			ServerNames: []string{"example.com"}, Backends: []string{backend},
		}); err == nil {
			t.Fatalf("backend %q must be refused", backend)
		}
	}
	if _, err := Generate(Spec{Mode: ModeRealityBalance, Port: 8443, ServerNames: []string{"example.com"}}); err == nil {
		t.Fatal("role must be required")
	}
	if _, err := Generate(Spec{Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 9443, ServerNames: []string{"example.com"}}); err == nil {
		t.Fatal("reserved port must be refused")
	}
	if _, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRoleSecondary, Port: 8443,
		ServerNames: []string{"example.com"}, Backends: []string{"10.0.0.2:9443"},
	}); err == nil {
		t.Fatal("secondary backends must be refused")
	}
	if _, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
		ServerNames: []string{"example.com"}, UnknownSNIPolicy: "decoy",
	}); err == nil {
		t.Fatal("decoy policy must be refused by the generator")
	}
}

// TestRealitySingleTransportKeepsRealityPrimary pins the Bash parity rule:
// adding a single transport to a Reality node appends it on the next port while
// Reality remains the primary raw inbound.
func TestRealitySingleTransportKeepsRealityPrimary(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeReality, Transport: TransportWS, Domain: "example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(g.Config, &root); err != nil {
		t.Fatalf("generated config is not JSON: %v", err)
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("expected two inbounds, got %v", root["inbounds"])
	}
	primary := inbounds[0].(map[string]any)
	if sec := primary["streamSettings"].(map[string]any)["security"]; sec != "reality" {
		t.Fatalf("primary inbound security = %v, want reality", sec)
	}
	added := inbounds[1].(map[string]any)
	stream := added["streamSettings"].(map[string]any)
	if stream["network"] != TransportWS {
		t.Fatalf("added inbound network = %v, want ws", stream["network"])
	}
	if port := added["port"].(float64); port < extraPortMin || port > extraPortMax {
		t.Fatalf("added inbound port = %v, want a port from the Bash ws pool %d-%d", port, extraPortMin, extraPortMax)
	}
	if g.Transport != TransportWS {
		t.Fatalf("generated transport = %q, want ws", g.Transport)
	}
	if !strings.Contains(g.ShareURI, "security=reality") {
		t.Fatalf("share URI lost reality security: %s", g.ShareURI)
	}
}

func stubCanBind(t *testing.T, fn func(addr string, port int) bool) {
	t.Helper()
	old := canBindTCP
	canBindTCP = fn
	t.Cleanup(func() { canBindTCP = old })
}

func portsByTransport(t *testing.T, g Generated) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, in := range multiInbounds(t, g) {
		network := in["streamSettings"].(map[string]any)["network"].(string)
		out[network] = int(in["port"].(float64))
	}
	return out
}

func TestExtraPortsUseBashPools(t *testing.T) {
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportMulti})
	if err != nil {
		t.Fatal(err)
	}
	ports := portsByTransport(t, g)
	for _, transport := range []string{TransportWS, TransportGRPC} {
		if ports[transport] < extraPortMin || ports[transport] > extraPortMax {
			t.Fatalf("%s port %d outside the Bash pool %d-%d", transport, ports[transport], extraPortMin, extraPortMax)
		}
	}
	if ports[TransportXHTTP] < xhttpPortMin || ports[TransportXHTTP] > xhttpPortMax {
		t.Fatalf("xhttp port %d outside the Bash pool %d-%d", ports[TransportXHTTP], xhttpPortMin, xhttpPortMax)
	}
	if ports[TransportWS] == ports[TransportGRPC] {
		t.Fatalf("ws and grpc must not share a port: %v", ports)
	}
}

func TestExtraPortsSkipBusyCandidates(t *testing.T) {
	stubCanBind(t, func(_ string, port int) bool { return port > 10002 })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS})
	if err != nil {
		t.Fatal(err)
	}
	ports := portsByTransport(t, g)
	if ports[TransportWS] != 10003 {
		t.Fatalf("ws port = %d, want 10003 after skipping 10000-10002", ports[TransportWS])
	}
	found := false
	for _, w := range g.Warnings {
		if strings.Contains(w, "10000") && strings.Contains(w, "in use") {
			found = true
		}
	}
	if !found {
		t.Fatalf("busy candidates must be reported, warnings = %v", g.Warnings)
	}
}

func TestExtraPortsHonourExplicitOverrides(t *testing.T) {
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportMulti,
		WSPort: 12345, GRPCPort: 12346, XHTTPPort: 12347})
	if err != nil {
		t.Fatal(err)
	}
	ports := portsByTransport(t, g)
	if ports[TransportWS] != 12345 || ports[TransportGRPC] != 12346 || ports[TransportXHTTP] != 12347 {
		t.Fatalf("explicit ports not honoured: %v", ports)
	}
}

func TestExtraPortsRejectBusyDuplicateAndReservedExplicit(t *testing.T) {
	stubCanBind(t, func(_ string, port int) bool { return port != 12345 })
	if _, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS, WSPort: 12345}); err == nil ||
		!strings.Contains(err.Error(), "in use") {
		t.Fatalf("busy explicit port must fail with an in-use error, got %v", err)
	}
	if _, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS, WSPort: 443}); err == nil ||
		!strings.Contains(err.Error(), "already used") {
		t.Fatalf("duplicate explicit port must fail, got %v", err)
	}
	if _, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS, WSPort: 9443}); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved explicit port must fail, got %v", err)
	}
	if _, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS, WSPort: 70000}); err == nil ||
		!strings.Contains(err.Error(), "between 1 and 65535") {
		t.Fatalf("out-of-range explicit port must fail, got %v", err)
	}
}

func TestExtraPortsDoNotWrapAt65535(t *testing.T) {
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS, Port: 65535})
	if err != nil {
		t.Fatal(err)
	}
	if port := portsByTransport(t, g)[TransportWS]; port < extraPortMin || port > extraPortMax {
		t.Fatalf("ws port = %d, want a pool port instead of wrapping to 1", port)
	}
}
