package xraycfg

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

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

func TestGenerateMultiTransportTLSRoutesEachInbound(t *testing.T) {
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", Transport: TransportMulti, Port: 10080})
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
	g, err := Generate(Spec{Mode: ModeTLS, Domain: "example.com", Transport: TransportWS, Port: 10080})
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
	s, err := Share(g.Config, 0, "", 0)
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

func TestGenerateRealityBalanceBackendsAndRefusals(t *testing.T) {
	g, err := Generate(Spec{
		Mode: ModeRealityBalance, BalanceRole: BalanceRolePrimary, Port: 8443,
		ServerNames: []string{"example.com"},
		Backends:    []string{"127.0.0.1:9443", "10.0.0.2:9443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n" +
		"server 10.0.0.2:9443 weight=50 max_fails=2 fail_timeout=10;\n"
	if got := g.NginxFragments["127.0.0.1.realityServers"]; got != want {
		t.Fatalf("multi-backend fragment = %q", got)
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
