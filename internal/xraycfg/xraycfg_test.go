package xraycfg

import (
	"encoding/json"
	"fmt"
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
	for _, needle := range []string{"proxy_pass http://127.0.0.1:10080;", "grpc_pass grpc://127.0.0.1:10081;", "location /xhttp/"} {
		if !strings.Contains(g.NginxConf, needle) {
			t.Fatalf("nginx snippet missing %q:\n%s", needle, g.NginxConf)
		}
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
