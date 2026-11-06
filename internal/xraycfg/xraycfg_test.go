package xraycfg

import (
	"encoding/json"
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
