package xraycfg

import (
	"encoding/json"
	"strings"
	"testing"
)

func editBase(t *testing.T) []byte {
	t.Helper()
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS})
	if err != nil {
		t.Fatal(err)
	}
	return g.Config
}

func editInbounds(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := []map[string]any{}
	for _, in := range asSlice(root["inbounds"]) {
		out = append(out, asMap(in))
	}
	return out
}

func directTLSBase(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "tag": "vless-ws-tls",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {"clients": [{"id": "7a4ab30c-b199-4840-a31e-316f4f73a72b"}], "decryption": "none"},
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "example.com",
          "certificates": [{"certificateFile": "/etc/idleleo/cert/xray.crt", "keyFile": "/etc/idleleo/cert/xray.key"}]
        },
        "wsSettings": {"path": "/e2e"}
      }
    }
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "routing": {"rules": [{"type": "field", "domain": ["keep.example"], "outboundTag": "direct"}]}
}`)
}

func directTLSPaths(t *testing.T, raw []byte) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	in := asMap(asSlice(root["inbounds"])[0])
	stream := asMap(in["streamSettings"])
	tls := asMap(stream["tlsSettings"])
	tls["wsSettings"] = asMap(stream["wsSettings"])
	return in, tls, root
}

func TestPatchDirectTLSRotatesOnlyThePair(t *testing.T) {
	raw := directTLSBase(t)
	patch, err := PatchDirectTLS(raw, EditRequest{
		CertFile: "/etc/idleleo/cert/new.crt", KeyFile: "/etc/idleleo/cert/new.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, tls, root := directTLSPaths(t, patch.Config)
	cert := asMap(asSlice(tls["certificates"])[0])
	if asString(cert["certificateFile"]) != "/etc/idleleo/cert/new.crt" ||
		asString(cert["keyFile"]) != "/etc/idleleo/cert/new.key" {
		t.Fatalf("pair not rotated: %v", cert)
	}
	if got := asString(asMap(tls["wsSettings"])["path"]); got != "/e2e" {
		t.Fatalf("ws path drifted: %q", got)
	}
	rules := asSlice(asMap(root["routing"])["rules"])
	if len(rules) != 1 {
		t.Fatalf("routing rules drifted: %v", rules)
	}
	if len(patch.Changed) != 2 || patch.Changed[0] != "cert-file" || patch.Changed[1] != "cert-key-file" {
		t.Fatalf("changed = %v", patch.Changed)
	}
}

func TestPatchDirectTLSUpdatesExistingServerName(t *testing.T) {
	raw := directTLSBase(t)
	patch, err := PatchDirectTLS(raw, EditRequest{Domain: "new.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, tls, _ := directTLSPaths(t, patch.Config)
	if got := asString(tls["serverName"]); got != "new.example.com" {
		t.Fatalf("serverName = %q", got)
	}
	if len(patch.Changed) != 1 || patch.Changed[0] != "domain" {
		t.Fatalf("changed = %v", patch.Changed)
	}
}

func TestPatchDirectTLSMovesListener(t *testing.T) {
	raw := directTLSBase(t)
	patch, err := PatchDirectTLS(raw, EditRequest{Listen: "127.0.0.1", Port: 8443})
	if err != nil {
		t.Fatal(err)
	}
	in, _, _ := directTLSPaths(t, patch.Config)
	if asString(in["listen"]) != "127.0.0.1" || asInt(in["port"]) != 8443 {
		t.Fatalf("listener = %v %v", in["listen"], in["port"])
	}
	if patch.Port != 8443 || patch.Listen != "127.0.0.1" {
		t.Fatalf("patch result = %+v", patch)
	}
}

func TestPatchDirectTLSNoChanges(t *testing.T) {
	raw := directTLSBase(t)
	patch, err := PatchDirectTLS(raw, EditRequest{
		Domain: "example.com", CertFile: "/etc/idleleo/cert/xray.crt",
		KeyFile: "/etc/idleleo/cert/xray.key", Listen: "0.0.0.0", Port: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(patch.Changed) != 0 {
		t.Fatalf("identical values must not report changes: %v", patch.Changed)
	}
}

func TestPatchDirectTLSRejectsPartialPair(t *testing.T) {
	if _, err := PatchDirectTLS(directTLSBase(t), EditRequest{CertFile: "/etc/idleleo/cert/new.crt"}); err == nil ||
		!strings.Contains(err.Error(), "both --cert and --cert-key") {
		t.Fatalf("a lone --cert must be refused, got %v", err)
	}
}

func TestPatchDirectTLSRejectsGeneratedFields(t *testing.T) {
	_, err := PatchDirectTLS(directTLSBase(t), EditRequest{Transport: TransportWS})
	if err == nil || !strings.Contains(err.Error(), "direct TLS supports only") {
		t.Fatalf("generated-mode fields must be refused, got %v", err)
	}
}

func TestPatchDirectTLSRejectsNonTLSConfig(t *testing.T) {
	_, err := PatchDirectTLS(editBase(t), EditRequest{Domain: "example.com"})
	if err == nil || !strings.Contains(err.Error(), "no direct TLS inbound") {
		t.Fatalf("a Reality config must be refused, got %v", err)
	}
}

func TestPatchDirectTLSRejectsMultiInboundPortMove(t *testing.T) {
	raw := directTLSBase(t)
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	inbounds := asSlice(root["inbounds"])
	second := asMap(inbounds[0])
	second["port"] = 8443
	root["inbounds"] = append(inbounds, second)
	multi, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = PatchDirectTLS(multi, EditRequest{Port: 9443})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("multi-inbound port move must be refused, got %v", err)
	}
	if _, err := PatchDirectTLS(multi, EditRequest{CertFile: "/a.crt", KeyFile: "/a.key"}); err != nil {
		t.Fatalf("pair rotation must still support several TLS inbounds: %v", err)
	}
}

func TestEditRuntimeDirectTLSResult(t *testing.T) {
	g, res, err := EditRuntime(directTLSBase(t), EditDefaults{Mode: ModeTLSDirect},
		EditRequest{CertFile: "/etc/idleleo/cert/new.crt", KeyFile: "/etc/idleleo/cert/new.key"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeTLSDirect || res.Transport != TransportWS || !res.Disconnect || res.NoChanges {
		t.Fatalf("result = %+v", res)
	}
	if res.Domain != "example.com" || res.Port != 443 {
		t.Fatalf("effective values = %+v", res)
	}
	if !strings.Contains(g.ShareURI, "example.com") {
		t.Fatalf("share link not rebuilt: %q", g.ShareURI)
	}
}

func TestEditRuntimeDirectTLSNoChanges(t *testing.T) {
	raw := directTLSBase(t)
	_, res, err := EditRuntime(raw, EditDefaults{Mode: ModeTLSDirect}, EditRequest{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoChanges || res.Disconnect {
		t.Fatalf("identical domain must be a no-op: %+v", res)
	}
}

func TestEditUUIDKeepsEveryOtherValue(t *testing.T) {
	raw := editBase(t)
	before := editInbounds(t, raw)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{UUID: "11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatal(err)
	}
	if res.NoChanges || !res.Disconnect {
		t.Fatalf("uuid edit must report a disconnect-prone change: %+v", res)
	}
	after := editInbounds(t, g.Config)
	if len(after) != len(before) {
		t.Fatalf("inbound count changed: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if asInt(before[i]["port"]) != asInt(after[i]["port"]) {
			t.Fatalf("inbound %d port drifted: %v -> %v", i, before[i]["port"], after[i]["port"])
		}
		if asString(before[i]["listen"]) != asString(after[i]["listen"]) {
			t.Fatalf("inbound %d listen drifted", i)
		}
		bs := asMap(before[i]["streamSettings"])
		as := asMap(after[i]["streamSettings"])
		if asString(asMap(bs["realitySettings"])["privateKey"]) != asString(asMap(as["realitySettings"])["privateKey"]) {
			t.Fatalf("inbound %d reality key drifted", i)
		}
		if asString(asMap(bs["wsSettings"])["path"]) != asString(asMap(as["wsSettings"])["path"]) {
			t.Fatalf("inbound %d ws path drifted", i)
		}
	}
	client := asMap(asSlice(asMap(after[0]["settings"])["clients"])[0])
	if asString(client["id"]) != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("uuid not applied: %v", client["id"])
	}
	if !strings.Contains(g.ShareURI, "11111111-2222-3333-4444-555555555555") {
		t.Fatalf("share link not regenerated: %s", g.ShareURI)
	}
}

func TestEditPortOnlyTouchesPort(t *testing.T) {
	raw := editBase(t)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443}, EditRequest{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Disconnect {
		t.Fatalf("port edit must be marked disconnect-prone")
	}
	if got := asInt(editInbounds(t, g.Config)[0]["port"]); got != 8080 {
		t.Fatalf("port = %d, want 8080", got)
	}
	// A direct Reality install has no front: with no recorded public port the
	// listen port is also the port clients dial, so the new link must use it.
	g2, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality}, EditRequest{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	info, err := Share(g2.Config, 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.Port != 8080 {
		t.Fatalf("share port = %d, want the edited port 8080", info.Port)
	}
}

func TestEditTransportRebuildsInbounds(t *testing.T) {
	raw := editBase(t)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{Transport: TransportGRPC})
	if err != nil {
		t.Fatal(err)
	}
	if res.Transport != TransportGRPC || !res.Disconnect {
		t.Fatalf("transport edit result = %+v", res)
	}
	in := editInbounds(t, g.Config)
	if len(in) != 2 {
		t.Fatalf("reality+grpc must keep the raw inbound and add grpc, got %d", len(in))
	}
	if got := asString(asMap(asMap(in[1]["streamSettings"])["grpcSettings"])["serviceName"]); got == "" {
		t.Fatalf("grpc inbound lost its service name")
	}
	// The Reality identity must survive a transport change.
	oldClient := asMap(asSlice(asMap(editInbounds(t, raw)[0]["settings"])["clients"])[0])
	newClient := asMap(asSlice(asMap(in[0]["settings"])["clients"])[0])
	if asString(oldClient["id"]) != asString(newClient["id"]) {
		t.Fatalf("transport edit changed the UUID")
	}
}

func TestEditTargetAndServerNames(t *testing.T) {
	raw := editBase(t)
	g, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{Target: "www.example.org:443", ServerNames: []string{"www.example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	rs := asMap(asMap(editInbounds(t, g.Config)[0]["streamSettings"])["realitySettings"])
	if asString(rs["target"]) != "www.example.org:443" {
		t.Fatalf("target = %v", rs["target"])
	}
	names := asSlice(rs["serverNames"])
	if len(names) != 1 || asString(names[0]) != "www.example.org" {
		t.Fatalf("serverNames = %v", rs["serverNames"])
	}
}

func TestEditRefusesUnknownTopLevelChanges(t *testing.T) {
	raw := editBase(t)
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	root["custom-tag"] = "keep-me"
	patched, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EditRuntime(patched, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{Port: 8080}); err == nil || !strings.Contains(err.Error(), "custom-tag") {
		t.Fatalf("unknown top-level field must block the edit, got %v", err)
	}
}

func TestEditRefusesMultiUserUUID(t *testing.T) {
	raw := editBase(t)
	root, _ := parseRuntime(raw)
	in := asMap(asSlice(root["inbounds"])[0])
	settings := asMap(in["settings"])
	clients := asSlice(settings["clients"])
	clone, _ := json.Marshal(clients[0])
	var second map[string]any
	if err := json.Unmarshal(clone, &second); err != nil {
		t.Fatal(err)
	}
	second["id"] = "99999999-2222-3333-4444-555555555555"
	settings["clients"] = append(clients, second)
	patched, _ := json.Marshal(root)
	if _, _, err := EditRuntime(patched, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{UUID: "11111111-2222-3333-4444-555555555555"}); err == nil {
		t.Fatalf("a single-uuid regeneration must not silently drop extra users")
	}
}

func TestEditMultiUserUUIDPointsAtUserCommand(t *testing.T) {
	raw := editBase(t)
	root, _ := parseRuntime(raw)
	in := asMap(asSlice(root["inbounds"])[0])
	settings := asMap(in["settings"])
	clients := asSlice(settings["clients"])
	primaryEmail := asString(asMap(clients[0])["email"])
	clone, _ := json.Marshal(clients[0])
	var second map[string]any
	if err := json.Unmarshal(clone, &second); err != nil {
		t.Fatal(err)
	}
	second["id"] = "99999999-2222-3333-4444-555555555555"
	second["email"] = "user-b@idleleo"
	settings["clients"] = append(clients, second)
	patched, _ := json.Marshal(root)
	_, _, err := EditRuntime(patched, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{UUID: "11111111-2222-3333-4444-555555555555"})
	if err == nil {
		t.Fatal("multi-user config must refuse a global uuid rewrite")
	}
	// The message must be actionable, not a vague pointer to another command.
	for _, want := range []string{"idleleo xray user uuid --email " + primaryEmail,
		"--new-uuid 11111111-2222-3333-4444-555555555555", "would drop them"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestEditRejectsFrontOwnedFields(t *testing.T) {
	raw := editBase(t)
	if _, _, err := EditRuntime(raw, EditDefaults{Mode: ModeRealityNginx, PublicPort: 443},
		EditRequest{Listen: "127.0.0.1"}); err == nil || !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("nginx-front listen edit must be rejected, got %v", err)
	}
	if _, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{Target: "example.com:443"}); err != nil {
		// reality target is legal; only non-reality must fail
		t.Fatal(err)
	}
	spec := Spec{Mode: ModeTLS, Transport: TransportWS}
	if _, err := applyEditRequest(&spec, EditDefaults{Mode: ModeTLS}, EditRequest{Target: "example.com:443"}); err == nil ||
		!strings.Contains(err.Error(), "Reality") {
		t.Fatalf("target edit outside reality must be rejected, got %v", err)
	}
}

func TestEditNoOpWhenNothingRequested(t *testing.T) {
	raw := editBase(t)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443}, EditRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoChanges {
		t.Fatalf("empty request must be a no-op: %+v", res)
	}
	before, _ := parseRuntime(raw)
	after, _ := parseRuntime(g.Config)
	if b, _ := json.Marshal(before); string(b) != string(mustMarshal(after)) {
		t.Fatalf("no-op edit rewrote the config")
	}
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func editTLSBase(t *testing.T) ([]byte, EditDefaults) {
	t.Helper()
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{
		Mode: ModeTLS, Transport: TransportWS, Domain: "example.com",
		Port: 10080, WSPort: 10080, PublicPort: 8443,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g.Config, EditDefaults{
		Mode: ModeTLS, PublicPort: 8443, Domain: "example.com",
		CertFile: DefaultCertFile, KeyFile: DefaultKeyFile,
	}
}

func TestEditTLSDomainRewritesNginxWithoutRuntimeDiff(t *testing.T) {
	raw, base := editTLSBase(t)
	g, res, err := EditRuntime(raw, base, EditRequest{Domain: "new.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if res.NoChanges {
		t.Fatalf("a domain edit must not be reported as no-op: %+v", res)
	}
	if res.Domain != "new.example.com" {
		t.Fatalf("domain = %q", res.Domain)
	}
	if len(res.Diff) != 0 {
		t.Fatalf("the TLS domain is front-owned; runtime diff = %v", res.Diff)
	}
	if !strings.Contains(g.NginxConf, "server_name           new.example.com;") {
		t.Fatalf("nginx server_name not rewritten:\n%s", g.NginxConf)
	}
	if !strings.Contains(g.NginxConf, DefaultCertFile) || !strings.Contains(g.NginxConf, DefaultKeyFile) {
		t.Fatal("a domain edit must keep the configured certificate pair")
	}
	if diff, err := diffRuntime(raw, g.Config); err != nil || len(diff) != 0 {
		t.Fatalf("runtime config changed: diff=%v err=%v", diff, err)
	}
}

func TestEditTLSCertificatePairIsAFrontOwnedChange(t *testing.T) {
	raw, base := editTLSBase(t)
	g, res, err := EditRuntime(raw, base, EditRequest{
		CertFile: "/etc/idleleo/cert/example.com.crt", KeyFile: "/etc/idleleo/cert/example.com.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.NoChanges {
		t.Fatalf("a certificate edit must rewrite Nginx: %+v", res)
	}
	if !strings.Contains(g.NginxConf, "ssl_certificate       /etc/idleleo/cert/example.com.crt;") {
		t.Fatalf("certificate path not applied:\n%s", g.NginxConf)
	}
	if !strings.Contains(g.NginxConf, "ssl_certificate_key   /etc/idleleo/cert/example.com.key;") {
		t.Fatalf("key path not applied:\n%s", g.NginxConf)
	}
	if res.CertFile != "/etc/idleleo/cert/example.com.crt" || res.KeyFile != "/etc/idleleo/cert/example.com.key" {
		t.Fatalf("effective pair = %q %q", res.CertFile, res.KeyFile)
	}
}

func TestEditTLSNoOpWhenValuesMatch(t *testing.T) {
	raw, base := editTLSBase(t)
	_, res, err := EditRuntime(raw, base, EditRequest{Domain: "example.com", CertFile: DefaultCertFile})
	if err != nil {
		t.Fatal(err)
	}
	if !res.NoChanges {
		t.Fatalf("repeating the live values must be a no-op: %+v", res)
	}
}

func TestEditRejectsTLSOwnedFieldsOutsideTLSMode(t *testing.T) {
	raw := editBase(t)
	if _, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{Domain: "example.com"}); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("reality must reject --domain, got %v", err)
	}
	if _, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{CertFile: "/tmp/a.crt"}); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("reality must reject --cert, got %v", err)
	}
}
