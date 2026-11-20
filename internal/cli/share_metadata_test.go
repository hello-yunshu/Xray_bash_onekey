package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

const shareTestUUID = "00000000-0000-4000-8000-000000000001"

// loopbackNoneConfig is the Bash TLS topology: Xray listens on loopback with
// stream security=none and Nginx terminates TLS on the public port.
const loopbackNoneConfig = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{"tag": "vless-in", "listen": "127.0.0.1", "port": 10086, "protocol": "vless",
    "settings": {"clients": [{"id": "` + shareTestUUID + `", "email": "primary@example.com"}]},
    "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/ray"}}}],
  "outbounds": [{"protocol": "freedom"}]
}`

func writeShareRoot(t *testing.T, cfgBody []byte, meta *store.Metadata) (string, string) {
	t.Helper()
	root := t.TempDir()
	cfgPath := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, cfgBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		meta.SchemaVersion = store.ManagerSchemaVersion
		meta.ActiveEngine = "xray"
		meta.Role = "node"
		meta.RuntimeConfigPath = "etc/idleleo/conf/xray/config.json"
		if meta.RuntimeSHA256 == "" {
			meta.RuntimeSHA256 = store.HashBytes(cfgBody)
		}
		b, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
		if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metaPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, cfgPath
}

func shareJSON(t *testing.T, args ...string) (int, xraycfg.ShareInfo, string) {
	t.Helper()
	code, out, errOut := run(t, args...)
	var info xraycfg.ShareInfo
	if code == 0 {
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatalf("share did not emit JSON: %v: %s", err, out)
		}
	}
	return code, info, out + errOut
}

func TestXrayShareUsesMetadataForPublicTLS(t *testing.T) {
	generated, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeTLS, Transport: xraycfg.TransportWS, Domain: "example.com", Port: 10086,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, cfgPath := writeShareRoot(t, generated.Config, &store.Metadata{
		TLS: "TLS", Transport: "ws",
		Install: &store.InstallSnapshot{Port: 443, ServerNames: []string{"example.com"}},
	})
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--host", "example.com", "--json")
	if code != 0 {
		t.Fatalf("share failed: %s", raw)
	}
	if info.Mode != xraycfg.ModeTLS || !strings.Contains(info.ShareURI, "security=tls") {
		t.Fatalf("metadata TLS not applied: %+v", info)
	}
	if !strings.Contains(info.ShareURI, "sni=example.com") || !strings.Contains(info.ShareURI, ":443") {
		t.Fatalf("public host/port not applied: %s", info.ShareURI)
	}
}

func TestXrayShareUsesMetadataForReality(t *testing.T) {
	generated, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeReality, Domain: "example.com", Port: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, cfgPath := writeShareRoot(t, generated.Config, &store.Metadata{
		TLS: "Reality", Transport: "tcp",
		Install: &store.InstallSnapshot{Port: 443, ServerNames: []string{"example.com"}},
	})
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--host", "198.51.100.25", "--json")
	if code != 0 {
		t.Fatalf("share failed: %s", raw)
	}
	if info.Mode != xraycfg.ModeReality || !strings.Contains(info.ShareURI, "security=reality") {
		t.Fatalf("metadata Reality not applied: %+v", info)
	}
	if info.Host != "198.51.100.25" || info.Port != 443 {
		t.Fatalf("public host/port not explicit: %+v", info)
	}
	if !strings.Contains(info.ShareURI, "@198.51.100.25:443?") ||
		!strings.Contains(info.ShareURI, "sni=example.com") {
		t.Fatalf("connection host and SNI are not separated: %s", info.ShareURI)
	}
	if strings.Contains(info.ShareURI, "@example.com") {
		t.Fatalf("Reality SNI leaked into the dial address: %s", info.ShareURI)
	}
	if !strings.Contains(info.ShareURI, "pbk=") {
		t.Fatalf("reality public key missing: %s", info.ShareURI)
	}
}

func TestXrayShareRealityRefusesToDialTheSNI(t *testing.T) {
	generated, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeReality, Domain: "www.example.com", Port: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, cfgPath := writeShareRoot(t, generated.Config, &store.Metadata{
		TLS: "Reality", Transport: "tcp",
		Install: &store.InstallSnapshot{Port: 443, ServerNames: []string{"www.example.com"}},
	})
	code, _, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath, "--json")
	if code == 0 {
		t.Fatalf("Reality share must require an explicit --host, not reuse serverNames: %s", raw)
	}
	if !strings.Contains(raw, "--host is required") {
		t.Fatalf("unexpected refusal reason: %s", raw)
	}
}

func TestXrayShareIgnoresMetadataFromAnotherRoot(t *testing.T) {
	reality, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeReality, Domain: "www.example.com", Port: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, cfgPath := writeShareRoot(t, reality.Config, nil)
	// A second root whose metadata says loopback security=none; it describes a
	// different deployment and must never be applied to the first root's config.
	otherRoot, _ := writeShareRoot(t, []byte(loopbackNoneConfig), &store.Metadata{
		TLS: "None", Transport: "ws",
		Install: &store.InstallSnapshot{Port: 10086},
	})
	code, info, raw := shareJSON(t, "--root", otherRoot, "xray", "share", "--path", cfgPath,
		"--host", "198.51.100.25", "--json")
	if code != 0 {
		t.Fatalf("foreign metadata polluted the share: %s", raw)
	}
	if info.Mode != xraycfg.ModeReality || !strings.Contains(info.ShareURI, "security=reality") {
		t.Fatalf("runtime Reality was overridden by another root's metadata: %+v", info)
	}
}

func TestXrayShareWarnsOnStaleMetadataWithoutApplyingIt(t *testing.T) {
	reality, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeReality, Domain: "www.example.com", Port: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The metadata hash no longer matches the bytes on disk (a direct edit). Its
	// public port/security must not shape the link, but share must still render
	// the runtime config instead of refusing with no way to recover.
	root, cfgPath := writeShareRoot(t, reality.Config, &store.Metadata{
		TLS: "None", Transport: "ws",
		Install:       &store.InstallSnapshot{Port: 10086},
		RuntimeSHA256: strings.Repeat("0", 64),
	})
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--host", "198.51.100.25", "--json")
	if code != 0 {
		t.Fatalf("share must still render a directly edited config: %s", raw)
	}
	if info.Mode != xraycfg.ModeReality || info.Port != 443 {
		t.Fatalf("stale metadata shaped the link: %+v", info)
	}
	found := false
	for _, w := range info.Warnings {
		if strings.Contains(w, "stale") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale metadata was not reported: %+v", info.Warnings)
	}
}

func TestXrayShareKeepsStaleLoopbackNoneAmbiguous(t *testing.T) {
	// When the only way to disambiguate is the metadata that just went stale,
	// the safe outcome is the actionable ambiguity error, never a guessed link.
	root, cfgPath := writeShareRoot(t, []byte(loopbackNoneConfig), &store.Metadata{
		TLS: "TLS", Transport: "ws",
		Install:       &store.InstallSnapshot{Port: 443},
		RuntimeSHA256: strings.Repeat("0", 64),
	})
	code, _, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--host", "example.com", "--json")
	if code == 0 {
		t.Fatalf("stale metadata must not resolve an ambiguous loopback config: %s", raw)
	}
	if !strings.Contains(raw, "--public-security") {
		t.Fatalf("expected an actionable ambiguity error: %s", raw)
	}
}

func TestXrayShareMatchesMetadataThroughNormalizedPath(t *testing.T) {
	root, _ := writeShareRoot(t, []byte(loopbackNoneConfig), &store.Metadata{
		TLS: "TLS", Transport: "ws",
		Install: &store.InstallSnapshot{Port: 443, ServerNames: []string{"example.com"}},
	})
	// Same file spelled with dot and parent segments; ownership must still match.
	weird := filepath.Join(root, "etc", ".", "idleleo/v1/../conf/xray/config.json")
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", weird,
		"--host", "example.com", "--json")
	if code != 0 {
		t.Fatalf("normalized path lost its metadata: %s", raw)
	}
	if info.Mode != xraycfg.ModeTLS || !strings.Contains(info.ShareURI, "security=tls") {
		t.Fatalf("metadata TLS not applied through normalized path: %+v", info)
	}
}

func TestXrayShareUsesMetadataToResolveLoopbackNone(t *testing.T) {
	root, cfgPath := writeShareRoot(t, []byte(loopbackNoneConfig), &store.Metadata{
		TLS: "None", Transport: "ws",
		Install: &store.InstallSnapshot{Port: 10086},
	})
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath, "--json")
	if code != 0 {
		t.Fatalf("metadata None must resolve the ambiguous loopback config: %s", raw)
	}
	if info.Mode != xraycfg.ModeNone || !strings.Contains(info.ShareURI, "security=none") {
		t.Fatalf("metadata None not applied: %+v", info)
	}
}

func TestXrayShareExplicitFlagWinsOverMetadata(t *testing.T) {
	root, cfgPath := writeShareRoot(t, []byte(loopbackNoneConfig), &store.Metadata{
		TLS: "TLS", Transport: "ws",
		Install: &store.InstallSnapshot{Port: 443, ServerNames: []string{"example.com"}},
	})
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--public-security", "none", "--public-port", "10086", "--host", "203.0.113.9", "--json")
	if code != 0 {
		t.Fatalf("explicit override failed: %s", raw)
	}
	if info.Mode != xraycfg.ModeNone || !strings.Contains(info.ShareURI, "security=none") {
		t.Fatalf("explicit --public-security lost: %+v", info)
	}
	if !strings.Contains(info.ShareURI, "203.0.113.9:10086") {
		t.Fatalf("explicit host/port lost: %s", info.ShareURI)
	}
}

func TestXrayShareWithoutMetadataStillRefusesAmbiguousLoopback(t *testing.T) {
	root, cfgPath := writeShareRoot(t, []byte(loopbackNoneConfig), nil)
	code, _, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--host", "203.0.113.9", "--public-port", "443", "--json")
	if code == 0 {
		t.Fatalf("ambiguous loopback config must stay refused without metadata: %s", raw)
	}
	if !strings.Contains(raw, "public security is ambiguous") {
		t.Fatalf("unexpected refusal reason: %s", raw)
	}
}

func TestXrayShareMetadataKeepsSelectedUser(t *testing.T) {
	generated, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeTLS, Transport: xraycfg.TransportWS, Domain: "example.com", Port: 10086,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondUUID := "00000000-0000-4000-8000-000000000002"
	cfgBody, _, err := xraycfg.AddUser(generated.Config, 0, xraycfg.AddUserSpec{
		UUID: secondUUID, Email: "second@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	root, cfgPath := writeShareRoot(t, cfgBody, &store.Metadata{
		TLS: "TLS", Transport: "ws",
		Install: &store.InstallSnapshot{Port: 443, ServerNames: []string{"example.com"}},
	})
	code, info, raw := shareJSON(t, "--root", root, "xray", "share", "--path", cfgPath,
		"--host", "example.com", "--user", "second@example.com", "--json")
	if code != 0 {
		t.Fatalf("share failed: %s", raw)
	}
	if info.UUID != secondUUID || info.Email != "second@example.com" {
		t.Fatalf("selected user lost: %+v", info)
	}
	if !strings.Contains(info.ShareURI, secondUUID) {
		t.Fatalf("share link carries another user: %s", info.ShareURI)
	}
}
