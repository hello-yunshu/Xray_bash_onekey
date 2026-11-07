package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const sampleConfig = `{
  "log": {"loglevel": "warning"},
  "dns": {"servers": ["1.1.1.1"]},
  "inbounds": [{
    "tag": "vless-in",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000000"}], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality"}
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "routing": {"rules": [{"type": "field", "ip": ["203.0.113.9"], "outboundTag": "direct"}]},
  "customTop": {"keep": true}
}`

func write(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMetadataErrors(t *testing.T) {
	tmp := t.TempDir()
	paths, _ := host.NewPaths(tmp)
	if _, _, err := LoadMetadata(paths); err == nil || ExitCode(err) != 3 {
		t.Fatalf("missing metadata: %v", err)
	}

	write(t, tmp, paths.ManagerMetadata(), "{bad json")
	if _, _, err := LoadMetadata(paths); err == nil || ExitCode(err) != 4 {
		t.Fatalf("corrupt metadata: %v", err)
	}

	write(t, tmp, paths.ManagerMetadata(), `{"schemaVersion":2,"activeEngine":"xray","role":"node","tls":"Reality"}`)
	if _, _, err := LoadMetadata(paths); err == nil || ExitCode(err) != 5 {
		t.Fatalf("schema high: %v", err)
	}

	write(t, tmp, paths.ManagerMetadata(), `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","uuid":"leak"}`)
	if _, _, err := LoadMetadata(paths); err == nil || ExitCode(err) != 4 {
		t.Fatalf("secret field accepted: %v", err)
	}

	write(t, tmp, paths.ManagerMetadata(), `{"schemaVersion":1,"activeEngine":"v2ray","role":"node","tls":"Reality"}`)
	if _, _, err := LoadMetadata(paths); err == nil || ExitCode(err) != 12 {
		t.Fatalf("unsupported engine: %v", err)
	}

	write(t, tmp, paths.ManagerMetadata(), `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality"}`)
	if _, _, err := LoadMetadata(paths); err != nil {
		t.Fatalf("valid metadata: %v", err)
	}
}

func TestLoadConfigPreservesCustomSections(t *testing.T) {
	tmp := t.TempDir()
	p := write(t, tmp, "etc/idleleo/conf/xray/config.json", sampleConfig)
	view, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Custom.DNS || !view.Custom.Routing || !view.Custom.Outbounds {
		t.Fatalf("custom flags: %+v", view.Custom)
	}
	if len(view.Custom.OtherTopLevelKeys) != 1 || view.Custom.OtherTopLevelKeys[0] != "customTop" {
		t.Fatalf("custom keys: %v", view.Custom.OtherTopLevelKeys)
	}
	if len(view.Inbounds) != 1 || view.Inbounds[0].Port != "443" || view.Inbounds[0].Security != "reality" {
		t.Fatalf("inbounds: %+v", view.Inbounds)
	}
	again, err := LoadConfig(p)
	if err != nil || again.SHA256 != view.SHA256 {
		t.Fatalf("config changed across reads: %v", err)
	}
}

func TestLoadConfigRefusesSymlinkAndBadJSON(t *testing.T) {
	tmp := t.TempDir()
	real := write(t, tmp, "real.json", sampleConfig)
	link := filepath.Join(tmp, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil || ExitCode(err) != 12 {
		t.Fatalf("symlink accepted: %v", err)
	}
	bad := write(t, tmp, "bad.json", `{"inbounds":`)
	if _, err := LoadConfig(bad); err == nil || ExitCode(err) != 4 {
		t.Fatalf("bad json accepted: %v", err)
	}
}
