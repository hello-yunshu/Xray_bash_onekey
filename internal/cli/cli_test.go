package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cfg = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{"tag": "vless-in", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
    "streamSettings": {"network": "tcp", "security": "reality"}}],
  "dns": {"servers": ["1.1.1.1"]},
  "routing": {"rules": []},
  "outbounds": [{"protocol": "freedom"}]
}`

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), args, Options{In: strings.NewReader(""), Out: &out, Err: &errOut})
	return code, out.String(), errOut.String()
}

func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/idleleo/conf/xray"), 0755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(cfg))
	meta := map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node",
		"tls": "Reality", "transport": "tcp",
		"runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256":     hex.EncodeToString(sum[:]),
	}
	b, _ := json.Marshal(meta)
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	if err := os.MkdirAll(filepath.Dir(metaPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := sha256.Sum256(b)
		out[p] = hex.EncodeToString(s[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVersionHelpAndNoTTY(t *testing.T) {
	if code, out, _ := run(t, "version"); code != 0 || !strings.Contains(out, "phase04") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, out, _ := run(t, "--help"); code != 0 || !strings.Contains(out, "status") {
		t.Fatalf("help: %d", code)
	}
	code, _, errOut := run(t, "--lang", "en")
	if code != 2 || !strings.Contains(errOut, "no TTY") {
		t.Fatalf("no tty: %d %q", code, errOut)
	}
	code, out, errOut := run(t, "--lang", "fr", "--help")
	if code != 0 || !strings.Contains(out, "Usage") {
		t.Fatalf("fr fallback: %d %q", code, out)
	}
	if !strings.Contains(errOut, "fr") || !strings.Contains(errOut, "falling back to English") {
		t.Fatalf("fr fallback must be announced, got %q", errOut)
	}
	if code, _, errOut := run(t, "--lang", "zh", "--help"); code != 0 || errOut != "" {
		t.Fatalf("complete language must not warn: %d %q", code, errOut)
	}
}

func TestHelpListsEveryTopLevelCommand(t *testing.T) {
	code, out, _ := run(t, "--help")
	if code != 0 {
		t.Fatalf("help: %d", code)
	}
	for _, want := range []string{
		"xray generate", "xray share", "xray relay", "xray user", "xray install",
		"xray cert issue|renew", "recover", "0.2.0-phase04",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("help is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Phase 01") {
		t.Fatalf("help still advertises Phase 01:\n%s", out)
	}
}

func TestSubcommandHelpIsNotExecuted(t *testing.T) {
	for _, args := range [][]string{
		{"xray", "generate", "--help"},
		{"xray", "cert", "--help"},
		{"bridge", "prepare", "-h"},
		{"schedule", "install", "--help"},
	} {
		code, out, errOut := run(t, append([]string{"--lang", "en"}, args...)...)
		if code != 0 || !strings.Contains(out, "Usage") {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errOut)
		}
		if errOut != "" {
			t.Fatalf("%v: help must not write an error: %q", args, errOut)
		}
	}
}

func TestStatsUnavailableIsReadOnly(t *testing.T) {
	root := t.TempDir()
	code, _, errOut := run(t, "--root", root, "--lang", "en", "stats", "--json")
	if code != 3 || !strings.Contains(errOut, "stats unavailable") {
		t.Fatalf("stats: %d %q", code, errOut)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("stats wrote files: %v", entries)
	}
}

func TestUpdateUnconfiguredIsReadOnly(t *testing.T) {
	root := t.TempDir()
	code, _, errOut := run(t, "--root", root, "--lang", "en", "update", "check")
	if code != 3 || !strings.Contains(errOut, "no Go release channel") {
		t.Fatalf("update check: %d %q", code, errOut)
	}
	code, out, _ := run(t, "--root", root, "--lang", "en", "update", "status", "--json")
	if code != 0 || !strings.Contains(out, "configured") {
		t.Fatalf("update status: %d %q", code, out)
	}
}

func TestStatusMissingRootCreatesNothing(t *testing.T) {
	root := t.TempDir()
	code, _, _ := run(t, "--root", root, "status")
	if code != 3 {
		t.Fatalf("status missing: %d", code)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("read-only status created files: %v", entries)
	}
}

func TestStatusJSONAndNoWrites(t *testing.T) {
	root := fixture(t)
	before := snapshot(t, root)
	code, out, errOut := run(t, "--root", root, "--json", "status")
	if code != 0 {
		t.Fatalf("status: %d %s", code, errOut)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report["installed"] != true || report["role"] != "node" {
		t.Fatalf("report: %v", report)
	}
	if report["config"].(map[string]any)["matchesMetadata"] != true {
		t.Fatal("metadata sha not matched")
	}
	after := snapshot(t, root)
	if len(before) != len(after) {
		t.Fatal("status changed file set")
	}
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("status changed %s", k)
		}
	}
}

func TestStatusReportsDriftWithoutWriting(t *testing.T) {
	root := fixture(t)
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	meta := map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node", "tls": "Reality",
		"runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256":     strings.Repeat("0", 64),
	}
	b, _ := json.Marshal(meta)
	if err := os.WriteFile(metaPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, root)
	code, out, _ := run(t, "--root", root, "--json", "status")
	if code != 0 || !strings.Contains(out, "runtime-config-sha-mismatch") {
		t.Fatalf("drift: %d %q", code, out)
	}
	if after := snapshot(t, root); len(after) != len(before) {
		t.Fatal("drift status wrote files")
	}
}

func TestInspectDoesNotModifyConfig(t *testing.T) {
	root := fixture(t)
	cfgPath := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	before, _ := os.ReadFile(cfgPath)
	code, out, errOut := run(t, "--root", root, "config", "inspect", "--json")
	if code != 0 {
		t.Fatalf("inspect: %d %s", code, errOut)
	}
	var view map[string]any
	if err := json.Unmarshal([]byte(out), &view); err != nil {
		t.Fatal(err)
	}
	if view["custom"].(map[string]any)["dns"] != true {
		t.Fatal("dns custom not detected")
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Fatal("inspect modified config")
	}
}

func TestChangeRequiresSandboxMarker(t *testing.T) {
	root := fixture(t)
	code, _, errOut := run(t, "--root", root, "change", "set-inbound-port",
		"--sandbox", root, "--port", "8443", "--validator", "/usr/bin/true")
	if code != 2 || !strings.Contains(errOut, "sandbox") {
		t.Fatalf("sandbox guard: %d %q", code, errOut)
	}
}

func TestChangeSuccessInSandbox(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, ".idleleo-phase01-sandbox"), []byte("I_ACCEPT_DISPOSABLE_SANDBOX\n"), 0600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, "--root", root, "--json", "change", "set-inbound-port",
		"--sandbox", root, "--port", "8443", "--validator", "/usr/bin/true")
	if code != 0 {
		t.Fatalf("change: %d %s", code, errOut)
	}
	if !strings.Contains(out, "COMMITTED") {
		t.Fatalf("entry: %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _, _ := run(t, "frobnicate"); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
}

func TestInteractiveMenuExitsOnEOF(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), nil, Options{In: strings.NewReader(""), Out: &out, Err: &errOut, TTY: true})
	if code != 0 || !strings.Contains(out.String(), "1) status") {
		t.Fatalf("menu: %d %q", code, out.String())
	}
}

var _ io.Writer = (*bytes.Buffer)(nil)
