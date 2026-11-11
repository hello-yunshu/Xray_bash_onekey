package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

func buildCLI(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build the crash fixture")
	}
	out := filepath.Join(t.TempDir(), "idleleo")
	cmd := exec.Command("go", "build", "-o", out, "github.com/hello-yunshu/Xray_bash_onekey/cmd/idleleo")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cli: %v: %s", err, b)
	}
	return out
}

func journalEntries(t *testing.T, root string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "var/lib/idleleo/transactions/phase01.json"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	return entries
}

// A real SIGKILL in the middle of the commit keeps the new file and the
// PREPARED record; `change recover` must converge back to the old file.
func TestChangeHardKillIsRecovered(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	killer := filepath.Join(root, "service-killer")
	killerBody := "#!/bin/sh\nif [ ! -f \"$0.armed\" ]; then\n  : > \"$0.armed\"\n  kill -9 \"$PPID\"\nfi\n"
	if err := os.WriteFile(killer, []byte(killerBody), 0755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	oldRaw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	bin := buildCLI(t)

	run := exec.Command(bin, "--root", root, "change", "set-inbound-port",
		"--sandbox", root, "--port", "8443", "--validator", "/usr/bin/true", "--service", killer)
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("the service was supposed to kill the process: %s", out)
	}

	// Half-applied on disk: the rename happened, the record did not.
	newRaw, _ := os.ReadFile(cfgPath)
	if string(newRaw) == string(oldRaw) {
		t.Fatalf("rename did not happen before the kill: %s", out)
	}
	entries := journalEntries(t, root)
	if state, _ := entries[len(entries)-1]["state"].(string); state != "PREPARED" {
		t.Fatalf("journal state=%q entries=%v", state, entries)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), ".idleleo-phase01-rollback")); err != nil {
		t.Fatalf("rollback snapshot missing: %v", err)
	}

	rec := exec.Command(bin, "--root", root, "change", "recover", "--json")
	recOut, recErr := rec.CombinedOutput()
	if recErr != nil {
		t.Fatalf("recover: %v: %s", recErr, recOut)
	}
	var report struct {
		Action    string `json:"action"`
		Converged bool   `json:"converged"`
	}
	if err := json.Unmarshal(recOut, &report); err != nil {
		t.Fatalf("recover output: %v: %s", err, recOut)
	}
	if !report.Converged || report.Action != "rolled-back" {
		t.Fatalf("report=%s", recOut)
	}
	restored, _ := os.ReadFile(cfgPath)
	if store.HashBytes(restored) != store.HashBytes(oldRaw) {
		t.Fatal("recover did not restore the old config")
	}
	entries = journalEntries(t, root)
	if state, _ := entries[len(entries)-1]["state"].(string); state != "ROLLED_BACK" {
		t.Fatalf("journal state=%q", state)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), ".idleleo-phase01-rollback")); !os.IsNotExist(err) {
		t.Fatal("rollback snapshot left behind")
	}
}

// The write gate is the last line of defence on a real root: without
// --container and the environment acknowledgement nothing may be staged.
func TestChangeRealRootIsRefusedWithoutContainerAck(t *testing.T) {
	if !host.InContainer() {
		t.Skip("container-only gate")
	}
	t.Setenv("IDLELEO_ALLOW_SYSTEM_WRITES", "")
	code, _, errOut := run(t, "--root", "/", "change", "set-inbound-port",
		"--sandbox", "/", "--port", "8443", "--validator", "/usr/bin/true", "--service", "/usr/bin/true")
	if code != 2 || !strings.Contains(errOut, "--container") {
		t.Fatalf("missing --container ack: %d %q", code, errOut)
	}
}

func TestChangeRealRootIsRefusedWithoutEnvAck(t *testing.T) {
	if !host.InContainer() {
		t.Skip("container-only gate")
	}
	t.Setenv("IDLELEO_ALLOW_SYSTEM_WRITES", "")
	code, _, errOut := run(t, "--root", "/", "change", "set-inbound-port",
		"--sandbox", "/", "--port", "8443", "--validator", "/usr/bin/true", "--service", "/usr/bin/true", "--container")
	if code != 2 || !strings.Contains(errOut, "IDLELEO_ALLOW_SYSTEM_WRITES") {
		t.Fatalf("missing env ack: %d %q", code, errOut)
	}
}

// With both acknowledgements the gate opens, but an unowned real root still
// has no baseline and must be refused before staging.
func TestChangeRealRootRequiresManagerMetadata(t *testing.T) {
	if !host.InContainer() {
		t.Skip("container-only gate")
	}
	if _, err := os.Stat("/etc/idleleo/v1/metadata.json"); err == nil {
		t.Skip("this container already owns a real root")
	}
	t.Setenv("IDLELEO_ALLOW_SYSTEM_WRITES", "I_ACCEPT_CONTAINER_ONLY")
	code, _, errOut := run(t, "--root", "/", "change", "set-inbound-port",
		"--sandbox", "/", "--port", "8443", "--validator", "/usr/bin/true", "--service", "/usr/bin/true", "--container")
	if code == 0 || !strings.Contains(errOut, "metadata") {
		t.Fatalf("unowned real root accepted: %d %q", code, errOut)
	}
	if _, err := os.Stat("/etc/idleleo/conf/xray/config.json"); err == nil {
		t.Fatal("refusal still wrote a runtime config")
	}
}

// Failure injection must never reach a real root.
func TestChangeRefusesFaultOnRealRoot(t *testing.T) {
	if !host.InContainer() {
		t.Skip("container-only gate")
	}
	t.Setenv("IDLELEO_ALLOW_SYSTEM_WRITES", "I_ACCEPT_CONTAINER_ONLY")
	code, _, errOut := run(t, "--root", "/", "change", "set-inbound-port",
		"--sandbox", "/", "--port", "8443", "--validator", "/usr/bin/true", "--service", "/usr/bin/true",
		"--container", "--fault", "service-fail")
	if code != 2 || !strings.Contains(errOut, "sandbox") {
		t.Fatalf("fault injector accepted on the real root: %d %q", code, errOut)
	}
}

func TestXrayUserAddInSandbox(t *testing.T) {
	root := t.TempDir()
	raw := `{"inbounds":[{"tag":"vless-in","listen":"127.0.0.1","port":443,"protocol":"vless",` +
		`"settings":{"clients":[{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","email":"first@example.com"}]},` +
		`"streamSettings":{"network":"tcp","security":"reality"}}],"outbounds":[{"protocol":"freedom"}]}`
	cfgDir := filepath.Join(root, "etc/idleleo/conf/xray")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(raw), 0640); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{
		"schemaVersion": 1, "activeEngine": "xray", "role": "node",
		"tls": "Reality", "transport": "tcp",
		"runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
		"runtimeSha256":     store.HashBytes([]byte(raw)),
	}
	metaRaw, _ := json.Marshal(meta)
	metaDir := filepath.Join(root, "etc/idleleo/v1")
	if err := os.MkdirAll(metaDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "metadata.json"), metaRaw, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := run(t, "--root", root, "xray", "user", "add", "--sandbox", root,
		"--inbound", "0", "--uuid", "11111111-1111-4111-8111-111111111111",
		"--email", "second@example.com", "--validator", "/usr/bin/true")
	if code != 0 {
		t.Fatalf("user add: %d %q %q", code, out, errOut)
	}
	updated, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "11111111-1111-4111-8111-111111111111") {
		t.Fatalf("user missing from config: %s", updated)
	}
	var after struct {
		RuntimeSHA256 string `json:"runtimeSha256"`
	}
	if b, err := os.ReadFile(filepath.Join(metaDir, "metadata.json")); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(b, &after); err != nil {
		t.Fatal(err)
	}
	if after.RuntimeSHA256 != store.HashBytes(updated) {
		t.Fatal("metadata fingerprint was not refreshed after the user change")
	}
}
