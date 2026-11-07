package change

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
)

const cfg = `{
  "log": {"loglevel": "warning"},
  "inbounds": [{"tag": "vless-in", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
    "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000000"}], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality"}}],
  "dns": {"servers": ["1.1.1.1"]},
  "routing": {"rules": [{"type": "field", "ip": ["203.0.113.9"], "outboundTag": "direct"}]},
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "customTop": {"keep": true}
}`

func sandbox(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}
	return root, cfgPath
}

func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseReq(root, cfgPath, validator, service string) Request {
	return Request{
		Target:    cfgPath,
		Mutate:    func(raw []byte) ([]byte, error) { return SetInboundPort(raw, 0, 8443) },
		Validator: runtime.XrayValidator{Path: validator},
		Service:   runtime.CommandService{Path: service},
		Journal:   Journal{Path: filepath.Join(root, "var/lib/idleleo/transactions/phase01.json")},
		LockPath:  filepath.Join(root, "run/lock/idleleo-update.lock"),
	}
}

func journalState(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("journal missing: %v", err)
	}
	var entries []Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("journal empty")
	}
	return entries[len(entries)-1].State
}

func TestApplyCommitsAndPreservesCustomFields(t *testing.T) {
	root, cfgPath := sandbox(t)
	validator := script(t, root, "validator", "exit 0")
	service := script(t, root, "service", `echo "$@" >> "$0.log"`)
	req := baseReq(root, cfgPath, validator, service)
	entry, err := Apply(context.Background(), req)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if entry.State != StateCommitted {
		t.Fatalf("state: %s", entry.State)
	}
	view, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(view), "COMMITTED") {
		t.Fatal("entry not committed")
	}
	raw, _ := os.ReadFile(cfgPath)
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	in := parsed["inbounds"].([]any)[0].(map[string]any)
	if in["port"].(float64) != 8443 {
		t.Fatalf("port not changed: %v", in["port"])
	}
	if _, ok := parsed["customTop"]; !ok {
		t.Fatal("custom field lost")
	}
	if _, ok := parsed["routing"]; !ok {
		t.Fatal("routing lost")
	}
	if journalState(t, req.Journal.Path) != StateCommitted {
		t.Fatal("journal state")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), ".idleleo-phase01-rollback")); !os.IsNotExist(err) {
		t.Fatal("rollback file left behind")
	}
}

func TestApplyValidatorFailureLeavesTargetUntouched(t *testing.T) {
	root, cfgPath := sandbox(t)
	validator := script(t, root, "validator", "echo rejected >&2; exit 1")
	service := script(t, root, "service", "exit 0")
	req := baseReq(root, cfgPath, validator, service)
	before, _ := os.ReadFile(cfgPath)
	_, err := Apply(context.Background(), req)
	var ve *runtime.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want validation error, got %v", err)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Fatal("target changed after validation failure")
	}
	if journalState(t, req.Journal.Path) != StateRejected {
		t.Fatal("journal state")
	}
}

func TestApplyWriteFaultLeavesTargetUntouched(t *testing.T) {
	root, cfgPath := sandbox(t)
	req := baseReq(root, cfgPath, script(t, root, "validator", "exit 0"), "")
	req.Fault = FaultWriteFailure
	before, _ := os.ReadFile(cfgPath)
	_, err := Apply(context.Background(), req)
	var ie *IOError
	if !errors.As(err, &ie) {
		t.Fatalf("want IO error, got %v", err)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Fatal("target changed on write fault")
	}
	if journalState(t, req.Journal.Path) != StateFailed {
		t.Fatal("journal state")
	}
}

func TestApplyExternalDriftIsRefused(t *testing.T) {
	root, cfgPath := sandbox(t)
	req := baseReq(root, cfgPath, script(t, root, "validator", "exit 0"), "")
	req.Fault = FaultDrift
	_, err := Apply(context.Background(), req)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want conflict, got %v", err)
	}
	raw, _ := os.ReadFile(cfgPath)
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatal("drift injection missing")
	}
	if journalState(t, req.Journal.Path) != StateConflict {
		t.Fatal("journal state")
	}
}

func TestApplyServiceFailureRollsBackWithoutStart(t *testing.T) {
	root, cfgPath := sandbox(t)
	validator := script(t, root, "validator", "exit 0")
	service := script(t, root, "service", `echo "$@" >> "$0.log"; exit 1`)
	req := baseReq(root, cfgPath, validator, service)
	before, _ := os.ReadFile(cfgPath)
	_, err := Apply(context.Background(), req)
	var se *runtime.ServiceError
	if !errors.As(err, &se) {
		t.Fatalf("want service error, got %v", err)
	}
	after, _ := os.ReadFile(cfgPath)
	if string(before) != string(after) {
		t.Fatal("target not restored")
	}
	if journalState(t, req.Journal.Path) != StateRolledBack {
		t.Fatal("journal state")
	}
	log, _ := os.ReadFile(service + ".log")
	if strings.TrimSpace(string(log)) != "apply" {
		t.Fatalf("unexpected service actions: %q", string(log))
	}
}

func TestApplyLockConflict(t *testing.T) {
	root, cfgPath := sandbox(t)
	req := baseReq(root, cfgPath, script(t, root, "validator", "exit 0"), "")
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := host.AcquireUpdate(req.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	_, err = Apply(context.Background(), req)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want lock conflict, got %v", err)
	}
	if _, err := os.Stat(req.Journal.Path); !os.IsNotExist(err) {
		t.Fatalf("lock conflict wrote a journal: %v", err)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("lock conflict modified the target")
	}
}

func TestSetInboundPortRejectsInvalid(t *testing.T) {
	if _, err := SetInboundPort([]byte(cfg), 0, 0); err == nil {
		t.Fatal("port 0 accepted")
	}
	if _, err := SetInboundPort([]byte(cfg), 9, 8443); err == nil {
		t.Fatal("bad index accepted")
	}
	if _, err := SetInboundPort([]byte("{"), 0, 8443); err == nil {
		t.Fatal("bad json accepted")
	}
}
