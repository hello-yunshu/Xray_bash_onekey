package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

func editSandbox(t *testing.T) (root, configPath string, raw []byte) {
	t.Helper()
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := xraycfg.Generate(xraycfg.Spec{Mode: xraycfg.ModeReality, Domain: "example.com", Transport: xraycfg.TransportRaw})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "etc/idleleo/conf/xray")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, g.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(root, binaryRel)
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Edits are a native-manager operation: a Bash-owned root is refused, so
	// the fixture carries the metadata a real native install writes.
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","transport":"raw",` +
		`"provenance":"native","runtimeConfigPath":"etc/idleleo/conf/xray/config.json"}` + "\n"
	if err := os.WriteFile(metaPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, configPath, g.Config
}

func TestEditRefusesBashManagedRoot(t *testing.T) {
	root, _, _ := editSandbox(t)
	legacyPath := filepath.Join(root, "etc/idleleo/conf/install_config.json")
	if err := os.WriteFile(legacyPath, []byte(`{"port":443}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := EditConfig(context.Background(), EditSpec{Root: root, DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "Bash") {
		t.Fatalf("a Bash-owned root must be refused, got %v", err)
	}
}

func TestEditRefusesImportedProvenance(t *testing.T) {
	root, _, _ := editSandbox(t)
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	seed := `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality",` +
		`"provenance":"legacy","runtimeConfigPath":"etc/idleleo/conf/xray/config.json"}` + "\n"
	if err := os.WriteFile(metaPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := EditConfig(context.Background(), EditSpec{Root: root, DryRun: true})
	if err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("an imported Bash root must be refused, got %v", err)
	}
}

func TestTLSPathsReadsTheLivePair(t *testing.T) {
	conf := `server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate     /etc/idleleo/cert/a.crt;
    ssl_certificate_key /etc/idleleo/cert/a.key;
}`
	cert, key := tlsPaths(conf)
	if cert != "/etc/idleleo/cert/a.crt" || key != "/etc/idleleo/cert/a.key" {
		t.Fatalf("tlsPaths = %q %q", cert, key)
	}
	if cert, key := tlsPaths("server { listen 80; }"); cert != "" || key != "" {
		t.Fatalf("a plain block must not invent a pair: %q %q", cert, key)
	}
}

func stubXrayTest(t *testing.T, fn func(ctx context.Context, bin, candidate string, env []string) error) {
	t.Helper()
	old := runXrayTest
	runXrayTest = fn
	t.Cleanup(func() { runXrayTest = old })
}

// stubEditService replaces the edit transaction's service seams. It is
// separate from deploy_test.go's stubService so both install and edit tests can
// coexist in this package.
func stubEditService(t *testing.T, fn func(ctx context.Context, args ...string) error) {
	t.Helper()
	oldService, oldWait := service, waitActive
	service = fn
	waitActive = func(context.Context) string { return "active" }
	t.Cleanup(func() { service, waitActive = oldService, oldWait })
}

func TestEditConfigWritesCandidateAndBackup(t *testing.T) {
	root, configPath, old := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	report, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8080}, NoRestart: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.NoChanges || !report.Disconnect {
		t.Fatalf("report = %+v", report)
	}
	newBody, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var rootCfg struct {
		Inbounds []struct {
			Port int `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(newBody, &rootCfg); err != nil {
		t.Fatal(err)
	}
	if rootCfg.Inbounds[0].Port != 8080 {
		t.Fatalf("port = %d, want 8080", rootCfg.Inbounds[0].Port)
	}
	if report.BackupDir == "" {
		t.Fatal("edit must leave a backup directory")
	}
	backup, err := os.ReadFile(filepath.Join(report.BackupDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != string(old) {
		t.Fatal("backup does not hold the previous config")
	}
	if _, err := os.Stat(filepath.Join(report.BackupDir, "manifest.json")); err != nil {
		t.Fatalf("backup manifest missing: %v", err)
	}
}

func TestEditPlanMatchesDryRunAndApply(t *testing.T) {
	root, _, _ := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	req := xraycfg.EditRequest{Port: 8080}
	dry, err := EditConfig(context.Background(), EditSpec{Root: root, Request: req, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Plan == nil {
		t.Fatal("dry run returned no plan")
	}
	applied, err := EditConfig(context.Background(), EditSpec{Root: root, Request: req, NoRestart: true})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Plan == nil || applied.Plan.Fingerprint != dry.Plan.Fingerprint {
		t.Fatalf("apply plan %+v does not match dry-run plan %+v", applied.Plan, dry.Plan)
	}
	if applied.Plan.DisconnectRisk == "" || applied.Plan.RollbackScope == "" || len(applied.Plan.ValidationSteps) == 0 {
		t.Fatalf("plan is missing contract fields: %+v", applied.Plan)
	}
	body, err := os.ReadFile(filepath.Join(applied.BackupDir, "plan.json"))
	if err != nil {
		t.Fatalf("backup has no plan.json: %v", err)
	}
	var stored change.Plan
	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Fingerprint != applied.Plan.Fingerprint {
		t.Fatalf("stored fingerprint %s != report %s", stored.Fingerprint, applied.Plan.Fingerprint)
	}
}

func TestEditRealityBalanceLeavesUpstreamTreeUntouched(t *testing.T) {
	root, configPath, _ := editSandbox(t)
	balance, err := xraycfg.Generate(xraycfg.Spec{
		Mode: xraycfg.ModeRealityBalance, BalanceRole: xraycfg.BalanceRolePrimary,
		Domain: "example.com", Port: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, balance.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	seed := `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","transport":"raw",` +
		`"balanceRole":"primary","provenance":"native","runtimeConfigPath":"etc/idleleo/conf/xray/config.json"}` + "\n"
	if err := os.WriteFile(metaPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	nginxDir := filepath.Join(root, nginxDirRel)
	if err := os.MkdirAll(nginxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nginxDir, nginx.MainConf),
		[]byte("stream {\n    server {\n        listen 443;\n    }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	upstream := filepath.Join(nginxDir, "reality_upstream.conf")
	if err := os.WriteFile(upstream, []byte("server 127.0.0.1:9443;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := hashTree(nginxDir)
	if err != nil {
		t.Fatal(err)
	}
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	report, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{ShortIDAuto: true},
		NoRestart: true, NoProbe: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !report.UpstreamUnchanged || report.UpstreamSHA256 != before {
		t.Fatalf("upstream evidence = %+v, want hash %s", report, before)
	}
	after, err := hashTree(nginxDir)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("reality-balance edit changed the upstream tree: %s -> %s", before, after)
	}
}

func TestEditConfigSelfCheckFailureWritesNothing(t *testing.T) {
	root, configPath, old := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return errors.New("syntax error") })
	_, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8080}, NoRestart: true,
	})
	if err == nil || !strings.Contains(err.Error(), "not changed") {
		t.Fatalf("validation failure must abort the edit, got %v", err)
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(old) {
		t.Fatal("config changed despite failing self-check")
	}
	backups, _ := filepath.Glob(filepath.Join(root, "etc/idleleo/backup/edit-*"))
	if len(backups) != 0 {
		t.Fatalf("no backup should be written before the candidate passes, found %v", backups)
	}
}

func TestEditConfigRefreshesInstallSnapshot(t *testing.T) {
	root, _, _ := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	oldProbe := probeOrigin
	probeOrigin = func(context.Context, string, string) error { return nil }
	t.Cleanup(func() { probeOrigin = oldProbe })

	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	metaPath, err := paths.Join(paths.ManagerMetadata(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","transport":"raw",` +
		`"runtimeConfigPath":"etc/idleleo/conf/xray/config.json",` +
		`"install":{"engineVersion":"26.10.31","port":8443,"target":"old.example.org:443","serverNames":["old.example.org"]}}` + "\n"
	if err := os.WriteFile(metaPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Target: "new.example.org:443"}, NoRestart: true,
	}); err != nil {
		t.Fatal(err)
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		t.Fatalf("metadata must stay loadable after an edit: %v", err)
	}
	if meta.Install == nil {
		t.Fatal("edit dropped the install snapshot")
	}
	if meta.Install.Target != "new.example.org:443" {
		t.Fatalf("snapshot target = %q, want the post-edit origin", meta.Install.Target)
	}
	if meta.Install.Port != 8443 || meta.Install.EngineVersion != "26.10.31" {
		t.Fatalf("edit must not invent a new port/version: %+v", meta.Install)
	}
}

func TestUpdateMetadataAfterEditKeepsLoadableTLSLabel(t *testing.T) {
	root, _, _ := editSandbox(t)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	metaPath, err := paths.Join(paths.ManagerMetadata(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","transport":"ws",` +
		`"runtimeConfigPath":"etc/idleleo/conf/xray/config.json"}` + "\n"
	if err := os.WriteFile(metaPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	var rep EditReport
	updateMetadataAfterEdit(paths, xraycfg.EditResult{Mode: xraycfg.ModeTLS, Transport: "ws"}, []byte(`{"inbounds":[]}`), &rep)
	if len(rep.Warnings) != 0 {
		t.Fatalf("metadata update warned: %v", rep.Warnings)
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		t.Fatalf("metadata written by an edit must load: %v", err)
	}
	if meta.TLS != "TLS" {
		t.Fatalf("tls label = %q, want the loadable %q", meta.TLS, "TLS")
	}
}

func TestEditConfigRestartFailureRollsBack(t *testing.T) {
	root, configPath, old := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	restarts := 0
	stubEditService(t, func(_ context.Context, args ...string) error {
		if len(args) > 0 && args[0] == "restart" {
			restarts++
			if restarts == 1 {
				return errors.New("restart failed")
			}
		}
		return nil
	})
	_, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8080},
	})
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("restart failure must roll back, got %v", err)
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(old) {
		t.Fatal("config was not restored after the restart failure")
	}
	if restarts < 2 {
		t.Fatalf("rollback must try to bring the old config back, restarts = %d", restarts)
	}
}

func TestEditConfigRestartsOnSuccess(t *testing.T) {
	root, _, _ := editSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	stubEditService(t, func(context.Context, ...string) error { return nil })
	if _, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{UUID: "11111111-2222-3333-4444-555555555555"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEditConfigDryRunWritesNothing(t *testing.T) {
	root, configPath, old := editSandbox(t)
	report, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8080}, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.NoChanges || report.NewSHA256 == "" {
		t.Fatalf("dry run must report the candidate: %+v", report)
	}
	after, _ := os.ReadFile(configPath)
	if string(after) != string(old) {
		t.Fatal("dry run wrote the config")
	}
	if report.BackupDir != "" {
		t.Fatal("dry run must not create a backup")
	}
}

// directTLSEditSandbox builds a native-managed root whose live config owns the
// listener and certificate pair (no Nginx front).
func directTLSEditSandbox(t *testing.T) (root, configPath, certPath, keyPath string, old []byte) {
	t.Helper()
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(root, "cert")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = writeTestPair(t, certDir, "example.com",
		time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), 0o600)
	body := `{
  "log": {"loglevel": "warning"},
  "inbounds": [{
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
        "certificates": [{"certificateFile": "` + certPath + `", "keyFile": "` + keyPath + `"}]
      },
      "wsSettings": {"path": "/e2e"}
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "routing": {"rules": [{"type": "field", "domain": ["keep.example"], "outboundTag": "direct"}]}
}`
	dir := filepath.Join(root, "etc/idleleo/conf/xray")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(root, binaryRel)
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(root, "etc/idleleo/v1/metadata.json")
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"schemaVersion":1,"activeEngine":"xray","role":"node","tls":"Reality","transport":"ws",` +
		`"provenance":"native","runtimeConfigPath":"etc/idleleo/conf/xray/config.json"}` + "\n"
	if err := os.WriteFile(metaPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, configPath, certPath, keyPath, []byte(body)
}

func TestEditConfigDirectTLSRotatesPairWithoutTouchingRouting(t *testing.T) {
	root, configPath, _, _, _ := directTLSEditSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	newCert, newKey := writeTestPair(t, t.TempDir(), "example.com",
		time.Now().Add(-time.Hour), time.Now().Add(120*24*time.Hour), 0o600)
	report, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{CertFile: newCert, KeyFile: newKey},
		NoRestart: true, NoProbe: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != xraycfg.ModeTLSDirect || report.NoChanges {
		t.Fatalf("report = %+v", report)
	}
	if report.ScheduleUpdated {
		t.Fatal("direct TLS must not rewrite a renewal schedule")
	}
	if !strings.Contains(strings.Join(report.Warnings, "\n"), "renewal is not managed") {
		t.Fatalf("missing direct TLS renewal warning: %v", report.Warnings)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), newCert) {
		t.Fatalf("certificate file was not rotated:\n%s", after)
	}
	if !strings.Contains(string(after), `"keep.example"`) {
		t.Fatalf("routing rule was dropped:\n%s", after)
	}
	if !strings.Contains(string(after), `"path": "/e2e"`) {
		t.Fatalf("ws path drifted:\n%s", after)
	}
}

func TestEditConfigDirectTLSRefusesMismatchedPairBeforeWriting(t *testing.T) {
	root, configPath, _, _, old := directTLSEditSandbox(t)
	_, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Domain: "other.example.com"},
		NoRestart: true, NoProbe: true,
	})
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("a domain without a covering pair must be refused, got %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(old) {
		t.Fatal("a refused pair must not rewrite the config")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, "etc/idleleo/backup")); len(entries) != 0 {
		t.Fatalf("a refused pair must not write a backup, got %d entries", len(entries))
	}
}

func TestEditConfigDirectTLSProbesItsOwnListener(t *testing.T) {
	root, _, _, _, _ := directTLSEditSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	stubEditService(t, func(context.Context, ...string) error { return nil })
	var gotAddr, gotSNI string
	stubTLSProbe(t, func(_ context.Context, addr, serverName string, _ []byte) (tlsProbeResult, error) {
		gotAddr, gotSNI = addr, serverName
		return tlsProbeResult{ServerName: serverName, Version: "TLS 1.3"}, nil
	})
	report, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8443},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != "127.0.0.1:8443" || gotSNI != "example.com" {
		t.Fatalf("probe target = %s SNI %s", gotAddr, gotSNI)
	}
	if report.TLSProbe != "ok" {
		t.Fatalf("TLSProbe = %q", report.TLSProbe)
	}
}

func TestEditConfigDirectTLSProbeFailureRollsBack(t *testing.T) {
	root, configPath, _, _, old := directTLSEditSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	stubEditService(t, func(context.Context, ...string) error { return nil })
	stubTLSProbe(t, func(context.Context, string, string, []byte) (tlsProbeResult, error) {
		return tlsProbeResult{}, certMismatchError{addr: "127.0.0.1:8443"}
	})
	_, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Port: 8443},
	})
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("a failed direct TLS probe must roll back, got %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(old) {
		t.Fatal("the old direct TLS config was not restored")
	}
}

func TestEditConfigDirectTLSKeepsMetadataLabel(t *testing.T) {
	root, _, _, _, _ := directTLSEditSandbox(t)
	stubXrayTest(t, func(context.Context, string, string, []string) error { return nil })
	if _, err := EditConfig(context.Background(), EditSpec{
		Root: root, Request: xraycfg.EditRequest{Listen: "127.0.0.1"},
		NoRestart: true, NoProbe: true,
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(root, "etc/idleleo/v1/metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "tls-direct") {
		t.Fatalf("the edit classification leaked into metadata:\n%s", after)
	}
	if !strings.Contains(string(after), `"tls":"Reality"`) && !strings.Contains(string(after), `"tls": "Reality"`) {
		t.Fatalf("install-time TLS label was not preserved:\n%s", after)
	}
}

func TestParseRelayConf(t *testing.T) {
	conf, err := xraycfg.RelayConf(xraycfg.RelaySpec{ListenAddress: "0.0.0.0", ListenPort: 8443, BackendHost: "203.0.113.5", BackendPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	target, addr, port := relayConfParts(conf)
	if addr != "0.0.0.0" || port != 8443 || target != "203.0.113.5:443" {
		t.Fatalf("parsed %q %d %q", addr, port, target)
	}
}
