package deploy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

func seedGuardInstall(t *testing.T) string {
	t.Helper()
	root := sandbox(t)
	meta := store.Metadata{
		SchemaVersion:     store.ManagerSchemaVersion,
		ActiveEngine:      "xray",
		Role:              "node",
		TLS:               "Reality",
		Transport:         "raw",
		RuntimeConfigPath: "etc/idleleo/conf/xray/config.json",
		RuntimeSHA256:     strings.Repeat("a", 64),
		OwnedResources:    []string{},
		UpdatedAt:         "2026-01-01T00:00:00Z",
		Install:           &store.InstallSnapshot{Port: 443, ServerNames: []string{"node.example.com"}},
	}
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"), mustJSON(t, meta))
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"),
		[]byte(`{"inbounds":[{"port":443,"protocol":"vless"}]}`))
	confDir := filepath.Join(root, nginxDirRel)
	writeGuardTestFile(t, filepath.Join(confDir, nginx.MainConf), []byte(`stream {
    map $ssl_preread_server_name $sni_upstream {
        include /etc/idleleo/conf/nginx/*.serverNames;
        default deny;
    }
    upstream deny {
        server 127.0.0.1:9403;
    }
}
`))
	writeGuardTestFile(t, filepath.Join(confDir, "03-isolate.conf"), []byte(isolateFragment()))
	writeGuardTestFile(t, filepath.Join(root, nginx.InstallDirRel, "conf/nginx.conf"), []byte(`http {
    include /etc/idleleo/conf/nginx/03-isolate.conf;
}
`))
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	return root
}

func writeGuardTestFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readGuardTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetSNIGuardRejectRemovesSites(t *testing.T) {
	root := seedGuardInstall(t)
	rep, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyReject})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Changed || rep.DenyPort != GuardRejectPort {
		t.Fatalf("unexpected report: %+v", rep)
	}
	confDir := filepath.Join(root, nginxDirRel)
	if _, err := os.Stat(filepath.Join(confDir, "03-isolate.conf")); !os.IsNotExist(err) {
		t.Fatal("isolate fragment must be removed for reject")
	}
	main := readGuardTestFile(t, filepath.Join(root, nginx.InstallDirRel, "conf/nginx.conf"))
	if strings.Contains(main, "03-isolate.conf") {
		t.Fatalf("isolate include must be removed: %s", main)
	}
	xrayConf := readGuardTestFile(t, filepath.Join(confDir, nginx.MainConf))
	if !strings.Contains(xrayConf, "127.0.0.1:9404") {
		t.Fatalf("deny upstream must point at 9404: %s", xrayConf)
	}
	meta := loadGuardTestMetadata(t, root)
	if meta.SNIGuard == nil || meta.SNIGuard.Policy != SNIPolicyReject {
		t.Fatalf("metadata must record reject: %+v", meta.SNIGuard)
	}
}

func TestSetSNIGuardIsolateRestoresFragment(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyReject}); err != nil {
		t.Fatal(err)
	}
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	confDir := filepath.Join(root, nginxDirRel)
	if got := readGuardTestFile(t, filepath.Join(confDir, "03-isolate.conf")); !strings.Contains(got, "ssl_reject_handshake on;") {
		t.Fatalf("isolate fragment not rewritten: %s", got)
	}
	main := readGuardTestFile(t, filepath.Join(root, nginx.InstallDirRel, "conf/nginx.conf"))
	if count := strings.Count(main, "03-isolate.conf"); count != 1 {
		t.Fatalf("isolate include must appear once, got %d: %s", count, main)
	}
	xrayConf := readGuardTestFile(t, filepath.Join(confDir, nginx.MainConf))
	if !strings.Contains(xrayConf, "127.0.0.1:9403") {
		t.Fatalf("deny upstream must point at 9403: %s", xrayConf)
	}
}

func TestSetSNIGuardDecoyGeneratesSite(t *testing.T) {
	root := seedGuardInstall(t)
	oldResolve := guardResolveHost
	guardResolveHost = func(string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	t.Cleanup(func() { guardResolveHost = oldResolve })

	rep, err := SetSNIGuard(context.Background(), SNIGuardSpec{
		Root: root, Policy: SNIPolicyDecoy, DecoyDomain: "decoy.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.SelfSigned || rep.DenyPort != GuardDecoyPort {
		t.Fatalf("unexpected report: %+v", rep)
	}
	certPath := filepath.Join(root, "etc/idleleo/cert/decoy.crt")
	keyPath := filepath.Join(root, "etc/idleleo/cert/decoy.key")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("generated pair is invalid: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key must be 0600, mode=%v", info.Mode().Perm())
	}
	frag := readGuardTestFile(t, filepath.Join(root, nginxDirRel, "03-decoy.conf"))
	if !strings.Contains(frag, "server_name decoy.example.com;") || !strings.Contains(frag, "listen 127.0.0.1:9444 ssl;") {
		t.Fatalf("decoy fragment wrong: %s", frag)
	}
	index := readGuardTestFile(t, filepath.Join(root, "etc/idleleo/decoy/index.html"))
	if !strings.Contains(index, "decoy.example.com") {
		t.Fatalf("decoy page missing domain: %s", index)
	}
	main := readGuardTestFile(t, filepath.Join(root, nginx.InstallDirRel, "conf/nginx.conf"))
	if !strings.Contains(main, "03-decoy.conf") || strings.Contains(main, "03-isolate.conf") {
		t.Fatalf("main include not switched: %s", main)
	}
	meta := loadGuardTestMetadata(t, root)
	if meta.SNIGuard == nil || meta.SNIGuard.DecoyDomain != "decoy.example.com" {
		t.Fatalf("metadata must record decoy: %+v", meta.SNIGuard)
	}
}

func TestSetSNIGuardRefusesDirectReality(t *testing.T) {
	root := sandbox(t)
	meta := store.Metadata{
		SchemaVersion: store.ManagerSchemaVersion, ActiveEngine: "xray", Role: "node",
		TLS: "Reality", Transport: "raw", RuntimeConfigPath: "etc/idleleo/conf/xray/config.json",
		RuntimeSHA256: strings.Repeat("a", 64), OwnedResources: []string{},
	}
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"), mustJSON(t, meta))
	_, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate})
	if err == nil || !strings.Contains(err.Error(), "managed Nginx front") {
		t.Fatalf("direct Reality must be refused: %v", err)
	}
}

func TestSetSNIGuardRestoresOnNginxTestFailure(t *testing.T) {
	root := seedGuardInstall(t)
	stubBalanceNginxTest(t, func(context.Context, string) error { return errors.New("bad config") })
	_, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyReject})
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, nginxDirRel, "03-isolate.conf")); statErr != nil {
		t.Fatal("isolate fragment must be restored")
	}
	xrayConf := readGuardTestFile(t, filepath.Join(root, nginxDirRel, nginx.MainConf))
	if !strings.Contains(xrayConf, "127.0.0.1:9403") {
		t.Fatalf("deny upstream must be restored: %s", xrayConf)
	}
	meta := loadGuardTestMetadata(t, root)
	if meta.SNIGuard != nil {
		t.Fatalf("metadata must be restored: %+v", meta.SNIGuard)
	}
}

func TestSetSNIGuardRefusesPortConflict(t *testing.T) {
	root := seedGuardInstall(t)
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"),
		[]byte(`{"inbounds":[{"port":9404}]}`))
	_, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyReject})
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("port conflict must be refused: %v", err)
	}
}

func TestInspectSNIGuardReportsDeployedPolicy(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Applicable || !st.ManagedFront || !st.MetadataSynced {
		t.Fatalf("unexpected status: %+v", st)
	}
	if st.Status != "active" || !st.Enabled || st.Policy != SNIPolicyIsolate || st.DenyPort != GuardIsolatePort {
		t.Fatalf("inspect must derive isolate from the deployed front: %+v", st)
	}
}

func TestInspectSNIGuardDetectsMetadataDrift(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	meta := loadGuardTestMetadata(t, root)
	meta.SNIGuard.Policy = SNIPolicyReject
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"), mustJSON(t, meta))

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "drift" || st.Policy != SNIPolicyIsolate {
		t.Fatalf("a metadata/artifact mismatch must be reported as drift: %+v", st)
	}
	if len(st.Warnings) == 0 {
		t.Fatal("drift must explain itself")
	}
}

func TestInspectSNIGuardDetectsFragmentNotIncluded(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	// Simulate a broken hand edit: the fragment exists but the main config no
	// longer includes it, so the policy is not actually deployed.
	writeGuardTestFile(t, filepath.Join(root, "usr/local/nginx/conf/nginx.conf"),
		[]byte("http {\n    # include removed\n}\n"))
	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "inconsistent" {
		t.Fatalf("an unreferenced fragment must not be reported as active: %+v", st)
	}
}

func TestInspectSNIGuardAcceptsGlobInclude(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	writeGuardTestFile(t, filepath.Join(root, "usr/local/nginx/conf/nginx.conf"),
		[]byte("http {\n    include /etc/idleleo/conf/nginx/*.conf;\n}\n"))
	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "active" || st.Policy != SNIPolicyIsolate {
		t.Fatalf("a glob include covers the fragment: %+v", st)
	}
}

func TestInspectSNIGuardDoesNotInventDefault(t *testing.T) {
	root := sandbox(t)
	meta := store.Metadata{
		SchemaVersion: store.ManagerSchemaVersion, ActiveEngine: "xray", Role: "node",
		TLS: "Vision", Transport: "tcp", RuntimeConfigPath: "etc/idleleo/conf/xray/config.json",
		RuntimeSHA256: strings.Repeat("a", 64), OwnedResources: []string{},
	}
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"), mustJSON(t, meta))
	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Applicable || st.Enabled || st.Policy != "" || st.Status != "not-applicable" {
		t.Fatalf("a node without a Reality+Nginx front must not report an enabled policy: %+v", st)
	}
}

func TestInspectSNIGuardReportsUnsyncedMetadata(t *testing.T) {
	root := seedGuardInstall(t)
	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.MetadataSynced {
		t.Fatalf("metadata without sniGuard must not be reported as synced: %+v", st)
	}
	if !st.Applicable || st.Policy != SNIPolicyIsolate {
		t.Fatalf("deployed artifacts must still be shown: %+v", st)
	}
}

func loadGuardTestMetadata(t *testing.T, root string) store.Metadata {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "etc/idleleo/v1/metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta store.Metadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return meta
}
