package deploy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// seedBalanceInstall writes the metadata and Nginx fragments a real install
// leaves behind, so the tests exercise the same gates as production.
func seedBalanceInstall(t *testing.T, tls, balanceRole string) string {
	t.Helper()
	root := sandbox(t)
	meta := store.Metadata{
		SchemaVersion:     store.ManagerSchemaVersion,
		ActiveEngine:      "xray",
		Role:              "node",
		TLS:               tls,
		Transport:         "raw",
		RuntimeConfigPath: "usr/local/etc/xray/config.json",
		RuntimeSHA256:     strings.Repeat("a", 64),
		OwnedResources:    []string{},
		UpdatedAt:         "2026-01-01T00:00:00Z",
		BalanceRole:       balanceRole,
		Install:           &store.InstallSnapshot{Port: 443, ServerNames: []string{"node.example.com"}},
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
	dir := filepath.Join(root, nginxDirRel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	frags := map[string]string{
		"00-xray.conf": `stream {
    upstream reality {
        include /etc/idleleo/conf/nginx/*.realityServers;
    }
}
`,
		"02-xray-server.conf": `upstream ws {
    include /etc/idleleo/conf/nginx/*.wsServers;
}
upstream grpc {
    include /etc/idleleo/conf/nginx/*.grpcServers;
}
upstream xhttp {
    include /etc/idleleo/conf/nginx/*.xhttpServers;
}
`,
		"127.0.0.1.realityServers":     "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n",
		"127.0.0.1.wsServers":          "server 127.0.0.1:10001 weight=50 max_fails=2 fail_timeout=10;\n",
		"node.example.com.serverNames": "node.example.com reality;\n",
	}
	for name, body := range frags {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func stubBalanceNginxTest(t *testing.T, fn func(context.Context, string) error) {
	t.Helper()
	oldTest := balanceNginxTest
	oldCmd, oldQuery, oldManaged := serviceCommand, serviceQuery, serviceManaged
	balanceNginxTest = fn
	serviceCommand = func(context.Context, ...string) error { return nil }
	serviceQuery = func(context.Context, ...string) string { return "" }
	serviceManaged = func(string) bool { return true }
	t.Cleanup(func() {
		balanceNginxTest = oldTest
		serviceCommand, serviceQuery, serviceManaged = oldCmd, oldQuery, oldManaged
	})
}

func TestBalanceRefusesRealityNginx(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "")
	spec := BalanceSpec{Root: root, Upstream: BalanceUpstreamReality}
	if _, err := ListBalance(spec); err == nil || !strings.Contains(err.Error(), "reality-balance primary") {
		t.Fatalf("reality-nginx must be refused with a pointer to reality-balance: %v", err)
	}
	if _, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.2", Port: 8443,
	}); err == nil {
		t.Fatal("add must be refused on reality-nginx")
	}
}

func TestBalanceRefusesLegacyMetadata(t *testing.T) {
	// An install from before balanceRole existed has TLS=Reality and no role.
	root := seedBalanceInstall(t, "Reality", "")
	_, err := RemoveBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.2",
	})
	if err == nil || !strings.Contains(err.Error(), "--mode reality-balance --role primary") {
		t.Fatalf("legacy metadata must be refused instead of guessed: %v", err)
	}
}

func TestBalanceRefusesSecondary(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "secondary")
	if _, err := ListBalance(BalanceSpec{Root: root, Upstream: BalanceUpstreamReality}); err == nil ||
		!strings.Contains(err.Error(), "reality-balance primary") {
		t.Fatalf("secondary must not manage the front: %v", err)
	}
}

func TestBalanceRefusesUnmanagedFront(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	if err := os.Remove(filepath.Join(root, nginxDirRel, "00-xray.conf")); err != nil {
		t.Fatal(err)
	}
	_, err := ListBalance(BalanceSpec{Root: root, Upstream: BalanceUpstreamReality})
	if err == nil || !strings.Contains(err.Error(), "not a managed Nginx front") {
		t.Fatalf("a missing include anchor must be refused: %v", err)
	}
}

func TestBalanceAddWritesOneFilePerHost(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	rep, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.2", Port: 8443, Weight: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, nginxDirRel, "10.0.0.2.realityServers")
	want := "server 10.0.0.2:8443 weight=60 max_fails=2 fail_timeout=10;\n"
	if got := readFile(t, file); got != want {
		t.Fatalf("backend file = %q, want %q", got, want)
	}
	if rep.File != file || !rep.Changed || rep.Probed {
		t.Fatalf("unexpected report: %+v", rep)
	}
	// The local primary file must not be touched.
	if got := readFile(t, filepath.Join(root, nginxDirRel, "127.0.0.1.realityServers")); got != "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n" {
		t.Fatalf("primary fragment was rewritten: %q", got)
	}
	if !hasWarning(rep.Warnings, noBalanceProbeWarning) {
		t.Fatalf("default add must warn that no probe ran: %v", rep.Warnings)
	}
}

func TestBalanceAddRejectsBadInput(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	base := BalanceSpec{Root: root, Upstream: BalanceUpstreamReality, Port: 8443}
	cases := []struct {
		name string
		spec BalanceSpec
		want string
	}{
		{"slash host", func() BalanceSpec { s := base; s.Host = "10.0.0.2/../../etc"; return s }(), "invalid backend host"},
		{"space host", func() BalanceSpec { s := base; s.Host = "bad host"; return s }(), "invalid backend host"},
		{"reserved port", func() BalanceSpec {
			s := base
			s.Host, s.Port = "10.0.0.3", 443
			return s
		}(), "reserved"},
		{"bad weight", func() BalanceSpec {
			s := base
			s.Host, s.Weight = "10.0.0.4", 101
			return s
		}(), "weight"},
		{"bad port", func() BalanceSpec {
			s := base
			s.Host, s.Port = "10.0.0.5", 70000
			return s
		}(), "port"},
	}
	for _, tc := range cases {
		if _, err := AddBalance(context.Background(), tc.spec); err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		} else if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
	// A second add on the same host is refused with a remove-first hint.
	if _, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.9", Port: 8443,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.9", Port: 8444,
	}); err == nil || !strings.Contains(err.Error(), "remove it first") {
		t.Fatalf("duplicate host must ask for remove first: %v", err)
	}
}

func TestBalanceAddRollsBackOnNginxFailure(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	stubBalanceNginxTest(t, func(context.Context, string) error {
		return os.ErrInvalid
	})
	_, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.7", Port: 8443,
	})
	if err == nil {
		t.Fatal("nginx -t failure must abort the add")
	}
	if _, statErr := os.Lstat(filepath.Join(root, nginxDirRel, "10.0.0.7.realityServers")); !os.IsNotExist(statErr) {
		t.Fatalf("failed add must leave no backend file, stat=%v", statErr)
	}
}

func TestBalanceProbeFailureWritesNothing(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	// Nothing listens on this loopback address, so the probe fails.
	_, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "127.0.0.2", Port: 65000, Probe: true,
	})
	if err == nil {
		t.Fatal("a failed probe must abort the add")
	}
	if _, statErr := os.Lstat(filepath.Join(root, nginxDirRel, "127.0.0.2.realityServers")); !os.IsNotExist(statErr) {
		t.Fatalf("a failed probe must leave no backend file, stat=%v", statErr)
	}
}

func TestBalanceRemoveRefusesLastLocalAndRestores(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	// The only backend is the loopback one: refuse both as loopback and as last.
	if _, err := RemoveBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "127.0.0.1",
	}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("loopback backend must be refused: %v", err)
	}
	if _, err := RemoveBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.2",
	}); err == nil || !strings.Contains(err.Error(), "no backend file") {
		t.Fatalf("missing backend must be reported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, nginxDirRel, "10.0.0.2.realityServers"),
		[]byte("server 10.0.0.2:8443 weight=50 max_fails=2 fail_timeout=10;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := RemoveBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.2", Port: 8443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Changed || rep.File == "" {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if _, statErr := os.Lstat(filepath.Join(root, nginxDirRel, "10.0.0.2.realityServers")); !os.IsNotExist(statErr) {
		t.Fatalf("removed backend still on disk: %v", statErr)
	}
	// Now leave a single non-loopback backend: removing it would empty the
	// upstream, so it must be refused as the last one.
	if err := os.Remove(filepath.Join(root, nginxDirRel, "127.0.0.1.realityServers")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, nginxDirRel, "10.0.0.3.realityServers"),
		[]byte("server 10.0.0.3:8443 weight=50 max_fails=2 fail_timeout=10;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.3",
	}); err == nil || !strings.Contains(err.Error(), "last") {
		t.Fatalf("last backend must be refused: %v", err)
	}
}

func TestBalanceRemoveRestoresOnNginxFailure(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	stubBalanceNginxTest(t, func(context.Context, string) error { return os.ErrInvalid })
	file := filepath.Join(root, nginxDirRel, "10.0.0.2.realityServers")
	body := "server 10.0.0.2:8443 weight=50 max_fails=2 fail_timeout=10;\n"
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamReality, Host: "10.0.0.2",
	}); err == nil {
		t.Fatal("nginx -t failure must abort the remove")
	}
	if got := readFile(t, file); got != body {
		t.Fatalf("removed backend was not restored: %q", got)
	}
}

func TestBalanceListReportsBackends(t *testing.T) {
	root := seedBalanceInstall(t, "Reality", "primary")
	if err := os.WriteFile(filepath.Join(root, nginxDirRel, "10.0.0.2.realityServers"),
		[]byte("server 10.0.0.2:8443 weight=70 max_fails=2 fail_timeout=10;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := ListBalance(BalanceSpec{Root: root, Upstream: BalanceUpstreamReality})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Backends) != 2 {
		t.Fatalf("backends = %+v, want 2", rep.Backends)
	}
	if b := rep.Backends[0]; b.Host != "10.0.0.2" || b.Port != 8443 || b.Weight != 70 {
		t.Fatalf("backend[0] = %+v", b)
	}
	if rep.Backends[1].Host != "127.0.0.1" || rep.Backends[1].Port != 9443 {
		t.Fatalf("backend[1] = %+v", rep.Backends[1])
	}
	if rep.Changed {
		t.Fatal("list must be read-only")
	}
}

func TestBalanceTLSUpstreamGate(t *testing.T) {
	root := seedBalanceInstall(t, "TLS", "")
	stubBalanceNginxTest(t, func(context.Context, string) error { return nil })
	if _, err := ListBalance(BalanceSpec{Root: root, Upstream: BalanceUpstreamReality}); err == nil {
		t.Fatal("reality upstream must not exist on a TLS install")
	}
	if _, err := AddBalance(context.Background(), BalanceSpec{
		Root: root, Upstream: BalanceUpstreamWS, Host: "10.0.0.2", Port: 8443,
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(root, nginxDirRel, "10.0.0.2.wsServers")); got != "server 10.0.0.2:8443 weight=50 max_fails=2 fail_timeout=10;\n" {
		t.Fatalf("ws backend file = %q", got)
	}
}

func hasWarning(warnings []string, want string) bool {
	for _, w := range warnings {
		if w == want {
			return true
		}
	}
	return false
}
