package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// seedBalanceCLI creates a sandbox with metadata and the Nginx fragments a
// managed install leaves behind, so the CLI gates run for real.
func seedBalanceCLI(t *testing.T, tls, role string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, host.SandboxMarker), []byte(host.SandboxMarkerValue), 0o600); err != nil {
		t.Fatal(err)
	}
	meta := store.Metadata{
		SchemaVersion:     store.ManagerSchemaVersion,
		ActiveEngine:      "xray",
		Role:              "node",
		TLS:               tls,
		Transport:         "raw",
		RuntimeConfigPath: "usr/local/etc/xray/config.json",
		RuntimeSHA256:     strings.Repeat("b", 64),
		OwnedResources:    []string{},
		UpdatedAt:         "2026-01-01T00:00:00Z",
		BalanceRole:       role,
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
	dir := filepath.Join(root, "etc/idleleo/conf/nginx")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	frags := map[string]string{
		"00-xray.conf":             "upstream reality {\n    include /etc/idleleo/conf/nginx/*.realityServers;\n}\n",
		"127.0.0.1.realityServers": "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n",
		"10.0.0.2.realityServers":  "server 10.0.0.2:8443 weight=60 max_fails=2 fail_timeout=10;\n",
	}
	for name, body := range frags {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestXrayBalanceList(t *testing.T) {
	root := seedBalanceCLI(t, "Reality", "primary")
	code, out, errOut := run(t, "--root", root, "xray", "balance", "list", "--upstream", "reality")
	if code != 0 {
		t.Fatalf("list failed: %d %q", code, errOut)
	}
	if !strings.Contains(out, "127.0.0.1\t9443\t50\t") || !strings.Contains(out, "10.0.0.2\t8443\t60\t") {
		t.Fatalf("unexpected list output: %q", out)
	}
}

func TestXrayBalanceListJSON(t *testing.T) {
	root := seedBalanceCLI(t, "Reality", "primary")
	code, out, errOut := run(t, "--root", root, "--json", "xray", "balance", "list", "--upstream", "reality")
	if code != 0 {
		t.Fatalf("list failed: %d %q", code, errOut)
	}
	var rep struct {
		Upstream string `json:"upstream"`
		Backends []struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"backends"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid json %q: %v", out, err)
	}
	if rep.Upstream != "reality" || len(rep.Backends) != 2 {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

func TestXrayBalanceRefusesRealityNginx(t *testing.T) {
	root := seedBalanceCLI(t, "Reality", "")
	code, _, errOut := run(t, "--root", root, "xray", "balance", "add",
		"--upstream", "reality", "--host", "10.0.0.3", "--port", "8443")
	if code == 0 || !strings.Contains(errOut, "reality-balance primary") {
		t.Fatalf("reality-nginx must be refused: %d %q", code, errOut)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/idleleo/conf/nginx/10.0.0.3.realityServers")); !os.IsNotExist(err) {
		t.Fatalf("refused add must not write a file: %v", err)
	}
}

func TestXrayBalanceRequiresUpstreamAndHost(t *testing.T) {
	root := seedBalanceCLI(t, "Reality", "primary")
	if code, _, _ := run(t, "--root", root, "xray", "balance", "list"); code == 0 {
		t.Fatal("--upstream is required")
	}
	if code, _, _ := run(t, "--root", root, "xray", "balance", "add", "--upstream", "reality"); code == 0 {
		t.Fatal("--host is required for add")
	}
}
