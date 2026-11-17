package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallRelayWritesConfAndInclude(t *testing.T) {
	root := sandbox(t)
	stubManagedNginx(t, nil, nil)
	spec := RelayInstallSpec{
		Root: root, BackendHost: "origin.example.com", BackendPort: 443,
		ListenPort: 8443, ListenAddress: "0.0.0.0", NoService: true,
	}
	rep, err := InstallRelay(context.Background(), spec)
	if err != nil {
		t.Fatalf("relay install: %v", err)
	}
	confPath := filepath.Join(root, "etc/idleleo/conf/nginx/relay-stream.conf")
	body := readFile(t, confPath)
	for _, needle := range []string{"stream {", "listen 0.0.0.0:8443;", "proxy_pass origin.example.com:443;"} {
		if !strings.Contains(body, needle) {
			t.Fatalf("relay-stream.conf missing %q:\n%s", needle, body)
		}
	}
	if rep.ConfigPath != confPath || rep.Listen != "0.0.0.0:8443" || rep.Backend != "origin.example.com:443" {
		t.Fatalf("unexpected relay report: %+v", rep)
	}

	mainPath := filepath.Join(root, "usr/local/nginx/conf/nginx.conf")
	mainBody := readFile(t, mainPath)
	include := "include /etc/idleleo/conf/nginx/relay-stream.conf;"
	marker := "# Xray_bash_onekey relay node (managed)"
	if !strings.Contains(mainBody, include) {
		t.Fatalf("main config missing relay include:\n%s", mainBody)
	}
	if !strings.Contains(mainBody, marker) {
		t.Fatalf("main config missing relay marker:\n%s", mainBody)
	}
	// Relay nodes have no Xray inbound fragments; bash writes neither the files
	// nor the includes, so a relay install must not leave dead node includes.
	for _, dead := range []string{"00-xray.conf", "03-isolate.conf"} {
		if strings.Contains(mainBody, "include /etc/idleleo/conf/nginx/"+dead+";") {
			t.Fatalf("relay main config still includes %s:\n%s", dead, mainBody)
		}
		if _, err := os.Stat(filepath.Join(root, "etc/idleleo/conf/nginx", dead)); !os.IsNotExist(err) {
			t.Fatalf("relay install created node fragment %s (stat err %v)", dead, err)
		}
	}
	// The http glob would pull relay-stream.conf into http{} and nginx rejects
	// the stream directive there.
	if strings.Contains(mainBody, "include /etc/idleleo/conf/nginx/*.conf;") {
		t.Fatalf("relay main config uses the http *.conf glob:\n%s", mainBody)
	}

	meta := readFile(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"))
	if !strings.Contains(meta, "relay") {
		t.Fatalf("metadata does not record the relay role: %s", meta)
	}

	// A second run must succeed and must not duplicate the include.
	if _, err := InstallRelay(context.Background(), spec); err != nil {
		t.Fatalf("second relay install: %v", err)
	}
	mainBody = readFile(t, mainPath)
	count := 0
	for _, line := range strings.Split(mainBody, "\n") {
		if strings.TrimSpace(line) == include {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("relay include appears %d times, want 1:\n%s", count, mainBody)
	}
	// The relay fragment itself must still be present after the reinstall.
	if _, err := os.Stat(confPath); err != nil {
		t.Fatalf("relay fragment missing after reinstall: %v", err)
	}
}
