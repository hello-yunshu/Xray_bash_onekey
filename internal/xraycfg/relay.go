package xraycfg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/compat"
)

// RelaySpec is one standalone Nginx stream relay.
type RelaySpec struct {
	ListenPort  int
	BackendHost string
	BackendPort int
	SNI         string
}

// RelayConf renders the project-owned Nginx stream fragment. It contains no
// Nginx main-context directives, so it must be included from stream{}.
func RelayConf(spec RelaySpec) (string, error) {
	if spec.ListenPort < 1 || spec.ListenPort > 65535 {
		return "", fmt.Errorf("listen port must be between 1 and 65535")
	}
	host := strings.TrimSpace(spec.BackendHost)
	if host == "" {
		return "", fmt.Errorf("backend host required")
	}
	if !compat.RelayIsValidHost(strings.Trim(host, "[]")) {
		return "", fmt.Errorf("invalid backend host %q", host)
	}
	if spec.BackendPort < 1 || spec.BackendPort > 65535 {
		return "", fmt.Errorf("backend port must be between 1 and 65535")
	}
	upstream := net.JoinHostPort(host, strconv.Itoa(spec.BackendPort))
	return fmt.Sprintf(`# Managed by Xray_bash_onekey (Go). Standalone relay, no Xray/UUID/cert.
stream {
    upstream idleleo_relay_backend {
        server %s;
    }
    server {
        listen %d;
        proxy_pass idleleo_relay_backend;
        proxy_timeout 300s;
        proxy_connect_timeout 10s;
    }
}
`, upstream, spec.ListenPort), nil
}
