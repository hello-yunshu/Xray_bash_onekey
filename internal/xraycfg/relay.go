package xraycfg

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/compat"
)

// RelaySpec is one standalone Nginx stream relay.
//
// ListenAddress mirrors the Bash relay_render_stream_conf contract: the
// operator chooses an explicit bind address (0.0.0.0, a specific IPv4 or IPv6
// literal). An empty ListenAddress keeps the Bash default of 0.0.0.0.
type RelaySpec struct {
	ListenAddress string
	ListenPort    int
	BackendHost   string
	BackendPort   int
	SNI           string
}

// RelayConf renders the project-owned Nginx stream fragment. It contains no
// Nginx main-context directives, so it must be included from stream{}.
//
// Directive values mirror install.sh relay_render_stream_conf: an explicit
// listen address, proxy_connect_timeout 10s, proxy_timeout 720m and
// proxy_socket_keepalive on. Direct proxy_pass is used (no upstream block) so
// the rendered fragment stays semantically identical to the Bash one.
func RelayConf(spec RelaySpec) (string, error) {
	addr := strings.TrimSpace(spec.ListenAddress)
	if addr == "" {
		addr = "0.0.0.0"
	}
	if !ValidListenAddress(addr) {
		return "", fmt.Errorf("invalid listen address %q: expected an IPv4 or IPv6 literal", addr)
	}
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
	listen := net.JoinHostPort(addr, strconv.Itoa(spec.ListenPort))
	upstream := net.JoinHostPort(host, strconv.Itoa(spec.BackendPort))
	return fmt.Sprintf(`# Managed by Xray_bash_onekey (Go). Standalone relay, no Xray/UUID/cert.
stream {
    server {
        listen %s;
        proxy_pass %s;
        proxy_connect_timeout 10s;
        proxy_timeout 720m;
        proxy_socket_keepalive on;
    }
}
`, listen, upstream), nil
}

// ValidListenAddress mirrors install.sh is_valid_listen_address: only IPv4 and
// IPv6 literals are accepted (no hostnames, no brackets). Go additionally
// requires the literal to parse, so malformed shorthand is refused instead of
// reaching nginx -t.
func ValidListenAddress(addr string) bool {
	if addr == "" || strings.ContainsAny(addr, "[]") {
		return false
	}
	parsed, err := netip.ParseAddr(addr)
	return err == nil && parsed.IsValid()
}
