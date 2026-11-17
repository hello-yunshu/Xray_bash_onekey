package nginx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// LocalAddress returns the host's primary non-loopback IPv4 address. It mirrors
// the address detection used by the Bash installer so the managed main config
// gets the same direct-IP 403 guard by default.
func LocalAddress(ctx context.Context) (string, error) {
	if res, err := host.Run(ctx, host.ExecSpec{
		Path: "ip", Args: []string{"-4", "route", "get", "1.1.1.1"}, Timeout: 5 * time.Second,
	}); err == nil && res.ExitCode == 0 {
		fields := strings.Fields(res.Stdout)
		for i, field := range fields {
			if field == "src" && i+1 < len(fields) && isLocalIPv4(fields[i+1]) {
				return fields[i+1], nil
			}
		}
	}
	res, err := host.Run(ctx, host.ExecSpec{
		Path: "hostname", Args: []string{"-I"}, Timeout: 5 * time.Second,
	})
	if err == nil && res.ExitCode == 0 {
		for _, field := range strings.Fields(res.Stdout) {
			if isLocalIPv4(field) {
				return field, nil
			}
		}
	}
	return "", fmt.Errorf("no non-loopback IPv4 address found")
}

func isLocalIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}
