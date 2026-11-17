package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Lookup resolves a domain to its A records followed by its AAAA records.
// resolverAddr, when set, is a host:port UDP/TCP resolver used for both record
// types: the transport is independent of the address family being queried, so
// an IPv4-only server can still detect a stale AAAA record.
//
// A family with no records is not an error (that is how dig reports an empty
// NOERROR answer). Lookup fails only when both queries fail for a reason other
// than "name does not exist"; an NXDOMAIN returns an empty set so the caller
// reports mode=none instead of inventing records.
func Lookup(ctx context.Context, domain, resolverAddr string) ([]string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	if resolverAddr != "" {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if strings.HasPrefix(network, "tcp") {
					return dialer.DialContext(ctx, "tcp", resolverAddr)
				}
				return dialer.DialContext(ctx, "udp", resolverAddr)
			},
		}
	}

	var records []string
	failures := 0
	for _, family := range []string{"ip4", "ip6"} {
		ips, err := resolver.LookupIP(ctx, family, domain)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue
			}
			failures++
			continue
		}
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			records = append(records, ip.String())
		}
	}
	if failures == 2 {
		return nil, fmt.Errorf("resolve %s: both A and AAAA queries failed", domain)
	}
	return records, nil
}

// LocalPublicIPs returns the first global unicast IPv4 and IPv6 address bound
// to an up, non-loopback interface. It is a local view only: no outbound echo
// probe is performed, so a private address can be returned on an isolated host.
// Callers may override either value with an explicit flag.
func LocalPublicIPs() (v4, v6 string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil || ip.IsLoopback() || !ip.IsGlobalUnicast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if v4 == "" {
					v4 = ip4.String()
				}
				continue
			}
			if ip.IsLinkLocalUnicast() {
				continue
			}
			if v6 == "" {
				v6 = ip.String()
			}
		}
	}
	return v4, v6
}
