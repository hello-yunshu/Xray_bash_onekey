package deploy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

// ErrOriginUnreachable marks a Reality origin probe failure. The edit path
// treats it as a refusal: nothing is written.
var ErrOriginUnreachable = errors.New("origin unreachable")

// probeOrigin is a seam so tests can exercise the edit flow without network.
var probeOrigin = defaultProbeOrigin

const (
	probeDialTimeout = 5 * time.Second
	probeTLSTimeout  = 5 * time.Second
)

// probeTLSConfig is a seam so tests can trust a throwaway CA without touching
// the host trust store. It must stay equivalent to an ordinary client: system
// roots, no OCSP lookups, Go's default TLS version range.
var probeTLSConfig = func(sni string) *tls.Config {
	return &tls.Config{ServerName: sni}
}

// defaultProbeOrigin checks that the Reality target accepts a TCP connection
// and, when an SNI is supplied, completes a TLS handshake that validates the
// certificate chain and the server name. That is the same bar a client of the
// stolen certificate faces; no extra checks (OCSP, minimum TLS version) are
// layered on top.
func defaultProbeOrigin(ctx context.Context, target, sni string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	if host == "" {
		return fmt.Errorf("%w: target %q has no host", ErrOriginUnreachable, target)
	}
	addr := net.JoinHostPort(host, port)
	dialer := net.Dialer{Timeout: probeDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("%w: tcp connect to %s failed: %v", ErrOriginUnreachable, addr, err)
	}
	defer conn.Close()
	if sni == "" {
		return nil
	}
	tlsConn := tls.Client(conn, probeTLSConfig(sni))
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(probeTLSTimeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: tls handshake with %s (sni %s) failed: %v",
			ErrOriginUnreachable, addr, sni, err)
	}
	return nil
}

func probeDescription(target, sni string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	if sni != "" {
		return fmt.Sprintf("tcp+tls(verify) %s (sni %s)", net.JoinHostPort(host, port), sni)
	}
	return "tcp " + net.JoinHostPort(host, port)
}

// probeOriginIfRequested probes the effective Reality origin only when the
// operator asked to change --target or --server-names.
func probeOriginIfRequested(ctx context.Context, req xraycfg.EditRequest, res xraycfg.EditResult, report *EditReport, noProbe bool) error {
	if req.Target == "" && len(req.ServerNames) == 0 {
		return nil
	}
	if noProbe {
		report.OriginProbe = "skipped: --no-probe"
		return nil
	}
	sni := ""
	if len(res.ServerNames) > 0 {
		sni = res.ServerNames[0]
	}
	target := res.Target
	if target == "" && sni != "" {
		target = net.JoinHostPort(sni, "443")
	}
	if target == "" {
		return nil
	}
	if err := probeOrigin(ctx, target, sni); err != nil {
		return fmt.Errorf("%w; configuration was not changed", err)
	}
	report.OriginTarget = target
	report.OriginProbe = probeDescription(target, sni)
	return nil
}
