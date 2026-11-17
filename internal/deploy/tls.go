package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// certWarnWindow mirrors schedule.CertRenewWindow: a certificate inside it is
// still accepted, but the operator is told the renewal job is the next step.
const certWarnWindow = 30 * 24 * time.Hour

// tlsPairInfo is what the edit path needs from the configured pair.
type tlsPairInfo struct {
	NotAfter time.Time
	SANs     []string
	LeafDER  []byte
}

// inspectTLSPair validates that certPath/keyPath form one usable pair for
// domain. A mismatch is refused instead of written: the Nginx reload would
// otherwise fail every new handshake while the old sessions keep working.
func inspectTLSPair(domain, certPath, keyPath string) (tlsPairInfo, []string, error) {
	var info tlsPairInfo
	certPEM, _, err := store.ReadRegular(certPath, "certificate "+certPath)
	if err != nil {
		return info, nil, err
	}
	keyPEM, keyMode, err := store.ReadRegular(keyPath, "private key "+keyPath)
	if err != nil {
		return info, nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return info, nil, fmt.Errorf("%s and %s are not a valid certificate/key pair: %w", certPath, keyPath, err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return info, nil, fmt.Errorf("certificate %s is not parseable: %w", certPath, err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return info, nil, fmt.Errorf("certificate %s is not valid before %s", certPath, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return info, nil, fmt.Errorf("certificate %s expired at %s; issue a new pair with 'idleleo xray cert issue'", certPath, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if domain != "" {
		if err := leaf.VerifyHostname(domain); err != nil {
			return info, nil, fmt.Errorf("certificate %s does not cover %q (SAN %v); renew the certificate before changing the domain",
				certPath, domain, leaf.DNSNames)
		}
	}
	info = tlsPairInfo{
		NotAfter: leaf.NotAfter,
		SANs:     append([]string(nil), leaf.DNSNames...),
		LeafDER:  append([]byte(nil), leaf.Raw...),
	}
	if len(info.SANs) == 0 && leaf.Subject.CommonName != "" {
		info.SANs = []string{leaf.Subject.CommonName}
	}
	warnings := []string{}
	if days := int(time.Until(leaf.NotAfter).Hours() / 24); days < int(certWarnWindow.Hours()/24) {
		warnings = append(warnings, fmt.Sprintf(
			"certificate %s expires in %d days; this command never re-issues, run 'idleleo schedule run --job cert-renew' (or 'xray cert renew')",
			certPath, days))
	}
	if keyMode.Perm()&0o004 != 0 {
		warnings = append(warnings, fmt.Sprintf("private key %s is world-readable (mode %04o)", keyPath, keyMode.Perm()))
	}
	return info, warnings, nil
}

// tlsProbeResult is one successful local handshake observation.
type tlsProbeResult struct {
	ServerName    string
	Version       string
	NotAfter      time.Time
	SystemTrusted bool
	TrustError    string
}

// errTLSServiceInactive separates "the front is not listening" from "the front
// answered with the wrong certificate". Only the latter fails the edit.
var errTLSServiceInactive = errors.New("local TLS front is not listening")

// certMismatchError marks a handshake that reached the previous Nginx
// generation. Reload is asynchronous: SIGHUP returns before the new workers
// accept connections, so the probe gives it a short window before failing.
type certMismatchError struct{ addr string }

func (e certMismatchError) Error() string {
	return fmt.Sprintf("front at %s serves a certificate that differs from the configured file", e.addr)
}

const (
	probeRetryWindow = 5 * time.Second
	probeRetryDelay  = 150 * time.Millisecond
)

// probeTLSServer is a seam so sandbox tests can avoid a real Nginx.
var probeTLSServer = defaultProbeTLSServer

// defaultProbeTLSServer connects to the local front with the new SNI, then
// checks the served leaf against the configured file, the domain, the validity
// window and the TLS version. System-root trust is reported separately: a
// staging or private CA is not an edit failure, but it must not look like a
// pass either.
func defaultProbeTLSServer(ctx context.Context, addr, serverName string, wantDER []byte) (tlsProbeResult, error) {
	var res tlsProbeResult
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return res, fmt.Errorf("%w at %s: %v", errTLSServiceInactive, addr, err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return res, fmt.Errorf("TLS handshake with %s (SNI %s) failed: %w", addr, serverName, err)
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return res, fmt.Errorf("front at %s presented no certificate", addr)
	}
	leaf := state.PeerCertificates[0]
	if len(wantDER) > 0 && !bytes.Equal(leaf.Raw, wantDER) {
		return res, certMismatchError{addr: addr}
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return res, fmt.Errorf("served certificate does not cover %q: %w", serverName, err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return res, fmt.Errorf("served certificate is outside its validity window (%s - %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if state.Version < tls.VersionTLS13 {
		return res, fmt.Errorf("front negotiated %s; the managed site requires TLS 1.3", tls.VersionName(state.Version))
	}
	res = tlsProbeResult{ServerName: serverName, Version: tls.VersionName(state.Version), NotAfter: leaf.NotAfter}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates}); err != nil {
		res.TrustError = err.Error()
	} else {
		res.SystemTrusted = true
	}
	return res, nil
}

// probeLocalTLS runs the handshake and records it on the report. A front that
// is not listening is a warning, never a pass.
func probeLocalTLS(ctx context.Context, report *EditReport, addr, domain string, wantDER []byte) error {
	report.TLSProbe = "skipped"
	deadline := time.Now().Add(probeRetryWindow)
	var res tlsProbeResult
	var err error
	for {
		res, err = probeTLSServer(ctx, addr, domain, wantDER)
		var mismatch certMismatchError
		if err != nil && errors.As(err, &mismatch) && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(probeRetryDelay):
				continue
			}
		}
		break
	}
	switch {
	case errors.Is(err, errTLSServiceInactive):
		report.Warnings = append(report.Warnings, "local TLS handshake not verified: "+err.Error())
		report.TLSProbe = "skipped: service unreachable"
		return nil
	case err != nil:
		return err
	}
	report.TLSProbe = "ok"
	report.TLSServerName = res.ServerName
	report.TLSVersion = res.Version
	report.TLSTrusted = res.SystemTrusted
	if !res.SystemTrusted {
		report.Warnings = append(report.Warnings,
			"served certificate chain is not trusted by the system roots (staging or private CA?): "+res.TrustError)
	}
	return nil
}

// probeAddress is the loopback address the local handshake targets. The
// managed site always listens on the public port; 443 is the historical
// default when the parsed value is missing.
func probeAddress(publicPort int) string {
	if publicPort == 0 {
		publicPort = 443
	}
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(publicPort))
}

// describeSANs renders the SAN list for the manifest and CLI report.
func describeSANs(sans []string) string {
	if len(sans) == 0 {
		return "-"
	}
	return strings.Join(sans, ",")
}
