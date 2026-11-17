package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// realityProbeTarget is a destination the tunnel must reach *through* VLESS.
// A bare handshake with the fallback target cannot distinguish an accepted
// credential: Reality forwards unauthenticated TLS to `dest`, which completes
// a TLS handshake too. Handshaking with a different host inside the tunnel
// only succeeds when the VLESS layer authenticated, because the fallback never
// dials the SOCKS destination.
const (
	realityProbeTarget = "example.com:443"
	// realityProbeHTTPTarget is the authenticated-request leg. When Reality
	// rejects a credential it forwards the outer TLS stream to `dest`; the
	// plaintext request then never reaches this destination, so only a real
	// VLESS session returns the marker.
	realityProbeHTTPTarget = "example.com:80"
	realityProbeHTTPMarker = "Example Domain"
)

// verifyRealityHandshake is a seam for unit tests; production always runs a
// real client process against the installed binary.
var verifyRealityHandshake = runRealityHandshake

// hashTree is the content fingerprint of a directory tree. It is used to prove
// that a reality-balance edit never rewrote the upstream files.
func hashTree(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	sum := sha256.New()
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(sum, "%s\n", name)
		sum.Write(body)
		sum.Write([]byte{'\n'})
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// runRealityHandshake starts a real Xray client with the share link and proves
// a VLESS+Reality session by completing a TLS handshake to a public target
// through its SOCKS inbound. A config that merely parses is not enough: the
// private key, shortId, SNI and public key must all agree end to end.
func runRealityHandshake(ctx context.Context, root, shareURI, addr string) error {
	link, err := parseShareURI(shareURI)
	if err != nil {
		return err
	}
	bin, err := host.NewPaths(root)
	if err != nil {
		return err
	}
	binPath, err := bin.Join(binaryRel, false)
	if err != nil {
		return err
	}
	if _, err := os.Stat(binPath); err != nil {
		return fmt.Errorf("xray client binary unavailable: %w", err)
	}
	socksPort, err := freePort()
	if err != nil {
		return err
	}
	cfgPath, cleanup, err := writeClientConfig(link, addr, socksPort)
	if err != nil {
		return err
	}
	defer cleanup()

	runCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cmd := &execCommand{}
	var stderr bytes.Buffer
	if err := cmd.start(runCtx, binPath, cfgPath, &stderr); err != nil {
		return fmt.Errorf("xray client failed to start: %w", err)
	}
	defer cmd.stop()

	if err := waitPort(runCtx, socksPort, 6*time.Second); err != nil {
		return fmt.Errorf("xray client did not open socks: %w (%s)", err, tail(stderr.String()))
	}
	conn, err := dialSocks("127.0.0.1:"+strconv.Itoa(socksPort), realityProbeTarget)
	if err != nil {
		return fmt.Errorf("socks connect through reality failed: %w (%s)", err, tail(stderr.String()))
	}
	defer conn.Close()
	hostName, _, _ := net.SplitHostPort(realityProbeTarget)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostName, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(runCtx); err != nil {
		return fmt.Errorf("reality handshake with %s failed: %w (%s)", realityProbeTarget, err, tail(stderr.String()))
	}
	_ = tlsConn.Close()
	if err := probeRealityRequest(runCtx, "127.0.0.1:"+strconv.Itoa(socksPort)); err != nil {
		return fmt.Errorf("reality request through %s failed: %w (%s)", realityProbeHTTPTarget, err, tail(stderr.String()))
	}
	return nil
}

// probeRealityRequest proves the VLESS layer authenticated: the HTTP response
// must come from the requested destination, which the Reality fallback never
// dials.
func probeRealityRequest(ctx context.Context, proxy string) error {
	conn, err := dialSocks(proxy, realityProbeHTTPTarget)
	if err != nil {
		return err
	}
	defer conn.Close()
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: idleleo-probe\r\n" +
		"Accept: */*\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	}
	body, readErr := io.ReadAll(io.LimitReader(conn, 64<<10))
	text := string(body)
	line, _, _ := strings.Cut(text, "\r\n")
	if !strings.HasPrefix(line, "HTTP/1.1 200") && !strings.HasPrefix(line, "HTTP/1.0 200") {
		return fmt.Errorf("unexpected response %q (read error: %v)", firstLine(text), readErr)
	}
	if !strings.Contains(text, realityProbeHTTPMarker) {
		return fmt.Errorf("marker %q missing from response", realityProbeHTTPMarker)
	}
	return nil
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\r\n")
	if len(line) > 120 {
		return line[:120]
	}
	return line
}

type shareLink struct {
	uuid, sni, pbk, sid, fp, spx, flow, network, path, serviceName string
}

func parseShareURI(raw string) (shareLink, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return shareLink{}, fmt.Errorf("share link is not a URI: %w", err)
	}
	q := u.Query()
	if q.Get("security") != "reality" {
		return shareLink{}, fmt.Errorf("share link security is %q, not reality", q.Get("security"))
	}
	link := shareLink{
		uuid:        u.User.Username(),
		sni:         q.Get("sni"),
		pbk:         q.Get("pbk"),
		sid:         q.Get("sid"),
		fp:          q.Get("fp"),
		spx:         q.Get("spx"),
		flow:        q.Get("flow"),
		network:     q.Get("type"),
		path:        q.Get("path"),
		serviceName: q.Get("serviceName"),
	}
	if link.fp == "" {
		link.fp = "chrome"
	}
	if link.network == "" || link.network == "tcp" {
		link.network = "raw"
	}
	if link.uuid == "" || link.pbk == "" || link.sni == "" {
		return shareLink{}, fmt.Errorf("share link is missing id/pbk/sni")
	}
	switch link.network {
	case "raw", "ws", "grpc", "xhttp":
	default:
		return shareLink{}, fmt.Errorf("reality handshake probe does not support network %q", link.network)
	}
	return link, nil
}

func writeClientConfig(link shareLink, addr string, socksPort int) (string, func(), error) {
	addrHost, addrPort, err := net.SplitHostPort(addr)
	if err != nil {
		return "", nil, fmt.Errorf("probe address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(addrPort)
	if err != nil {
		return "", nil, err
	}
	reality := map[string]any{
		"serverName":  link.sni,
		"fingerprint": link.fp,
		"publicKey":   link.pbk,
		"shortId":     link.sid,
	}
	if link.spx != "" {
		reality["spiderX"] = link.spx
	}
	stream := map[string]any{"network": link.network, "security": "reality", "realitySettings": reality}
	switch link.network {
	case "ws":
		ws := map[string]any{}
		if link.path != "" {
			ws["path"] = link.path
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{}
		if link.serviceName != "" {
			grpc["serviceName"] = link.serviceName
		}
		stream["grpcSettings"] = grpc
	case "xhttp":
		xhttp := map[string]any{}
		if link.path != "" {
			xhttp["path"] = link.path
		}
		stream["xhttpSettings"] = xhttp
	}
	user := map[string]any{"id": link.uuid, "encryption": "none"}
	if link.flow != "" {
		user["flow"] = link.flow
	}
	client := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "probe", "listen": "127.0.0.1", "port": socksPort,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": addrHost, "port": port, "users": []any{user},
			}}},
			"streamSettings": stream,
		}},
	}
	body, err := json.MarshalIndent(client, "", "  ")
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "reality-probe-*")
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return path, func() { os.RemoveAll(dir) }, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitPort(ctx context.Context, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %d never opened", port)
}

// dialSocks performs the minimal SOCKS5 CONNECT the probe needs.
func dialSocks(proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks auth rejected: %v", reply)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[0] != 5 || head[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks connect rejected: rep=%d", head[1])
	}
	// Consume the bound address so the stream starts at the tunnel payload.
	switch head[3] {
	case 1:
		_, err = io.CopyN(io.Discard, conn, 4+2)
	case 4:
		_, err = io.CopyN(io.Discard, conn, 16+2)
	case 3:
		n := make([]byte, 1)
		if _, err = io.ReadFull(conn, n); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(n[0])+2)
		}
	default:
		err = fmt.Errorf("socks reply has unknown address type %d", head[3])
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func tail(body string) string {
	body = strings.TrimSpace(body)
	if len(body) > 400 {
		return body[len(body)-400:]
	}
	return body
}

// execCommand wraps the client process so tests can stub it if they need to.
type execCommand struct {
	cmd *exec.Cmd
}

// start/stop keep process handling in one place; the probe never inherits the
// editor's stdin/stdout.
func (e *execCommand) start(ctx context.Context, bin, cfg string, stderr *bytes.Buffer) error {
	c := exec.CommandContext(ctx, bin, "run", "-c", cfg)
	c.Stderr = stderr
	c.Stdout = io.Discard
	if err := c.Start(); err != nil {
		return err
	}
	e.cmd = c
	return nil
}

func (e *execCommand) stop() {
	if e.cmd == nil {
		return
	}
	if e.cmd.Process != nil {
		_ = e.cmd.Process.Kill()
	}
	_ = e.cmd.Wait()
}
