// Package clientprobe runs a real Xray client against a managed listener and
// proves the proxy path with an HTTP request. It is deliberately separate from
// configuration parsing: a config that loads is not a working tunnel.
//
// The probe only writes a temporary client config (0600, removed afterwards)
// and opens an ephemeral loopback SOCKS port. It never touches the managed
// root, a service unit, or a listening port.
package clientprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Link is the client-side projection of one server inbound.
type Link struct {
	UUID        string
	SNI         string
	PublicKey   string
	ShortID     string
	Fingerprint string
	SpiderX     string
	Flow        string
	Network     string
	Path        string
	ServiceName string
	// Security is "reality", "tls" or "none". TLS is accepted so a local
	// listener can be probed, but the result only proves the tunnel; it says
	// nothing about the certificate chain or the public hostname.
	Security string
}

// Result records what the origin actually returned.
type Result struct {
	StatusLine string
	BodyBytes  int
	Marker     string
}

// ParseShareURI projects a VLESS share link onto a Link. Unknown transports and
// securities are refused instead of guessed.
func ParseShareURI(raw string) (Link, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Link{}, fmt.Errorf("share link is not a URI: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return Link{}, fmt.Errorf("share link scheme %q is not vless", u.Scheme)
	}
	q := u.Query()
	link := Link{
		UUID:        u.User.Username(),
		SNI:         q.Get("sni"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		Fingerprint: q.Get("fp"),
		SpiderX:     q.Get("spx"),
		Flow:        q.Get("flow"),
		Network:     q.Get("type"),
		Path:        q.Get("path"),
		ServiceName: q.Get("serviceName"),
		Security:    q.Get("security"),
	}
	if link.Fingerprint == "" {
		link.Fingerprint = "chrome"
	}
	if link.Network == "" || link.Network == "tcp" {
		link.Network = "raw"
	}
	if link.UUID == "" {
		return Link{}, fmt.Errorf("share link is missing the user id")
	}
	switch link.Network {
	case "raw", "ws", "grpc", "xhttp":
	default:
		return Link{}, fmt.Errorf("client probe does not support network %q", link.Network)
	}
	switch link.Security {
	case "reality":
		if link.PublicKey == "" || link.SNI == "" {
			return Link{}, fmt.Errorf("reality link is missing pbk/sni")
		}
	case "tls", "none", "":
	default:
		return Link{}, fmt.Errorf("client probe does not support security %q", link.Security)
	}
	return link, nil
}

// Probe starts the real Xray client from xrayBin, dials addr through the tunnel
// and performs one HTTP GET for originURL. marker, when set, must appear in the
// response body; otherwise the body must be non-empty.
func Probe(ctx context.Context, xrayBin string, link Link, addr, originURL, marker string) (Result, error) {
	if fi, err := os.Stat(xrayBin); err != nil || fi.IsDir() {
		return Result{}, fmt.Errorf("xray binary unavailable: %s", xrayBin)
	}
	target, hostHeader, requestPath, err := parseOrigin(originURL)
	if err != nil {
		return Result{}, err
	}
	socksPort, err := freePort()
	if err != nil {
		return Result{}, err
	}
	cfgPath, cleanup, err := writeClientConfig(link, addr, socksPort)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(runCtx, xrayBin, "run", "-c", cfgPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start xray client: %w", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	if err := waitPort(runCtx, proxy, 8*time.Second); err != nil {
		return Result{}, fmt.Errorf("xray client did not open socks: %w (%s)", err, tail(stderr.String()))
	}
	conn, err := dialSocks(proxy, target)
	if err != nil {
		return Result{}, fmt.Errorf("socks connect through the tunnel failed: %w (%s)", err, tail(stderr.String()))
	}
	defer conn.Close()

	return httpThrough(conn, hostHeader, requestPath, marker)
}

// ProbeForward proves a raw TCP forwarder (the managed relay) end to end. A
// relay has no Xray inbound and no user credential, so a real HTTP client
// through the relay listener is the strongest honest evidence available; the
// caller must not call it REAL_CLIENT_PASS for a VLESS session.
func ProbeForward(ctx context.Context, addr, originURL, marker string) (Result, error) {
	_, hostHeader, requestPath, err := parseOrigin(originURL)
	if err != nil {
		return Result{}, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("dial the relay listener %s: %w", addr, err)
	}
	defer conn.Close()
	return httpThrough(conn, hostHeader, requestPath, marker)
}

// httpThrough performs one HTTP/1.1 GET on an established tunnel and validates
// the origin response. It is shared by the VLESS probe and the relay probe.
func httpThrough(conn net.Conn, hostHeader, requestPath, marker string) (Result, error) {
	request := "GET " + requestPath + " HTTP/1.1\r\nHost: " + hostHeader +
		"\r\nUser-Agent: idleleo-client-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return Result{}, fmt.Errorf("write request: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	body, readErr := io.ReadAll(io.LimitReader(conn, 64<<10))
	text := string(body)
	line, _, _ := strings.Cut(text, "\r\n")
	if !strings.HasPrefix(line, "HTTP/1.1 200") && !strings.HasPrefix(line, "HTTP/1.0 200") {
		return Result{}, fmt.Errorf("unexpected origin response %q (read error: %v)", firstLine(text), readErr)
	}
	payload := text
	if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
		payload = text[idx+4:]
	}
	if marker != "" {
		if !strings.Contains(payload, marker) {
			return Result{}, fmt.Errorf("origin body does not contain %q", marker)
		}
	} else if strings.TrimSpace(payload) == "" {
		return Result{}, fmt.Errorf("origin returned an empty body")
	}
	return Result{StatusLine: line, BodyBytes: len(payload), Marker: marker}, nil
}

func parseOrigin(raw string) (target, hostHeader, path string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("probe URL %q: %w", raw, err)
	}
	if u.Scheme != "http" {
		return "", "", "", fmt.Errorf("probe URL must use http, got %q (TLS origin validation is not part of the probe)", u.Scheme)
	}
	if u.Host == "" {
		return "", "", "", fmt.Errorf("probe URL has no host")
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	path = u.RequestURI()
	if path == "" {
		path = "/"
	}
	return net.JoinHostPort(u.Hostname(), port), u.Host, path, nil
}

func writeClientConfig(link Link, addr string, socksPort int) (string, func(), error) {
	addrHost, addrPort, err := net.SplitHostPort(addr)
	if err != nil {
		return "", nil, fmt.Errorf("probe address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(addrPort)
	if err != nil {
		return "", nil, err
	}
	stream := map[string]any{"network": link.Network}
	switch link.Security {
	case "reality":
		reality := map[string]any{
			"serverName":  link.SNI,
			"fingerprint": link.Fingerprint,
			"publicKey":   link.PublicKey,
			"shortId":     link.ShortID,
		}
		if link.SpiderX != "" {
			reality["spiderX"] = link.SpiderX
		}
		stream["security"] = "reality"
		stream["realitySettings"] = reality
	case "tls":
		// The client validates the tunnel, not the public certificate. The
		// report must keep that boundary explicit.
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{"serverName": link.SNI, "allowInsecure": true}
	default:
		stream["security"] = "none"
	}
	switch link.Network {
	case "ws":
		ws := map[string]any{}
		if link.Path != "" {
			ws["path"] = link.Path
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{}
		if link.ServiceName != "" {
			grpc["serviceName"] = link.ServiceName
		}
		stream["grpcSettings"] = grpc
	case "xhttp":
		xhttp := map[string]any{}
		if link.Path != "" {
			xhttp["path"] = link.Path
		}
		stream["xhttpSettings"] = xhttp
	}
	user := map[string]any{"id": link.UUID, "encryption": "none"}
	if link.Flow != "" {
		user["flow"] = link.Flow
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
	dir, err := os.MkdirTemp("", "idleleo-client-probe-")
	if err != nil {
		return "", nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
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

func waitPort(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s never opened", addr)
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

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\r\n")
	if len(line) > 120 {
		return line[:120]
	}
	return line
}

func tail(body string) string {
	body = strings.TrimSpace(body)
	if len(body) > 400 {
		return body[len(body)-400:]
	}
	return body
}
