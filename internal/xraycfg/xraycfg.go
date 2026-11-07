// Package xraycfg generates new-install Xray configurations, edits users in an
// existing configuration and renders client share information.
//
// It never writes files itself: callers either validate the candidate with a
// real `xray -test` (generation) or route the edit through internal/change so
// the atomic transaction, rollback and lock still apply.
package xraycfg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/compat"
)

// Modes mirror the Bash install modes that this package can build.
const (
	ModeReality      = "reality"
	ModeRealityNginx = "reality-nginx"
	ModeTLS          = "tls"
	ModeNone         = "none"
)

// Transports are the backend transports used with Nginx TLS or no TLS.
const (
	TransportWS    = "ws"
	TransportGRPC  = "grpc"
	TransportXHTTP = "xhttp"
	TransportRaw   = "raw"
)

// Spec describes one to-be-generated configuration.
type Spec struct {
	Mode             string
	Transport        string
	Port             int
	PublicPort       int
	Listen           string
	Domain           string
	CertFile         string
	KeyFile          string
	Target           string
	ServerNames      []string
	Path             string
	ServiceName      string
	UUID             string
	Email            string
	Flow             string
	PrivateKey       string
	ShortID          string
	AllowNonLoopback bool
}

// UserView is one VLESS client in the generated/edited inbound.
type UserView struct {
	Index   int    `json:"index"`
	UUID    string `json:"uuid"`
	Email   string `json:"email,omitempty"`
	Flow    string `json:"flow,omitempty"`
	Level   int    `json:"level"`
	Primary bool   `json:"primary"`
}

// Generated is the in-memory result of a new-install generation.
type Generated struct {
	Mode       string     `json:"mode"`
	Transport  string     `json:"transport"`
	Port       int        `json:"port"`
	PublicPort int        `json:"publicPort"`
	Listen     string     `json:"listen"`
	Config     []byte     `json:"-"`
	Users      []UserView `json:"users"`
	UUID       string     `json:"uuid"`
	ShortID    string     `json:"shortId,omitempty"`
	PrivateKey string     `json:"privateKey"`
	PublicKey  string     `json:"publicKey"`
	ServerName string     `json:"serverName,omitempty"`
	Target     string     `json:"target,omitempty"`
	ShareURI   string     `json:"shareUri"`
	ClashYAML  string     `json:"clashYaml,omitempty"`
	NginxConf  string     `json:"nginxConf,omitempty"`
	Warnings   []string   `json:"warnings"`
}

const (
	defaultPath        = "/ray/"
	defaultGRPCService = "idleleo-grpc"
	defaultEmail       = "me@hey.run"
	defaultRealityFlow = "xtls-rprx-vision"
)

// Generate builds one configuration and its client artifacts. Secrets are
// created with crypto/rand when the spec does not supply them.
func Generate(spec Spec) (Generated, error) {
	spec.Mode = strings.ToLower(strings.TrimSpace(spec.Mode))
	if spec.Mode == "" {
		spec.Mode = ModeReality
	}
	g := Generated{Mode: spec.Mode, Warnings: []string{}}
	switch spec.Mode {
	case ModeReality, ModeRealityNginx:
		g.Transport = TransportRaw
	case ModeTLS, ModeNone:
		if spec.Transport == "" {
			spec.Transport = TransportWS
		}
		spec.Transport = strings.ToLower(spec.Transport)
		switch spec.Transport {
		case TransportWS, TransportGRPC, TransportXHTTP:
		default:
			return Generated{}, fmt.Errorf("unsupported transport %q for mode %s", spec.Transport, spec.Mode)
		}
		g.Transport = spec.Transport
	default:
		return Generated{}, fmt.Errorf("unsupported mode %q", spec.Mode)
	}
	if spec.Port == 0 {
		switch spec.Mode {
		case ModeReality:
			spec.Port = 443
		default:
			spec.Port = 10086
		}
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return Generated{}, fmt.Errorf("port must be between 1 and 65535")
	}
	if spec.PublicPort == 0 {
		switch spec.Mode {
		case ModeTLS, ModeRealityNginx:
			spec.PublicPort = 443
		default:
			spec.PublicPort = spec.Port
		}
	}
	if spec.Listen == "" {
		if spec.Mode == ModeReality {
			spec.Listen = "0.0.0.0"
		} else {
			spec.Listen = "127.0.0.1"
		}
	}
	if spec.Mode == ModeNone && !isLoopback(spec.Listen) && !spec.AllowNonLoopback {
		return Generated{}, fmt.Errorf("non-loopback listen %q requires explicit confirmation", spec.Listen)
	}
	if spec.Email == "" {
		spec.Email = defaultEmail
	}
	if spec.UUID == "" {
		id, err := NewUUID()
		if err != nil {
			return Generated{}, err
		}
		spec.UUID = id
	}
	if !validUUID(spec.UUID) {
		return Generated{}, fmt.Errorf("uuid is not a valid RFC4122 value")
	}
	if spec.Path == "" {
		spec.Path = defaultPath
	}
	if !strings.HasPrefix(spec.Path, "/") {
		spec.Path = "/" + spec.Path
	}
	if spec.ServiceName == "" {
		spec.ServiceName = defaultGRPCService
	}
	if spec.Mode == ModeTLS && spec.Domain == "" {
		return Generated{}, fmt.Errorf("tls mode requires --domain")
	}
	if spec.CertFile == "" && spec.Domain != "" {
		spec.CertFile = "/etc/idleleo/cert/" + spec.Domain + ".crt"
	}
	if spec.KeyFile == "" && spec.Domain != "" {
		spec.KeyFile = "/etc/idleleo/cert/" + spec.Domain + ".key"
	}

	serverName := ""
	var realityTarget string
	var privateKey, publicKey, shortID string
	if spec.Mode == ModeReality || spec.Mode == ModeRealityNginx {
		if len(spec.ServerNames) == 0 {
			if spec.Domain == "" {
				return Generated{}, fmt.Errorf("reality mode requires --server-name or --domain")
			}
			spec.ServerNames = []string{spec.Domain}
		}
		for _, sn := range spec.ServerNames {
			if !compat.RelayIsValidHost(sn) {
				return Generated{}, fmt.Errorf("invalid server name %q", sn)
			}
		}
		serverName = spec.ServerNames[0]
		realityTarget = spec.Target
		if realityTarget == "" {
			realityTarget = net.JoinHostPort(serverName, "443")
		}
		targetHost := realityTarget
		if host, _, splitErr := net.SplitHostPort(realityTarget); splitErr == nil {
			targetHost = host
		} else if strings.Contains(realityTarget, ":") && !strings.HasPrefix(realityTarget, "[") {
			return Generated{}, fmt.Errorf("invalid reality target %q: expected host:port", realityTarget)
		}
		if !compat.RelayIsValidHost(strings.Trim(targetHost, "[]")) {
			return Generated{}, fmt.Errorf("invalid reality target host %q", targetHost)
		}
		flow := spec.Flow
		if flow == "" {
			flow = defaultRealityFlow
		}
		spec.Flow = flow
		var err error
		privateKey, publicKey, err = selectRealityKeys(spec.PrivateKey)
		if err != nil {
			return Generated{}, err
		}
		shortID = spec.ShortID
		if shortID == "" {
			shortID, err = NewShortID()
			if err != nil {
				return Generated{}, err
			}
		}
		if !validShortID(shortID) {
			return Generated{}, fmt.Errorf("shortId must be 1-16 hex characters with even length")
		}
	} else {
		if spec.Flow != "" {
			return Generated{}, fmt.Errorf("flow is only valid for reality inbounds")
		}
		if spec.Mode == ModeTLS {
			serverName = spec.Domain
		}
	}

	config := buildConfig(spec, g.Transport, serverName, realityTarget, privateKey, shortID)

	g.Port, g.PublicPort, g.Listen = spec.Port, spec.PublicPort, spec.Listen
	g.UUID, g.ShortID, g.PrivateKey, g.PublicKey = spec.UUID, shortID, privateKey, publicKey
	g.ServerName, g.Target = serverName, realityTarget
	g.Users = []UserView{{Index: 0, UUID: spec.UUID, Email: spec.Email, Flow: spec.Flow, Level: 0, Primary: true}}
	g.Config = config

	shareHost := spec.Domain
	if spec.Mode == ModeNone {
		shareHost = spec.Listen
	} else if shareHost == "" {
		shareHost = serverName
	}
	if shareHost == "" {
		shareHost = spec.Listen
	}
	g.ShareURI = buildShareURI(spec, g.Transport, shareHost, publicKey, shortID, serverName)
	g.ClashYAML = buildClash(spec, g.Transport, shareHost, publicKey, shortID, serverName, &g)
	g.NginxConf = buildNginx(spec, g.Transport, serverName)
	return g, nil
}

func buildConfig(spec Spec, transport, serverName, target, privateKey, shortID string) []byte {
	client := map[string]any{
		"id":    spec.UUID,
		"level": 0,
		"email": spec.Email,
	}
	if spec.Flow != "" {
		client["flow"] = spec.Flow
	}
	stream := map[string]any{"security": "none", "network": transport}
	switch transport {
	case TransportWS:
		stream["wsSettings"] = map[string]any{"path": spec.Path}
	case TransportGRPC:
		stream["grpcSettings"] = map[string]any{"serviceName": spec.ServiceName}
	case TransportXHTTP:
		stream["xhttpSettings"] = map[string]any{"path": spec.Path, "mode": "auto"}
	case TransportRaw:
		stream["security"] = "reality"
		rs := map[string]any{
			"target":       target,
			"serverNames":  spec.ServerNames,
			"privateKey":   privateKey,
			"shortIds":     []any{shortID},
			"minClientVer": "1.0.0",
		}
		stream["realitySettings"] = rs
	}
	tag := "VLESS-Reality-in"
	if transport != TransportRaw {
		tag = "VLESS-" + transport + "-in"
	}
	root := map[string]any{
		"log": map[string]any{
			"access":   "/var/log/xray/access.log",
			"error":    "/var/log/xray/error.log",
			"loglevel": "warning",
		},
		"inbounds": []any{map[string]any{
			"tag":      tag,
			"port":     spec.Port,
			"listen":   spec.Listen,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{client},
				"decryption": "none",
			},
			"streamSettings": stream,
		}},
		"outbounds": []any{
			map[string]any{
				"protocol": "freedom",
				"tag":      "direct",
				"streamSettings": map[string]any{
					"sockopt": map[string]any{"domainStrategy": "UseIPv4v6"},
				},
			},
			map[string]any{"protocol": "blackhole", "tag": "blocked"},
		},
		"dns": map[string]any{
			"servers": []any{
				"https+local://dns.google/dns-query",
				"https+local://cloudflare-dns.com/dns-query",
				"https+local://doh.opendns.com/dns-query",
				"208.67.222.222",
				"8.8.8.8",
				"1.1.1.1",
				"localhost",
			},
			"disableCache": false,
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"type":        "field",
				"inboundTag":  []any{tag},
				"outboundTag": "direct",
			}},
		},
	}
	return mustJSON(root)
}

func buildShareURI(spec Spec, transport, host, publicKey, shortID, serverName string) string {
	q := func(v string) string { return strings.TrimRight(compat.VLESSURLQuote(v), "\n") }
	h := strings.TrimSpace(compat.FormatURIAuthorityHost(host))
	port := spec.PublicPort
	params := []string{"encryption=none"}
	name := "idleleo-" + spec.Mode
	switch transport {
	case TransportRaw:
		params = append(params,
			"flow="+q(spec.Flow),
			"security=reality",
			"sni="+q(serverName),
			"fp=chrome",
			"pbk="+publicKey,
			"sid="+shortID,
			"type=raw",
		)
	case TransportWS:
		params = append(params, "security="+securityName(spec.Mode))
		if serverName != "" {
			params = append(params, "sni="+q(serverName))
		}
		params = append(params,
			"type=ws",
			"path="+q(spec.Path),
			"host="+q(host),
		)
	case TransportGRPC:
		params = append(params, "security="+securityName(spec.Mode))
		if serverName != "" {
			params = append(params, "sni="+q(serverName))
		}
		params = append(params,
			"type=grpc",
			"serviceName="+q(spec.ServiceName),
		)
	case TransportXHTTP:
		params = append(params, "security="+securityName(spec.Mode))
		if serverName != "" {
			params = append(params, "sni="+q(serverName))
		}
		params = append(params,
			"type=xhttp",
			"path="+q(spec.Path),
			"host="+q(host),
		)
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", spec.UUID, h, port, strings.Join(params, "&"), q(name))
}

func securityName(mode string) string {
	if mode == ModeTLS {
		return "tls"
	}
	return "none"
}

func buildClash(spec Spec, transport, host, publicKey, shortID, serverName string, g *Generated) string {
	if transport == TransportXHTTP {
		g.Warnings = append(g.Warnings, "clash-xhttp-unsupported")
		return ""
	}
	network := "ws"
	if transport == TransportGRPC {
		network = "grpc"
	}
	if transport == TransportRaw {
		network = "tcp"
	}
	var b strings.Builder
	b.WriteString("proxies:\n")
	fmt.Fprintf(&b, "  - name: %q\n", "idleleo-"+spec.Mode)
	b.WriteString("    type: vless\n")
	fmt.Fprintf(&b, "    server: %s\n", yamlValue(host))
	fmt.Fprintf(&b, "    port: %d\n", spec.PublicPort)
	fmt.Fprintf(&b, "    uuid: %s\n", spec.UUID)
	fmt.Fprintf(&b, "    network: %s\n", network)
	b.WriteString("    udp: true\n")
	if spec.Mode == ModeTLS {
		b.WriteString("    tls: true\n")
		fmt.Fprintf(&b, "    servername: %s\n", yamlValue(serverName))
	} else if spec.Mode == ModeReality || spec.Mode == ModeRealityNginx {
		b.WriteString("    tls: true\n")
		fmt.Fprintf(&b, "    servername: %s\n", yamlValue(serverName))
		fmt.Fprintf(&b, "    flow: %s\n", spec.Flow)
		b.WriteString("    client-fingerprint: chrome\n")
		b.WriteString("    reality-opts:\n")
		fmt.Fprintf(&b, "      public-key: %s\n", publicKey)
		fmt.Fprintf(&b, "      short-id: %s\n", shortID)
	}
	if transport == TransportWS {
		b.WriteString("    ws-opts:\n")
		fmt.Fprintf(&b, "      path: %s\n", yamlValue(spec.Path))
		if spec.Mode == ModeTLS {
			b.WriteString("      headers:\n")
			fmt.Fprintf(&b, "        Host: %s\n", yamlValue(spec.Domain))
		}
	}
	if transport == TransportGRPC {
		b.WriteString("    grpc-opts:\n")
		fmt.Fprintf(&b, "      grpc-service-name: %s\n", yamlValue(spec.ServiceName))
	}
	return b.String()
}

func yamlValue(v string) string {
	q := strings.TrimSpace(compat.YAMLQuoteScalar(v))
	// compat.YAMLQuoteScalar returns a trailing newline for plain scalars.
	return strings.TrimRight(q, "\n")
}

func buildNginx(spec Spec, transport, serverName string) string {
	if spec.Mode == ModeTLS {
		var loc string
		switch transport {
		case TransportWS:
			loc = fmt.Sprintf(`    location %s {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }`, spec.Path, spec.Port)
		case TransportGRPC:
			loc = fmt.Sprintf(`    location /%s {
        grpc_pass grpc://127.0.0.1:%d;
    }`, spec.ServiceName, spec.Port)
		case TransportXHTTP:
			loc = fmt.Sprintf(`    location %s {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }`, spec.Path, spec.Port)
		}
		return fmt.Sprintf(`# Managed by Xray_bash_onekey (Go). Do not edit by hand.
server {
    listen 443 ssl http2;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.3;
%s
}
`, serverName, spec.CertFile, spec.KeyFile, loc)
	}
	if spec.Mode == ModeRealityNginx {
		return fmt.Sprintf(`# Managed by Xray_bash_onekey (Go). Stream SNI front for Reality.
stream {
    map $ssl_preread_server_name $idleleo_backend {
        default 127.0.0.1:%d;
    }
    server {
        listen 0.0.0.0:443;
        ssl_preread on;
        proxy_pass $idleleo_backend;
    }
}
`, spec.Port)
	}
	return ""
}

// NewUUID returns a random RFC 4122 version 4 UUID.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// NewShortID returns 8 hex characters, matching the Bash shortId shape.
func NewShortID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NewRealityKeys returns one base64url X25519 private/public pair in the
// encoding Xray expects.
func NewRealityKeys() (string, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(key.Bytes()), enc.EncodeToString(key.PublicKey().Bytes()), nil
}

func selectRealityKeys(privateKey string) (string, string, error) {
	if privateKey != "" {
		raw, err := base64.RawURLEncoding.DecodeString(privateKey)
		if err != nil || len(raw) != 32 {
			return "", "", fmt.Errorf("privateKey must be 32-byte base64url")
		}
		key, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return "", "", err
		}
		return privateKey, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
	}
	return NewRealityKeys()
}

// DerivePublicKey returns the Xray public key for a stored private key.
func DerivePublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("privateKey must be 32-byte base64url")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

func validShortID(s string) bool {
	if len(s) < 1 || len(s) > 16 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func isLoopback(host string) bool {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func mustJSON(root map[string]any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
