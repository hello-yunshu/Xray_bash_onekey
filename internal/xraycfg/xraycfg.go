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
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/compat"
)

// Modes mirror the Bash install modes that this package can build.
const (
	ModeReality        = "reality"
	ModeRealityNginx   = "reality-nginx"
	ModeRealityBalance = "reality-balance"
	ModeTLS            = "tls"
	ModeNone           = "none"
)

// Reality balance roles mirror the Bash primary/secondary wizard profiles.
const (
	BalanceRolePrimary   = "primary"
	BalanceRoleSecondary = "secondary"
)

// realityBalanceBackendPort is the fixed loopback port the Bash Reality
// template keeps for a balance primary; the primary Nginx front owns the
// public port.
const realityBalanceBackendPort = 9443

// Transports are the backend transports used with Nginx TLS or no TLS.
const (
	TransportWS    = "ws"
	TransportGRPC  = "grpc"
	TransportXHTTP = "xhttp"
	TransportRaw   = "raw"
	// TransportMulti is the Bash multi-entry topology: one base inbound plus
	// the two remaining transports on their own loopback ports.
	TransportMulti = "ws+grpc+xhttp"
)

// inboundDef is one generated inbound entry.
type inboundDef struct {
	tag         string
	transport   string
	port        int
	listen      string
	email       string
	flow        string
	path        string
	serviceName string
}

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
	// BalanceRole is required by ModeRealityBalance: primary runs the Nginx
	// stream front, secondary only serves the Reality backend.
	BalanceRole string
	// Backends are extra host:port entries written into the primary
	// Nginx upstream fragment. Empty means the local 127.0.0.1:9443 backend.
	Backends []string
	// UnknownSNIPolicy selects the Bash SNI guard branch: isolate (default),
	// reject. decoy requires pre-existing site artifacts and is refused here.
	UnknownSNIPolicy string
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
	// NginxFragments holds the files the Bash installer writes next to the
	// stream config (upstream servers, SNI map entries, isolate site).
	NginxFragments map[string]string `json:"nginxFragments,omitempty"`
	BalanceRole    string            `json:"balanceRole,omitempty"`
	Warnings       []string          `json:"warnings"`
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
	if spec.Mode == ModeRealityBalance {
		// Bash exposes the role as an explicit wizard choice; requiring it here
		// avoids silently deploying a front-end on a server meant as a backend.
		spec.BalanceRole = strings.ToLower(strings.TrimSpace(spec.BalanceRole))
		switch spec.BalanceRole {
		case BalanceRolePrimary, BalanceRoleSecondary:
		default:
			return Generated{}, fmt.Errorf("reality-balance requires --role primary or secondary")
		}
		g.BalanceRole = spec.BalanceRole
	}
	switch spec.Mode {
	case ModeReality, ModeRealityNginx, ModeRealityBalance:
		spec.Transport = strings.ToLower(strings.TrimSpace(spec.Transport))
		switch spec.Transport {
		case "", TransportRaw:
			spec.Transport = TransportRaw
		case TransportMulti:
			// Reality stays the primary raw inbound; the other transports are
			// added as loopback inbounds, matching Bash reality_add_more.
			if spec.Mode == ModeRealityBalance {
				return Generated{}, fmt.Errorf("reality-balance does not support transport %q", spec.Transport)
			}
		default:
			return Generated{}, fmt.Errorf("unsupported transport %q for mode %s", spec.Transport, spec.Mode)
		}
		g.Transport = spec.Transport
	case ModeTLS, ModeNone:
		if spec.Transport == "" {
			spec.Transport = TransportWS
		}
		spec.Transport = strings.ToLower(spec.Transport)
		switch spec.Transport {
		case TransportWS, TransportGRPC, TransportXHTTP, TransportMulti:
		default:
			return Generated{}, fmt.Errorf("unsupported transport %q for mode %s", spec.Transport, spec.Mode)
		}
		g.Transport = spec.Transport
	default:
		return Generated{}, fmt.Errorf("unsupported mode %q", spec.Mode)
	}
	if spec.Port == 0 {
		switch spec.Mode {
		case ModeReality, ModeRealityNginx, ModeRealityBalance:
			spec.Port = 443
		default:
			spec.Port = 10086
		}
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return Generated{}, fmt.Errorf("port must be between 1 and 65535")
	}
	// Bash reserves 9403/9404/9443/9444 for the SNI guard and Reality backend
	// and rejects them as the operator-facing port for every Reality mode.
	if spec.Mode == ModeReality || spec.Mode == ModeRealityNginx || spec.Mode == ModeRealityBalance {
		if isRealityReservedPort(spec.Port) {
			return Generated{}, fmt.Errorf("port %d is reserved for Reality internals (9403, 9404, 9443, 9444)", spec.Port)
		}
	}
	if spec.PublicPort == 0 {
		switch spec.Mode {
		case ModeTLS:
			spec.PublicPort = 443
		case ModeRealityNginx, ModeRealityBalance:
			// Bash treats the selected port as the Nginx front port; Xray keeps
			// listening on the fixed loopback backend port.
			spec.PublicPort = spec.Port
		default:
			spec.PublicPort = spec.Port
		}
	}
	if spec.PublicPort < 1 || spec.PublicPort > 65535 {
		return Generated{}, fmt.Errorf("public port must be between 1 and 65535")
	}
	if spec.Listen == "" {
		if spec.Mode == ModeReality || spec.Mode == ModeRealityBalance {
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
	if spec.Domain != "" && !compat.RelayIsValidHost(spec.Domain) {
		// The domain also becomes part of the default certificate path and
		// Nginx server_name, so a path-like or malformed value must not pass.
		return Generated{}, fmt.Errorf("invalid domain %q", spec.Domain)
	}
	if spec.CertFile == "" && spec.Domain != "" {
		// Bash installs one well-known pair under /etc/idleleo/cert and points
		// every TLS site at it; --cert/--key still override.
		spec.CertFile = "/etc/idleleo/cert/xray.crt"
	}
	if spec.KeyFile == "" && spec.Domain != "" {
		spec.KeyFile = "/etc/idleleo/cert/xray.key"
	}

	serverName := ""
	var realityTarget string
	var privateKey, publicKey, shortID string
	if spec.Mode == ModeReality || spec.Mode == ModeRealityNginx || spec.Mode == ModeRealityBalance {
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
		// Bash serverNames_set accepts exactly one hostname; the balance SNI
		// fragment is one "<name> reality;" line per name, so keep it single.
		if spec.Mode == ModeRealityBalance && len(spec.ServerNames) != 1 {
			return Generated{}, fmt.Errorf("reality-balance requires exactly one --server-name")
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
		} else {
			// Xray rejects a Reality target without an explicit port; the Bash
			// default is 443, so normalize instead of emitting a broken config.
			targetHost = strings.Trim(realityTarget, "[]")
			realityTarget = net.JoinHostPort(targetHost, "443")
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

	inboundPort := spec.Port
	if spec.Mode == ModeRealityBalance || spec.Mode == ModeRealityNginx {
		if err := validateBalance(spec); err != nil {
			return Generated{}, err
		}
		if spec.Mode == ModeRealityNginx || spec.BalanceRole == BalanceRolePrimary {
			// Bash keeps the Reality template port (9443) on the Xray inbound and
			// lets Nginx own the public port. Reusing the public port would make
			// Xray and Nginx fight over the same TCP port.
			inboundPort = realityBalanceBackendPort
		}
	}

	defs := buildInboundDefs(spec, g.Transport, inboundPort)
	config := buildConfig(spec, defs, serverName, realityTarget, privateKey, shortID)

	g.Port, g.PublicPort, g.Listen = inboundPort, spec.PublicPort, spec.Listen
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
	base := defs[0]
	g.ShareURI = buildShareURI(spec, base.transport, shareHost, publicKey, shortID, serverName)
	g.ClashYAML = buildClash(spec, base.transport, shareHost, publicKey, shortID, serverName, &g)
	g.NginxConf = buildNginx(spec, defs, serverName)
	if spec.Mode == ModeTLS {
		g.NginxFragments = buildTLSServerFragments(defs)
		g.NginxFragments["01-xray-80.conf"] = buildTLSRedirectNginx(spec, serverName)
		g.NginxFragments["02-xray-server.conf"] = buildTLSServerConf(defs)
	}
	if spec.Mode == ModeRealityNginx {
		// Bash Reality+Nginx renders the same SNI Guard stream block and
		// fragment set as a balance primary; only the Xray inbound port differs.
		g.NginxConf = buildRealityBalanceNginx(spec.PublicPort, balanceDenyPort(spec.UnknownSNIPolicy))
		g.NginxFragments = buildRealityBalanceFragments(spec, serverName)
	}
	if spec.Mode == ModeRealityBalance && spec.BalanceRole == BalanceRolePrimary {
		g.NginxConf = buildRealityBalanceNginx(spec.PublicPort, balanceDenyPort(spec.UnknownSNIPolicy))
		g.NginxFragments = buildRealityBalanceFragments(spec, serverName)
	}
	if g.Transport == TransportMulti {
		g.Warnings = append(g.Warnings, "multi-transport: only the primary inbound share URI is emitted; use 'xray share --inbound' for the others")
	}
	return g, nil
}

const defaultXHTTPPath = "/xhttp/"

// portOffset returns a distinct port near base, wrapping inside the valid
// range. Multi-entry installs use consecutive ports instead of Bash's random
// selection so the artifact stays reproducible.
func portOffset(base, offset int) int {
	p := base + offset
	for p > 65535 {
		p -= 65535
	}
	if p < 1 {
		p = 1
	}
	return p
}

func inboundTag(transport string) string {
	switch transport {
	case TransportWS:
		return "VLESS-ws-in"
	case TransportGRPC:
		return "VLESS-gRPC-in"
	case TransportXHTTP:
		return "VLESS-xhttp-in"
	default:
		return "VLESS-Reality-in"
	}
}

// buildInboundDefs returns the inbounds for the requested transport. The
// primary inbound always uses inboundPort so callers can address it by index 0.
func buildInboundDefs(spec Spec, transport string, inboundPort int) []inboundDef {
	if transport != TransportMulti {
		if transport == TransportRaw {
			return []inboundDef{{tag: inboundTag(transport), transport: TransportRaw, port: inboundPort,
				listen: spec.Listen, email: spec.Email, flow: spec.Flow}}
		}
		return []inboundDef{{
			tag: inboundTag(transport), transport: transport, port: inboundPort, listen: spec.Listen,
			email: spec.Email, path: spec.Path, serviceName: spec.ServiceName,
		}}
	}
	reality := spec.Mode == ModeReality || spec.Mode == ModeRealityNginx
	defs := make([]inboundDef, 0, 4)
	if reality {
		defs = append(defs, inboundDef{tag: inboundTag(TransportRaw), transport: TransportRaw,
			port: inboundPort, listen: spec.Listen, email: spec.Email, flow: spec.Flow})
	} else {
		defs = append(defs, inboundDef{tag: inboundTag(TransportWS), transport: TransportWS,
			port: inboundPort, listen: spec.Listen, email: spec.Email, path: spec.Path})
	}
	// Bash keeps added inbounds on loopback for none/TLS but exposes them on
	// the primary listen address for Reality (reality_add_more runs after the
	// 0.0.0.0 rewrite). Match that instead of forcing loopback everywhere.
	extraListen := "127.0.0.1"
	if reality {
		extraListen = spec.Listen
	}
	offset := 1
	if reality {
		defs = append(defs, inboundDef{tag: inboundTag(TransportWS), transport: TransportWS,
			port: portOffset(spec.Port, offset), listen: extraListen, email: "ws@hey.run", path: spec.Path})
		offset++
	}
	defs = append(defs, inboundDef{tag: inboundTag(TransportGRPC), transport: TransportGRPC,
		port: portOffset(spec.Port, offset), listen: extraListen, email: "me@hey.run",
		serviceName: spec.ServiceName})
	offset++
	defs = append(defs, inboundDef{tag: inboundTag(TransportXHTTP), transport: TransportXHTTP,
		port: portOffset(spec.Port, offset), listen: extraListen, email: "xhttp@hey.run",
		path: defaultXHTTPPath})
	return defs
}

func buildConfig(spec Spec, defs []inboundDef, serverName, target, privateKey, shortID string) []byte {
	inbounds := make([]any, 0, len(defs))
	tags := make([]any, 0, len(defs))
	for _, def := range defs {
		client := map[string]any{
			"id":    spec.UUID,
			"level": 0,
			"email": def.email,
		}
		if def.flow != "" {
			client["flow"] = def.flow
		}
		stream := map[string]any{"security": "none", "network": def.transport}
		switch def.transport {
		case TransportWS:
			stream["wsSettings"] = map[string]any{"path": def.path}
		case TransportGRPC:
			stream["grpcSettings"] = map[string]any{
				"serviceName": def.serviceName, "multiMode": true, "idle_timeout": 20,
			}
		case TransportXHTTP:
			stream["xhttpSettings"] = map[string]any{"path": def.path, "mode": "auto"}
		case TransportRaw:
			stream["security"] = "reality"
			stream["realitySettings"] = map[string]any{
				"target":       target,
				"serverNames":  spec.ServerNames,
				"privateKey":   privateKey,
				"shortIds":     []any{shortID},
				"minClientVer": "1.0.0",
			}
		}
		inbounds = append(inbounds, map[string]any{
			"tag":      def.tag,
			"port":     def.port,
			"listen":   def.listen,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{client},
				"decryption": "none",
			},
			"streamSettings": stream,
		})
		tags = append(tags, def.tag)
	}
	root := map[string]any{
		"log": map[string]any{
			"access":   "/var/log/xray/access.log",
			"error":    "/var/log/xray/error.log",
			"loglevel": "warning",
		},
		"inbounds": inbounds,
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
				"inboundTag":  tags,
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
	} else if spec.Mode == ModeReality || spec.Mode == ModeRealityNginx || spec.Mode == ModeRealityBalance {
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

func buildNginx(spec Spec, defs []inboundDef, serverName string) string {
	if spec.Mode != ModeTLS {
		return ""
	}
	var sites strings.Builder
	for _, def := range defs {
		switch def.transport {
		case TransportWS:
			fmt.Fprintf(&sites, `    location %s {
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_pass http://xray-ws-server;
    }
`, def.path)
		case TransportGRPC:
			fmt.Fprintf(&sites, `    location /%s {
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header Early-Data $ssl_early_data;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        grpc_pass grpc://xray-grpc-server;
    }
`, def.serviceName)
		case TransportXHTTP:
			fmt.Fprintf(&sites, `    location %s {
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header Early-Data $ssl_early_data;
        grpc_set_header Host $host;
        client_max_body_size 0;
        grpc_pass grpc://xray-xhttp-server;
    }
`, def.path)
		}
	}
	return fmt.Sprintf(`# Managed by Xray_bash_onekey (Go). Do not edit by hand.
server {
    listen %[1]d ssl reuseport;
    listen [::]:%[1]d ssl reuseport;
    listen %[1]d quic reuseport;
    listen [::]:%[1]d quic reuseport;

    http2 on;
    set_real_ip_from      127.0.0.1;
    real_ip_header        X-Forwarded-For;
    real_ip_recursive     on;
    ssl_certificate       %[2]s;
    ssl_certificate_key   %[3]s;
    ssl_protocols         TLSv1.3;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_ecdh_curve        X25519:prime256v1:secp384r1;
    server_name           %[4]s;
    root /var/www/html;
    error_page 403 https://hey.run/helloworld;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_early_data on;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000";

%s
    location / {
        return 403;
    }
}
`, spec.PublicPort, spec.CertFile, spec.KeyFile, serverName, sites.String())
}

// buildTLSRedirectNginx renders the Bash 01-xray-80.conf ACME + redirect site.
func buildTLSRedirectNginx(spec Spec, serverName string) string {
	redirect := serverName
	if spec.PublicPort != 443 {
		redirect = fmt.Sprintf("%s:%d", serverName, spec.PublicPort)
	}
	return fmt.Sprintf(`# Managed by Xray_bash_onekey (Go). Do not edit by hand.
server {
    listen 80;
    listen [::]:80;
    server_name %s;

    location ^~ /.well-known/acme-challenge/ {
        root /etc/idleleo/conf;
        default_type "text/plain";
        allow all;
    }
    location = /.well-known/acme-challenge/ {
        return 404;
    }

    location / {
        return 301 https://%s$request_uri;
    }
}
`, serverName, redirect)
}

// buildTLSServerConf renders the Bash 02-xray-server.conf upstream blocks.
func buildTLSServerConf(defs []inboundDef) string {
	var b strings.Builder
	b.WriteString("# Managed by Xray_bash_onekey (Go). Do not edit by hand.\n")
	seen := map[string]bool{}
	for _, def := range defs {
		if seen[def.transport] {
			continue
		}
		seen[def.transport] = true
		fmt.Fprintf(&b, `upstream xray-%s-server {
    include /etc/idleleo/conf/nginx/*.%sServers;
}

`, def.transport, def.transport)
	}
	return b.String()
}

// buildTLSServerFragments renders the Bash 127.0.0.1.<transport>Servers files.
func buildTLSServerFragments(defs []inboundDef) map[string]string {
	frags := map[string]string{}
	for _, def := range defs {
		name := "127.0.0.1." + def.transport + "Servers"
		frags[name] = fmt.Sprintf("server 127.0.0.1:%d weight=50 max_fails=2 fail_timeout=10;\n", def.port)
	}
	return frags
}

func isRealityReservedPort(p int) bool {
	switch p {
	case 9403, 9404, 9443, 9444:
		return true
	}
	return false
}

func validateBalance(spec Spec) error {
	for _, raw := range spec.Backends {
		backend := strings.TrimSpace(raw)
		host, portStr, err := net.SplitHostPort(backend)
		if err != nil {
			return fmt.Errorf("invalid backend %q: expected host:port", raw)
		}
		if !compat.RelayIsValidHost(strings.Trim(host, "[]")) {
			return fmt.Errorf("invalid backend host %q", host)
		}
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid backend port in %q", raw)
		}
	}
	if spec.BalanceRole == BalanceRoleSecondary && len(spec.Backends) > 0 {
		return fmt.Errorf("reality-balance secondary has no Nginx front; --backend is primary only")
	}
	switch spec.UnknownSNIPolicy {
	case "", "isolate", "reject":
	case "decoy":
		return fmt.Errorf("unknown-sni-policy decoy needs pre-existing decoy cert/site artifacts and is not generated by the Go CLI")
	default:
		return fmt.Errorf("unsupported unknown-sni-policy %q", spec.UnknownSNIPolicy)
	}
	return nil
}

func balanceDenyPort(policy string) int {
	if policy == "reject" {
		return 9404
	}
	return 9403
}

// buildRealityBalanceNginx renders the Bash nginx_reality_conf_add stream
// block verbatim, with the operator port applied by modify_nginx_port. Paths
// are the Bash-owned /etc/idleleo and /usr/local/nginx locations so a Go
// deployment and a Bash deployment include the same fragments.
func buildRealityBalanceNginx(publicPort, denyPort int) string {
	return fmt.Sprintf(`
stream {
    map $ssl_preread_protocol $is_valid_protocol {
        #TLSv1.2    1;
        TLSv1.3    1;
        default    0;
    }

    map $ssl_preread_server_name $sni_upstream {
        include /etc/idleleo/conf/nginx/*.serverNames;
        default deny;
    }

    map "$sni_upstream:$is_valid_protocol" $final_upstream {
        # 格式：上游名称:协议标记 => 最终上游
        ~^reality:1$     reality;
        default          deny;
    }

    map $final_upstream $is_abnormal {
        deny    1;
        default 0;
    }

    map "$sni_upstream:$is_valid_protocol" $error_type {
        ~^reality:0$     "tls_error";
        ~^deny:1$        "sni_error";
        ~^deny:0$        "tls_sni_error";
        default          "other_error";
    }

    map $error_type $is_tls_error {
        "tls_error"      1;
        #"tls_sni_error"  1;
        default          0;
    }

    map $error_type $is_sni_error {
        "sni_error"      1;
        "tls_sni_error"  1;
        default          0;
    }

    upstream reality {
        include /etc/idleleo/conf/nginx/*.realityServers;
    }

    upstream deny {
        server 127.0.0.1:%d;
    }

    log_format tls_error_log '$remote_addr [$time_local] "$ssl_preread_server_name" '
                             '$ssl_preread_protocol $status';

    log_format sni_error_log '$remote_addr [$time_local] "$ssl_preread_server_name" '
                             '$ssl_preread_protocol $status';

    server {
        listen %d reuseport so_keepalive=on backlog=65535;
        proxy_pass $final_upstream;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 300s;
        access_log /usr/local/nginx/logs/tls_error.log tls_error_log buffer=8k flush=3s if=$is_tls_error;
        access_log /usr/local/nginx/logs/sni_error.log sni_error_log buffer=8k flush=3s if=$is_sni_error;
    }
}
`, denyPort, publicPort)
}

// buildRealityBalanceFragments returns the files Bash writes beside the
// stream config. One .realityServers file holds every upstream line, which
// matches how scripts/file_manager.sh appends backends.
func buildRealityBalanceFragments(spec Spec, serverName string) map[string]string {
	// Bash always keeps the local 127.0.0.1:9443 backend line and appends
	// operator-added servers; --backend never replaces the primary.
	primary := net.JoinHostPort("127.0.0.1", strconv.Itoa(realityBalanceBackendPort))
	backends := []string{primary}
	seen := map[string]bool{primary: true}
	for _, raw := range spec.Backends {
		backend := strings.TrimSpace(raw)
		if seen[backend] {
			continue
		}
		seen[backend] = true
		backends = append(backends, backend)
	}
	var upstream strings.Builder
	for _, backend := range backends {
		fmt.Fprintf(&upstream, "server %s weight=50 max_fails=2 fail_timeout=10;\n", backend)
	}
	frags := map[string]string{
		"127.0.0.1.realityServers":  upstream.String(),
		serverName + ".serverNames": serverName + " reality;\n",
	}
	if spec.UnknownSNIPolicy == "" || spec.UnknownSNIPolicy == "isolate" {
		frags["03-isolate.conf"] = `# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert
server {
    listen 127.0.0.1:9403 ssl;
    ssl_reject_handshake on;
    access_log off;
    error_log /dev/null;
}
`
	}
	return frags
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
