package xraycfg

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ShareInfo is the client-facing view rendered from an existing config.
type ShareInfo struct {
	Mode      string   `json:"mode"`
	Transport string   `json:"transport"`
	UUID      string   `json:"uuid"`
	Email     string   `json:"email,omitempty"`
	Flow      string   `json:"flow,omitempty"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	ShareURI  string   `json:"shareUri"`
	ClashYAML string   `json:"clashYaml,omitempty"`
	Warnings  []string `json:"warnings"`
}

// ShareOptions describes which client view to render and which public entry
// terminates TLS.
//
// PublicSecurity is the trusted public-side mode ("tls", "none" or "reality")
// when the runtime config alone cannot prove it. Bash TLS deployments keep
// Xray on loopback with stream security=none and let Nginx terminate TLS, so a
// runtime config with security=none plus a loopback listener is ambiguous;
// callers must supply the management metadata value instead of letting Go
// guess (which previously emitted a security=none link for a public TLS port).
type ShareOptions struct {
	InboundIndex   int
	Host           string
	PublicPort     int
	PublicSecurity string
	User           string
}

// Share renders VLESS URI and Clash proxy for one inbound and one user using
// only the runtime config. Kept as the config-only entry point; ambiguous
// deployments must call ShareConfig with PublicSecurity set.
func Share(raw []byte, inboundIndex int, host string, publicPort int) (ShareInfo, error) {
	return ShareConfig(raw, ShareOptions{InboundIndex: inboundIndex, Host: host, PublicPort: publicPort})
}

// ShareConfig renders VLESS URI and Clash proxy for one inbound and one user.
// host and publicPort override what is stored in the config (the config usually
// keeps the loopback backend port when Nginx terminates TLS).
func ShareConfig(raw []byte, opts ShareOptions) (ShareInfo, error) {
	root, err := decode(raw)
	if err != nil {
		return ShareInfo{}, err
	}
	in, err := inboundAt(root, opts.InboundIndex)
	if err != nil {
		return ShareInfo{}, err
	}
	if protocol, _ := in["protocol"].(string); !strings.EqualFold(protocol, "vless") {
		return ShareInfo{}, fmt.Errorf("inbound %d is not VLESS", opts.InboundIndex)
	}
	settings, _ := in["settings"].(map[string]any)
	clients, _ := settings["clients"].([]any)
	if len(clients) == 0 {
		return ShareInfo{}, fmt.Errorf("inbound %d has no clients", opts.InboundIndex)
	}
	selected, err := selectClient(clients, opts.User, opts.InboundIndex)
	if err != nil {
		return ShareInfo{}, err
	}
	id, _ := selected["id"].(string)
	flow, _ := selected["flow"].(string)
	email, _ := selected["email"].(string)
	if !validUUID(id) {
		return ShareInfo{}, fmt.Errorf("selected client has invalid uuid")
	}
	port, err := intField(in["port"])
	if err != nil {
		return ShareInfo{}, err
	}
	listen, _ := in["listen"].(string)
	if opts.PublicPort == 0 {
		opts.PublicPort = port
	}
	stream, _ := in["streamSettings"].(map[string]any)
	network, _ := stream["network"].(string)
	security, _ := stream["security"].(string)
	path := defaultPath
	serviceName := defaultGRPCService
	var serverNames []string
	privateKey, shortID := "", ""
	switch network {
	case "ws", "":
		network = TransportWS
		if ws, _ := stream["wsSettings"].(map[string]any); ws != nil {
			if p, _ := ws["path"].(string); p != "" {
				path = p
			}
		}
	case "grpc":
		if grpc, _ := stream["grpcSettings"].(map[string]any); grpc != nil {
			if s, _ := grpc["serviceName"].(string); s != "" {
				serviceName = s
			}
		}
	case "xhttp":
		if xh, _ := stream["xhttpSettings"].(map[string]any); xh != nil {
			if p, _ := xh["path"].(string); p != "" {
				path = p
			}
		}
	case "raw", "tcp":
		network = TransportRaw
	}
	internalMode := ModeNone
	if security == "reality" {
		internalMode = ModeReality
		rs, _ := stream["realitySettings"].(map[string]any)
		if rs != nil {
			if v, _ := rs["privateKey"].(string); v != "" {
				privateKey = v
			}
			if ids, ok := rs["shortIds"].([]any); ok && len(ids) > 0 {
				shortID, _ = ids[0].(string)
			}
			if sns, ok := rs["serverNames"].([]any); ok {
				for _, v := range sns {
					if s, _ := v.(string); s != "" {
						serverNames = append(serverNames, s)
					}
				}
			}
		}
	} else if security == "tls" {
		internalMode = ModeTLS
		if tls, _ := stream["tlsSettings"].(map[string]any); tls != nil {
			if s, _ := tls["serverName"].(string); s != "" {
				serverNames = []string{s}
			}
		}
	}
	mode, warnings, err := resolvePublicMode(internalMode, security, listen, port, opts)
	if err != nil {
		return ShareInfo{}, err
	}
	host := strings.TrimSpace(opts.Host)
	if host == "" {
		if len(serverNames) > 0 {
			host = serverNames[0]
		} else {
			host = listen
		}
	}
	if mode == ModeTLS && (host == "" || host == listen) {
		return ShareInfo{}, fmt.Errorf("--host is required to render a public TLS share link (runtime listen is %q)", listen)
	}
	publicKey := ""
	if privateKey != "" {
		publicKey, err = DerivePublicKey(privateKey)
		if err != nil {
			return ShareInfo{}, err
		}
	}
	if mode == ModeTLS && len(serverNames) == 0 {
		serverNames = []string{host}
	}
	spec := Spec{
		Mode: specMode(mode, network), Transport: network, Port: port, PublicPort: opts.PublicPort,
		Listen: listen, Domain: host, Path: path, ServiceName: serviceName,
		UUID: id, Flow: flow, ServerNames: serverNames, ShortID: shortID,
	}
	if len(serverNames) == 0 && host != "" {
		spec.ServerNames = []string{host}
	}
	out := ShareInfo{Mode: mode, Transport: network, UUID: id, Email: email, Flow: flow, Host: host, Port: opts.PublicPort, Warnings: warnings}
	if publicKey != "" {
		out.ShareURI = buildShareURI(spec, network, host, publicKey, shortID, firstOf(serverNames, host))
	} else {
		out.ShareURI = buildShareURI(spec, network, host, "", shortID, firstOf(serverNames, host))
	}
	var tmp Generated
	out.ClashYAML = buildClash(spec, network, host, publicKey, shortID, firstOf(serverNames, host), &tmp)
	out.Warnings = append(out.Warnings, tmp.Warnings...)
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	return out, nil
}

// selectClient returns the requested user (email or UUID) or the primary
// client. It refuses an ambiguous selector instead of silently picking one.
func selectClient(clients []any, selector string, inbound int) (map[string]any, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		first, _ := clients[0].(map[string]any)
		if first == nil {
			return nil, fmt.Errorf("primary client is not an object")
		}
		return first, nil
	}
	var matches []map[string]any
	for _, raw := range clients {
		client, _ := raw.(map[string]any)
		if client == nil {
			continue
		}
		id, _ := client["id"].(string)
		email, _ := client["email"].(string)
		if id == selector || email == selector {
			matches = append(matches, client)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("user %q not found in inbound %d", selector, inbound)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("user %q matches %d clients in inbound %d; select by UUID", selector, len(matches), inbound)
	}
}

// resolvePublicMode determines the public-side security without guessing when
// the runtime config is ambiguous. Bash TLS deployments are loopback-backed
// with stream security=none, so a caller-provided --public-security (usually
// from install metadata) is mandatory in that case.
func resolvePublicMode(internal, security, listen string, port int, opts ShareOptions) (string, []string, error) {
	requested := strings.ToLower(strings.TrimSpace(opts.PublicSecurity))
	if requested == "auto" {
		requested = ""
	}
	if requested != "" {
		switch requested {
		case ModeTLS, ModeNone, ModeReality:
		default:
			return "", nil, fmt.Errorf("--public-security must be tls, none or reality (got %q)", opts.PublicSecurity)
		}
		if requested != internal && internal != ModeNone {
			return "", nil, fmt.Errorf("--public-security %s conflicts with runtime stream security=%s", requested, security)
		}
		warnings := []string{}
		if requested == ModeTLS && security != "tls" {
			warnings = append(warnings, "public-tls-terminated-by-proxy: runtime stream security is none, --public-security tls supplied by caller")
		}
		return requested, warnings, nil
	}
	if internal != ModeNone {
		return internal, []string{}, nil
	}
	if isLoopback(listen) && (strings.TrimSpace(opts.Host) != "" || (opts.PublicPort != 0 && opts.PublicPort != port)) {
		return "", nil, fmt.Errorf("inbound listens on loopback %s with security=none: public security is ambiguous between an Nginx TLS front and a plain public port; pass --public-security tls|none (use the install metadata tls field)", listen)
	}
	return ModeNone, []string{}, nil
}

func specMode(mode, network string) string {
	if mode == ModeReality && network != TransportRaw {
		return ModeRealityNginx
	}
	return mode
}

func firstOf(values []string, fallback string) string {
	if len(values) > 0 {
		return values[0]
	}
	return fallback
}

func intField(v any) (int, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("port is not an integer")
		}
		return int(i), nil
	case float64:
		return int(n), nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, fmt.Errorf("port is not an integer")
		}
		return i, nil
	default:
		return 0, fmt.Errorf("port is missing")
	}
}
