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
	Flow      string   `json:"flow,omitempty"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	ShareURI  string   `json:"shareUri"`
	ClashYAML string   `json:"clashYaml,omitempty"`
	Warnings  []string `json:"warnings"`
}

// Share renders VLESS URI and Clash proxy for the first client of one inbound.
// host and publicPort override what is stored in the config (the config usually
// keeps the loopback backend port when Nginx terminates TLS).
func Share(raw []byte, inboundIndex int, host string, publicPort int) (ShareInfo, error) {
	root, err := decode(raw)
	if err != nil {
		return ShareInfo{}, err
	}
	in, err := inboundAt(root, inboundIndex)
	if err != nil {
		return ShareInfo{}, err
	}
	if protocol, _ := in["protocol"].(string); !strings.EqualFold(protocol, "vless") {
		return ShareInfo{}, fmt.Errorf("inbound %d is not VLESS", inboundIndex)
	}
	settings, _ := in["settings"].(map[string]any)
	clients, _ := settings["clients"].([]any)
	if len(clients) == 0 {
		return ShareInfo{}, fmt.Errorf("inbound %d has no clients", inboundIndex)
	}
	first, _ := clients[0].(map[string]any)
	if first == nil {
		return ShareInfo{}, fmt.Errorf("primary client is not an object")
	}
	id, _ := first["id"].(string)
	flow, _ := first["flow"].(string)
	if !validUUID(id) {
		return ShareInfo{}, fmt.Errorf("primary client has invalid uuid")
	}
	port, err := intField(in["port"])
	if err != nil {
		return ShareInfo{}, err
	}
	listen, _ := in["listen"].(string)
	if publicPort == 0 {
		publicPort = port
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
	mode := ModeNone
	if security == "reality" {
		mode = ModeReality
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
		mode = ModeTLS
		if tls, _ := stream["tlsSettings"].(map[string]any); tls != nil {
			if s, _ := tls["serverName"].(string); s != "" {
				serverNames = []string{s}
			}
		}
	}
	if host == "" {
		if len(serverNames) > 0 {
			host = serverNames[0]
		} else {
			host = listen
		}
	}
	publicKey := ""
	if privateKey != "" {
		publicKey, err = DerivePublicKey(privateKey)
		if err != nil {
			return ShareInfo{}, err
		}
	}
	spec := Spec{
		Mode: specMode(mode, network), Transport: network, Port: port, PublicPort: publicPort,
		Listen: listen, Domain: host, Path: path, ServiceName: serviceName,
		UUID: id, Flow: flow, ServerNames: serverNames, ShortID: shortID,
	}
	if len(serverNames) == 0 && host != "" {
		spec.ServerNames = []string{host}
	}
	out := ShareInfo{Mode: mode, Transport: network, UUID: id, Flow: flow, Host: host, Port: publicPort, Warnings: []string{}}
	if publicKey != "" {
		out.ShareURI = buildShareURI(spec, network, host, publicKey, shortID, firstOf(serverNames, host))
	} else {
		out.ShareURI = buildShareURI(spec, network, host, "", shortID, firstOf(serverNames, host))
	}
	var tmp Generated
	out.ClashYAML = buildClash(spec, network, host, publicKey, shortID, firstOf(serverNames, host), &tmp)
	out.Warnings = tmp.Warnings
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	return out, nil
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
