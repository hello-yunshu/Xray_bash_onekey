package xraycfg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AdoptRuntime takes an existing Xray runtime config and returns a canonical
// copy that preserves every field byte-for-byte (only indentation changes).
//
// It exists so an operator can move an existing Bash-managed configuration
// under Go management without the generator silently replacing ports, paths,
// UUIDs, Reality keys or custom DNS/routing. The CLI refuses to regenerate
// over an existing config unless the operator explicitly asks for a rewrite;
// this is the safe "modify in place" entry point instead.
//
// The copy is validated before it is returned so a corrupt file cannot be
// adopted as if it were usable. Unknown/custom fields are intentionally kept.
func AdoptRuntime(raw []byte) ([]byte, error) {
	var probe runtimeProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("runtime config is not valid JSON: %w", err)
	}
	if len(probe.Inbounds) == 0 {
		return nil, fmt.Errorf("runtime config has no inbounds to preserve")
	}
	tags := map[string]bool{}
	ports := map[string]bool{}
	for i, ib := range probe.Inbounds {
		where := "inbound[" + strconv.Itoa(i) + "]"
		if ib.Port < 1 || ib.Port > 65535 {
			return nil, fmt.Errorf("%s port %d is outside 1-65535", where, ib.Port)
		}
		if ib.Protocol == "" {
			return nil, fmt.Errorf("%s has no protocol", where)
		}
		if ib.StreamSettings.Security != "" {
			switch ib.StreamSettings.Security {
			case "none", "tls", "reality":
			default:
				return nil, fmt.Errorf("%s has unsupported security %q", where, ib.StreamSettings.Security)
			}
		}
		if ib.Tag != "" {
			if tags[ib.Tag] {
				return nil, fmt.Errorf("duplicate inbound tag %q", ib.Tag)
			}
			tags[ib.Tag] = true
		}
		listen := ib.Listen
		if listen == "" {
			// Xray binds all interfaces when listen is omitted; record it as such
			// for the conflict check but keep the original empty value in output.
			listen = "0.0.0.0"
		}
		key := net.JoinHostPort(strings.Trim(listen, "[]"), strconv.Itoa(ib.Port))
		if ports[key] {
			return nil, fmt.Errorf("two inbounds bind %s", key)
		}
		ports[key] = true
		for _, c := range ib.Settings.Clients {
			if c.ID != "" && !validUUID(c.ID) {
				return nil, fmt.Errorf("%s client id is not an RFC4122 UUID", where)
			}
		}
		if rs := ib.StreamSettings.RealitySettings; rs != nil {
			for _, pk := range []string{rs.PrivateKey, rs.Settings.PrivateKey} {
				if pk == "" {
					continue
				}
				rawKey, err := base64.RawURLEncoding.DecodeString(pk)
				if err != nil || len(rawKey) != 32 {
					return nil, fmt.Errorf("%s reality privateKey is not 32-byte base64url", where)
				}
			}
			for _, sid := range rs.ShortIDs {
				if !validShortID(sid) {
					return nil, fmt.Errorf("%s reality shortId %q is invalid", where, sid)
				}
			}
		}
	}
	// json.Indent keeps key order and every value exactly as written; unlike
	// unmarshal/marshal it cannot drop or normalize unknown custom fields.
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return nil, fmt.Errorf("reindent runtime config: %w", err)
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

type runtimeProbe struct {
	Inbounds []struct {
		Port     int    `json:"port"`
		Listen   string `json:"listen"`
		Protocol string `json:"protocol"`
		Tag      string `json:"tag"`
		Settings struct {
			Clients []struct {
				ID string `json:"id"`
			} `json:"clients"`
		} `json:"settings"`
		StreamSettings struct {
			Network         string `json:"network"`
			Security        string `json:"security"`
			RealitySettings *struct {
				PrivateKey string   `json:"privateKey"`
				ShortIDs   []string `json:"shortIds"`
				Settings   struct {
					PrivateKey string `json:"privateKey"`
				} `json:"settings"`
			} `json:"realitySettings"`
		} `json:"streamSettings"`
	} `json:"inbounds"`
}
