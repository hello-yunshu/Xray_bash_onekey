// Package hotuser applies user changes to a running Xray through its API while
// the committed config remains the source of truth.
package hotuser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

var (
	// ErrNotConfigured means the config has no API inbound to talk to.
	ErrNotConfigured = errors.New("xray API is not enabled")
	// ErrApply means the running service still needs the persisted state.
	ErrApply = errors.New("running xray was not updated")
)

// Endpoint describes the API listener and the inbound that accepts users.
type Endpoint struct {
	Server     string `json:"server"`
	InboundTag string `json:"inboundTag"`
	Listen     string `json:"listen"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
}

// Locate finds the API listener and the user-bearing inbound in a config.
func Locate(raw []byte, serverOverride string) (Endpoint, error) {
	var doc struct {
		API *struct {
			Tag string `json:"tag"`
		} `json:"api"`
		Inbounds []struct {
			Listen   string          `json:"listen"`
			Port     int             `json:"port"`
			Protocol string          `json:"protocol"`
			Tag      string          `json:"tag"`
			Settings json.RawMessage `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Endpoint{}, fmt.Errorf("parse xray config: %w", err)
	}
	if doc.API == nil {
		return Endpoint{}, ErrNotConfigured
	}
	apiTag := doc.API.Tag
	if apiTag == "" {
		apiTag = "api"
	}
	var ep Endpoint
	foundAPI := false
	for _, in := range doc.Inbounds {
		if in.Tag == apiTag {
			foundAPI = true
			if serverOverride != "" {
				ep.Server = serverOverride
			} else {
				hostPart := in.Listen
				if hostPart == "" || hostPart == "0.0.0.0" || hostPart == "::" {
					hostPart = "127.0.0.1"
				}
				ep.Server = net.JoinHostPort(hostPart, fmt.Sprintf("%d", in.Port))
			}
			continue
		}
		if ep.InboundTag != "" || in.Port == 0 || in.Tag == "" {
			continue
		}
		if in.Protocol != "vless" && in.Protocol != "vmess" && in.Protocol != "trojan" {
			continue
		}
		ep.InboundTag = in.Tag
		ep.Listen = in.Listen
		ep.Port = in.Port
		ep.Protocol = in.Protocol
	}
	if !foundAPI || ep.Server == "" {
		return Endpoint{}, ErrNotConfigured
	}
	if ep.InboundTag == "" {
		return Endpoint{}, fmt.Errorf("no user-bearing inbound found; API hot changes need vless/vmess/trojan")
	}
	return ep, nil
}

// EnableAPI adds the loopback API inbound if it is missing. It returns the new
// config and whether anything changed; it never writes.
func EnableAPI(raw []byte, port int) ([]byte, bool, error) {
	if port < 1 || port > 65535 {
		return nil, false, fmt.Errorf("api port %d is out of range", port)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, fmt.Errorf("parse xray config: %w", err)
	}
	inbounds, _ := doc["inbounds"].([]any)
	for _, item := range inbounds {
		in, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if p, ok := in["port"].(float64); ok && int(p) == port && in["tag"] != "api" {
			return nil, false, fmt.Errorf("port %d is already used by inbound %v", port, in["tag"])
		}
	}
	apiTag := "api"
	if api, ok := doc["api"].(map[string]any); ok {
		if t, _ := api["tag"].(string); t != "" {
			apiTag = t
		}
	}
	haveInbound := false
	for _, item := range inbounds {
		if in, ok := item.(map[string]any); ok && in["tag"] == apiTag {
			haveInbound = true
		}
	}
	changed := false
	api, _ := doc["api"].(map[string]any)
	if api == nil {
		api = map[string]any{}
		doc["api"] = api
		changed = true
	}
	if t, _ := api["tag"].(string); t == "" {
		api["tag"] = apiTag
		changed = true
	}
	// Xray only registers StatsService when both api.services advertises it and
	// the top-level "stats" object exists; the legacy installer writes both.
	// Enabling the API without them yields an API that cannot answer stats.
	services, _ := api["services"].([]any)
	var extras []any
	for _, item := range services {
		switch s, _ := item.(string); s {
		case "StatsService", "HandlerService":
		default:
			extras = append(extras, item)
		}
	}
	// StatsService and HandlerService are always part of the managed API.
	normalized := []any{"StatsService", "HandlerService"}
	normalized = append(normalized, extras...)
	if !sameStrings(services, normalized) {
		api["services"] = normalized
		changed = true
	}
	if _, ok := doc["stats"]; !ok {
		doc["stats"] = map[string]any{}
		changed = true
	}
	if enableInboundTrafficStats(doc) {
		changed = true
	}
	if !haveInbound {
		doc["inbounds"] = append(inbounds, map[string]any{
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "dokodemo-door",
			"settings": map[string]any{"address": "127.0.0.1"},
			"tag":      apiTag,
		})
		routing, _ := doc["routing"].(map[string]any)
		if routing == nil {
			routing = map[string]any{}
			doc["routing"] = routing
		}
		rules, _ := routing["rules"].([]any)
		rule := map[string]any{"type": "field", "inboundTag": []any{apiTag}, "outboundTag": apiTag}
		routing["rules"] = append([]any{rule}, rules...)
		changed = true
	}
	if !changed {
		return raw, false, nil
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(out, '\n'), true, nil
}

// enableInboundTrafficStats makes inbound traffic queries useful. Xray requires
// these system policy flags in addition to the StatsService and stats object.
func enableInboundTrafficStats(doc map[string]any) bool {
	policy, _ := doc["policy"].(map[string]any)
	if policy == nil {
		policy = map[string]any{}
		doc["policy"] = policy
	}
	system, _ := policy["system"].(map[string]any)
	if system == nil {
		system = map[string]any{}
		policy["system"] = system
	}
	changed := false
	for _, key := range []string{"statsInboundUplink", "statsInboundDownlink"} {
		if enabled, _ := system[key].(bool); !enabled {
			system[key] = true
			changed = true
		}
	}
	return changed
}

func sameStrings(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		as, _ := a[i].(string)
		bs, _ := b[i].(string)
		if as != bs {
			return false
		}
	}
	return true
}

// Reachable asks the API for the inbound list; it proves the listener answers.
func Reachable(ctx context.Context, xray, server string) error {
	res, err := host.Run(ctx, host.ExecSpec{
		Path: xray, Args: []string{"api", "lsi", "--server=" + server}, Timeout: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("xray api lsi: %s", strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return nil
}

// WaitReachable polls the API until it answers or the timeout expires.
func WaitReachable(ctx context.Context, xray, server string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = Reachable(ctx, xray, server); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return last
}

// Lookup returns the runtime UUID for an email, or "" when it is absent.
func Lookup(ctx context.Context, xray, server, tag, email string) (string, error) {
	res, err := host.Run(ctx, host.ExecSpec{
		Path:    xray,
		Args:    []string{"api", "inbounduser", "--server=" + server, "--tag=" + tag, "--email=" + email},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Users []struct {
			Account *struct {
				ID string `json:"id"`
			} `json:"account"`
			ID string `json:"id"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		return "", fmt.Errorf("parse inbounduser: %w", err)
	}
	for _, u := range out.Users {
		if u.Account != nil && u.Account.ID != "" {
			return u.Account.ID, nil
		}
		if u.ID != "" {
			return u.ID, nil
		}
	}
	return "", nil
}

// Add inserts one user into the running inbound and proves it appeared. Flow and
// level come from the persisted client record, so the running inbound never
// drifts from the config that is the source of truth.
func Add(ctx context.Context, xray string, ep Endpoint, email, id, flow string, level int) error {
	user := map[string]any{"email": email, "id": id, "level": level}
	if flow != "" && ep.Protocol == "vless" {
		user["flow"] = flow
	}
	settings := map[string]any{"clients": []any{user}}
	if ep.Protocol == "vless" {
		settings["decryption"] = "none"
	}
	fragment := map[string]any{"inbounds": []any{map[string]any{
		"tag": ep.InboundTag, "listen": ep.Listen, "port": ep.Port,
		"protocol": ep.Protocol, "settings": settings,
	}}}
	data, err := json.Marshal(fragment)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "idleleo-hotuser-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "add.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		return err
	}
	res, err := host.Run(ctx, host.ExecSpec{
		Path: xray, Args: []string{"api", "adu", "--server=" + ep.Server, file}, Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		// A retry after a half-failed apply finds the user already present;
		// that is the desired end state, not a failure.
		if got, lookupErr := Lookup(ctx, xray, ep.Server, ep.InboundTag, email); lookupErr == nil && got == id {
			return nil
		}
		return fmt.Errorf("%w: adu: %s", ErrApply, strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return waitFor(ctx, xray, ep.Server, ep.InboundTag, email, id, true)
}

// Remove deletes one user from the running inbound and proves it disappeared.
func Remove(ctx context.Context, xray string, ep Endpoint, email string) error {
	res, err := host.Run(ctx, host.ExecSpec{
		Path:    xray,
		Args:    []string{"api", "rmu", "--server=" + ep.Server, "--tag=" + ep.InboundTag, email},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		if got, lookupErr := Lookup(ctx, xray, ep.Server, ep.InboundTag, email); lookupErr == nil && got == "" {
			return nil
		}
		return fmt.Errorf("%w: rmu: %s", ErrApply, strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return waitFor(ctx, xray, ep.Server, ep.InboundTag, email, "", false)
}

func waitFor(ctx context.Context, xray, server, tag, email, wantID string, present bool) error {
	deadline := time.Now().Add(3 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		got, err := Lookup(ctx, xray, server, tag, email)
		if err == nil {
			last = got
			if present && got == wantID {
				return nil
			}
			if !present && got == "" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if present {
		return fmt.Errorf("%w: user %s did not appear in the running inbound (id=%q)", ErrApply, email, last)
	}
	return fmt.Errorf("%w: user %s is still present in the running inbound (id=%q)", ErrApply, email, last)
}
