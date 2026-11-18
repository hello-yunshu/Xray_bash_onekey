package hotuser

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const baseConfig = `{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"listen": "0.0.0.0", "port": 443, "protocol": "vless", "tag": "reality",
     "settings": {"clients": [{"id": "11111111-1111-1111-1111-111111111111", "email": "a", "flow": "xtls-rprx-vision"}], "decryption": "none"}}
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}`

func TestLocateRequiresAPI(t *testing.T) {
	_, err := Locate([]byte(baseConfig), "")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestEnableAPIAddsLoopbackInboundAndRule(t *testing.T) {
	out, changed, err := EnableAPI([]byte(baseConfig), 10085)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected a change")
	}
	ep, err := Locate(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Server != "127.0.0.1:10085" {
		t.Fatalf("server = %q", ep.Server)
	}
	if ep.InboundTag != "reality" || ep.Protocol != "vless" || ep.Port != 443 {
		t.Fatalf("endpoint = %+v", ep)
	}
	var doc struct {
		API     map[string]any `json:"api"`
		Routing struct {
			Rules []struct {
				InboundTag  []string `json:"inboundTag"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.API["tag"] != "api" {
		t.Fatalf("api tag = %v", doc.API["tag"])
	}
	if len(doc.Routing.Rules) == 0 || doc.Routing.Rules[0].OutboundTag != "api" {
		t.Fatalf("api routing rule missing: %+v", doc.Routing.Rules)
	}
}

func TestEnableAPIIsIdempotent(t *testing.T) {
	once, _, err := EnableAPI([]byte(baseConfig), 10085)
	if err != nil {
		t.Fatal(err)
	}
	twice, changed, err := EnableAPI(once, 10086)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second enable reported a change")
	}
	if string(twice) != string(once) {
		t.Fatal("idempotent enable rewrote the config")
	}
}

func TestEnableAPIRejectsPortConflict(t *testing.T) {
	_, _, err := EnableAPI([]byte(baseConfig), 443)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("want port conflict, got %v", err)
	}
}

func TestEnableAPIRejectsOutOfRangePort(t *testing.T) {
	if _, _, err := EnableAPI([]byte(baseConfig), 0); err == nil {
		t.Fatal("port 0 accepted")
	}
	if _, _, err := EnableAPI([]byte(baseConfig), 70000); err == nil {
		t.Fatal("port 70000 accepted")
	}
}

func TestEnableAPIReportsMissingUsersInbound(t *testing.T) {
	cfg := `{"inbounds":[{"listen":"127.0.0.1","port":8080,"protocol":"dokodemo-door","tag":"front"}],"outbounds":[]}`
	out, changed, err := EnableAPI([]byte(cfg), 10085)
	if err != nil || !changed {
		t.Fatalf("enable failed: changed=%v err=%v", changed, err)
	}
	if _, err := Locate(out, ""); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want a no-user-inbound error, got %v", err)
	}
}

func TestLocateHonoursServerOverride(t *testing.T) {
	cfg := `{
  "api": {"tag": "api", "services": ["HandlerService"]},
  "inbounds": [
    {"listen": "", "port": 10085, "protocol": "dokodemo-door", "tag": "api"},
    {"listen": "::", "port": 443, "protocol": "vless", "tag": "v", "settings": {"clients": []}}
  ]
}`
	ep, err := Locate([]byte(cfg), "127.0.0.1:19000")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Server != "127.0.0.1:19000" {
		t.Fatalf("override ignored: %q", ep.Server)
	}
	if ep.InboundTag != "v" || ep.Port != 443 {
		t.Fatalf("inbound = %+v", ep)
	}
}

func TestLocateDefaultsWildcardAPIToLoopback(t *testing.T) {
	cfg := `{
  "api": {"tag": "api"},
  "inbounds": [
    {"listen": "::", "port": 10085, "protocol": "dokodemo-door", "tag": "api"},
    {"port": 8443, "protocol": "trojan", "tag": "t", "settings": {"clients": []}}
  ]
}`
	ep, err := Locate([]byte(cfg), "")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Server != "127.0.0.1:10085" {
		t.Fatalf("server = %q", ep.Server)
	}
	if ep.Protocol != "trojan" || ep.Port != 8443 {
		t.Fatalf("endpoint = %+v", ep)
	}
}
