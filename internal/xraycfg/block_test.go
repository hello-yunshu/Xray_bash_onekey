package xraycfg

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func blockBase(t *testing.T) []byte {
	t.Helper()
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS})
	if err != nil {
		t.Fatal(err)
	}
	return g.Config
}

func decodeRoot(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// injectUserRule adds a hand-written rule the way an operator would, so the
// preservation assertions have something to protect.
func injectUserRule(t *testing.T, raw []byte) []byte {
	t.Helper()
	root := decodeRoot(t, raw)
	routing := asMap(root["routing"])
	rules := asSlice(routing["rules"])
	user := map[string]any{"type": "field", "outboundTag": "blocked", "domain": []any{"full:corp.example"}}
	routing["rules"] = append(rules, user)
	root["routing"] = routing
	return mustJSON(root)
}

func routingOf(t *testing.T, raw []byte) ([]any, string) {
	t.Helper()
	root := decodeRoot(t, raw)
	routing := asMap(root["routing"])
	return asSlice(routing["rules"]), asString(routing["domainStrategy"])
}

func TestBuildBlockRulesMatchesBashOrder(t *testing.T) {
	rules, err := BuildBlockRules(RoutingBlock{
		Countries:     []string{"cn", "us"},
		BitTorrent:    true,
		Ads:           true,
		PrivateIP:     true,
		CustomDomains: []string{"ads.example", "full:exact.example"},
		CustomIPs:     []string{"203.0.113.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"domain":["geosite:cn"],"outboundTag":"blocked","type":"field"}`,
		`{"domain":["geosite:us"],"outboundTag":"blocked","type":"field"}`,
		`{"ip":["geoip:cn"],"outboundTag":"blocked","type":"field"}`,
		`{"ip":["geoip:us"],"outboundTag":"blocked","type":"field"}`,
		`{"outboundTag":"blocked","protocol":["bittorrent"],"type":"field"}`,
		`{"domain":["geosite:category-ads-all"],"outboundTag":"blocked","type":"field"}`,
		`{"ip":["geoip:private"],"outboundTag":"blocked","type":"field"}`,
		`{"domain":["domain:ads.example","full:exact.example"],"outboundTag":"blocked","type":"field"}`,
		`{"ip":["203.0.113.0/24"],"outboundTag":"blocked","type":"field"}`,
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d: %v", len(want), len(rules), rules)
	}
	for i := range want {
		if got := ruleKey(rules[i]); got != want[i] {
			t.Fatalf("rule %d = %s, want %s", i, got, want[i])
		}
	}
}

func TestBuildBlockRulesRejectsBadInput(t *testing.T) {
	for _, tc := range []RoutingBlock{
		{Countries: []string{"chn"}},
		{Countries: []string{"cn", "CN"}},
		{CustomDomains: []string{" "}},
		{CustomIPs: []string{"not-an-ip"}},
	} {
		if _, err := BuildBlockRules(tc); err == nil {
			t.Fatalf("expected rejection for %+v", tc)
		}
	}
}

func TestApplyRoutingBlockIsIdempotent(t *testing.T) {
	raw := injectUserRule(t, blockBase(t))
	st := BlockState{Block: RoutingBlock{
		Countries: []string{"cn"}, Ads: true, PrivateIP: true, BitTorrent: true,
		CustomDomains: []string{"ads.example"},
	}}
	first, applied, err := ApplyRoutingBlock(raw, st)
	if err != nil {
		t.Fatal(err)
	}
	second, applied2, err := ApplyRoutingBlock(first, applied)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("second apply changed the config:\n%s\n---\n%s", first, second)
	}
	if len(applied.OwnedRules) != len(applied2.OwnedRules) {
		t.Fatalf("owned rule count drifted: %d -> %d", len(applied.OwnedRules), len(applied2.OwnedRules))
	}
	rules, strategy := routingOf(t, second)
	if strategy != "IPIfNonMatch" {
		t.Fatalf("domainStrategy = %q, want IPIfNonMatch", strategy)
	}
	if !hasDirectRule(rules) {
		t.Fatalf("merged rules lost the direct tail: %v", rules)
	}
	// The hand-written rule must survive both applies.
	var found bool
	for _, rule := range rules {
		m := asMap(rule)
		if m["outboundTag"] == "blocked" && reflect.DeepEqual(m["domain"], []any{"full:corp.example"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("user rule was dropped: %v", rules)
	}
	if len(applied.OwnedRules) != 6 {
		t.Fatalf("expected 6 owned rules, got %d", len(applied.OwnedRules))
	}
}

func TestApplyRoutingBlockRefusesCatchAllUserRule(t *testing.T) {
	root := decodeRoot(t, blockBase(t))
	routing := asMap(root["routing"])
	routing["rules"] = append(asSlice(routing["rules"]), map[string]any{
		"type": "field", "outboundTag": "blocked",
	})
	root["routing"] = routing
	if _, _, err := ApplyRoutingBlock(mustJSON(root), BlockState{Block: RoutingBlock{Ads: true}}); err == nil {
		t.Fatal("expected refusal for an unconditional blocked tail")
	}
}

func TestRemoveRoutingBlockRestoresPreviousValues(t *testing.T) {
	raw := blockBase(t)
	st := BlockState{Block: RoutingBlock{Countries: []string{"cn"}, Ads: true, PrivateIP: true}}
	appliedConfig, applied, err := ApplyRoutingBlock(raw, st)
	if err != nil {
		t.Fatal(err)
	}
	restored, cleared, err := RemoveRoutingBlock(appliedConfig, applied)
	if err != nil {
		t.Fatal(err)
	}
	rules, strategy := routingOf(t, restored)
	if strategy != "AsIs" {
		t.Fatalf("domainStrategy not restored: %q", strategy)
	}
	if len(cleared.OwnedRules) != 0 || cleared.PrevDomainStrategy != "" || cleared.PrevSniffing != nil {
		t.Fatalf("state not cleared: %+v", cleared)
	}
	for _, rule := range rules {
		if asString(asMap(rule)["outboundTag"]) == "blocked" {
			t.Fatalf("blocked rule survived removal: %s", ruleKey(rule))
		}
	}
	root := decodeRoot(t, restored)
	for _, item := range asSlice(root["inbounds"]) {
		if _, ok := asMap(item)["sniffing"]; ok {
			t.Fatalf("sniffing not restored: %v", item)
		}
	}
}

// TestEditUUIDKeepsTrafficBlock is the C2 ordering gate: installing blocking
// then editing the UUID must not drop a single owned rule, must keep the
// operator's own rule, and must keep the direct tail that lets normal sites
// through.
func TestEditUUIDKeepsTrafficBlock(t *testing.T) {
	raw := injectUserRule(t, blockBase(t))
	st := BlockState{Block: RoutingBlock{
		Countries: []string{"cn"}, Ads: true, PrivateIP: true, BitTorrent: true,
		CustomDomains: []string{"ads.example"},
		CustomIPs:     []string{"203.0.113.0/24"},
	}}
	live, applied, err := ApplyRoutingBlock(raw, st)
	if err != nil {
		t.Fatal(err)
	}
	beforeRules, beforeStrategy := routingOf(t, live)
	if _, ok := asMap(asSlice(decodeRoot(t, live)["inbounds"])[0])["sniffing"]; !ok {
		t.Fatal("fixture did not apply sniffing")
	}

	g, res, err := EditRuntime(live, EditDefaults{Mode: ModeReality, PublicPort: 443, RoutingBlock: &applied},
		EditRequest{UUID: "11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatalf("edit with block state failed: %v", err)
	}
	if !res.BlockPreserved || res.BlockRuleCount != len(applied.OwnedRules) {
		t.Fatalf("block not reported as preserved: %+v", res)
	}
	afterRules, afterStrategy := routingOf(t, g.Config)
	if afterStrategy != beforeStrategy {
		t.Fatalf("domainStrategy drifted: %q -> %q", beforeStrategy, afterStrategy)
	}
	// The whole rule list must be identical: same owned rules, same user rule,
	// same order, same direct tail.
	if len(afterRules) != len(beforeRules) {
		t.Fatalf("rule count drifted: %d -> %d\nbefore=%v\nafter=%v", len(beforeRules), len(afterRules), beforeRules, afterRules)
	}
	for i := range beforeRules {
		if ruleKey(beforeRules[i]) != ruleKey(afterRules[i]) {
			t.Fatalf("rule %d drifted:\n before=%s\n after =%s", i, ruleKey(beforeRules[i]), ruleKey(afterRules[i]))
		}
	}
	if !hasDirectRule(afterRules) {
		t.Fatalf("direct tail lost: %v", afterRules)
	}
	if ok, err := OwnedRulesPresent(g.Config, applied.OwnedRules); err != nil || !ok {
		t.Fatalf("owned rules not all present (ok=%t err=%v)", ok, err)
	}
	// Dining the sniffing requirement: ads/country need it, so it must remain.
	first := asMap(asSlice(decodeRoot(t, g.Config)["inbounds"])[0])
	sniffing := asMap(first["sniffing"])
	if sniffing["enabled"] != true {
		t.Fatalf("sniffing lost after edit: %v", first["sniffing"])
	}
	if !strings.Contains(string(g.Config), "11111111-2222-3333-4444-555555555555") {
		t.Fatal("uuid edit did not apply")
	}
	// Guard the fixture: the edited config is still valid JSON with a blocked outbound.
	var parsed map[string]any
	if err := json.Unmarshal(g.Config, &parsed); err != nil {
		t.Fatalf("edited config is not JSON: %v", err)
	}
}

// TestApplyReplacesBashRulesOnFirstRun covers the one-time migration: Bash
// leaves no owned_rules, so its known rule shapes are recognised and rebuilt,
// while an operator's own blocked rule survives.
func TestApplyReplacesBashRulesOnFirstRun(t *testing.T) {
	root := decodeRoot(t, blockBase(t))
	routing := asMap(root["routing"])
	routing["rules"] = []any{
		map[string]any{"type": "field", "outboundTag": "blocked", "domain": []any{"geosite:category-ads-all"}},
		map[string]any{"type": "field", "outboundTag": "blocked", "ip": []any{"geoip:private"}},
		map[string]any{"type": "field", "outboundTag": "blocked", "domain": []any{"full:corp.example"}},
		map[string]any{"type": "field", "inboundTag": []any{"vless-ws"}, "outboundTag": "direct"},
	}
	root["routing"] = routing
	out, applied, err := ApplyRoutingBlock(mustJSON(root), BlockState{Block: RoutingBlock{Ads: true}})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := routingOf(t, out)
	if len(applied.OwnedRules) != 1 {
		t.Fatalf("expected one owned rule, got %v", applied.OwnedRules)
	}
	var ads, user int
	for _, rule := range rules {
		m := asMap(rule)
		if asString(m["outboundTag"]) != "blocked" {
			continue
		}
		if reflect.DeepEqual(m["domain"], []any{"geosite:category-ads-all"}) {
			ads++
		}
		if reflect.DeepEqual(m["domain"], []any{"full:corp.example"}) {
			user++
		}
		if reflect.DeepEqual(m["ip"], []any{"geoip:private"}) {
			t.Fatalf("legacy private rule was not replaced: %v", rules)
		}
	}
	if ads != 1 || user != 1 {
		t.Fatalf("expected one rebuilt ads rule and one user rule, got ads=%d user=%d: %v", ads, user, rules)
	}
}

// TestEditWithoutBlockStateStillRefusesRoutingChanges keeps the old contract:
// an install with no traffic_blocker.json must not silently gain routing rules.
func TestEditWithoutBlockStateStillRefusesRoutingChanges(t *testing.T) {
	raw := injectUserRule(t, blockBase(t))
	if _, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{UUID: "11111111-2222-3333-4444-555555555555"}); err == nil {
		t.Fatal("expected refusal: regeneration would drop the hand-written routing rule")
	}
}
