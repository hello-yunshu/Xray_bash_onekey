package xraycfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// RoutingBlock is the operator-facing switch set that C2 renders into Xray
// routing rules. It mirrors traffic_blocker.json: the four Bash types plus the
// Go-only custom domain/IP lists.
type RoutingBlock struct {
	Countries     []string
	BitTorrent    bool
	Ads           bool
	PrivateIP     bool
	CustomDomains []string
	CustomIPs     []string
}

// InboundSniffing is the sniffing value one inbound carried before the block
// was applied. A nil Sniffing means the key was absent and must be deleted on
// restore, which is exactly what Bash stores in previous_sniffing.
type InboundSniffing struct {
	Tag      string `json:"tag"`
	Sniffing any    `json:"sniffing"`
}

// BlockState is everything Apply/Remove needs: the desired rules, the rules
// this manager wrote last time (so only those are removed), and the values
// that must come back when the block is turned off.
type BlockState struct {
	Block              RoutingBlock
	OwnedRules         []any
	PrevDomainStrategy string
	PrevSniffing       []InboundSniffing
}

// BlockRuleCount is the number of blocked rules this state owns.
func (s BlockState) BlockRuleCount() int { return len(s.OwnedRules) }

// NeedsGeo reports which GeoData files the enabled switches require.
func (b RoutingBlock) NeedsGeo() (geosite, geoip bool) {
	for _, cc := range b.Countries {
		if cc != "" {
			geosite, geoip = true, true
			break
		}
	}
	if b.Ads {
		geosite = true
	}
	if b.PrivateIP {
		geoip = true
	}
	return geosite, geoip
}

// Any reports whether at least one switch would produce a blocked rule.
func (b RoutingBlock) Any() bool {
	return len(b.Countries) > 0 || b.BitTorrent || b.Ads || b.PrivateIP ||
		len(b.CustomDomains) > 0 || len(b.CustomIPs) > 0
}

var countryCode = regexp.MustCompile(`^[a-z]{2}$`)

// BuildBlockRules renders the blocked rules in the exact order Bash uses:
// country domains, country IPs, BitTorrent, ads, private IPs, then the
// Go-only custom lists. An empty selector is never emitted.
func BuildBlockRules(b RoutingBlock) ([]any, error) {
	countries := make([]string, 0, len(b.Countries))
	seen := map[string]bool{}
	for _, raw := range b.Countries {
		cc := strings.ToLower(strings.TrimSpace(raw))
		if !countryCode.MatchString(cc) {
			return nil, fmt.Errorf("country code %q must be two letters", raw)
		}
		if seen[cc] {
			return nil, fmt.Errorf("country code %q is listed twice", raw)
		}
		seen[cc] = true
		countries = append(countries, cc)
	}
	domains, err := normalizeCustomDomains(b.CustomDomains)
	if err != nil {
		return nil, err
	}
	ips, err := normalizeCustomIPs(b.CustomIPs)
	if err != nil {
		return nil, err
	}

	rules := []any{}
	for _, cc := range countries {
		rules = append(rules, blockedRule("domain", "geosite:"+cc))
	}
	for _, cc := range countries {
		rules = append(rules, blockedRule("ip", "geoip:"+cc))
	}
	if b.BitTorrent {
		rules = append(rules, map[string]any{
			"type": "field", "outboundTag": "blocked", "protocol": []any{"bittorrent"},
		})
	}
	if b.Ads {
		rules = append(rules, blockedRule("domain", "geosite:category-ads-all"))
	}
	if b.PrivateIP {
		rules = append(rules, blockedRule("ip", "geoip:private"))
	}
	if len(domains) > 0 {
		rules = append(rules, stringListRule("domain", domains))
	}
	if len(ips) > 0 {
		rules = append(rules, stringListRule("ip", ips))
	}
	for _, rule := range rules {
		if err := validateBlockRule(rule); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

func blockedRule(key, value string) map[string]any {
	return map[string]any{"type": "field", "outboundTag": "blocked", key: []any{value}}
}

func stringListRule(key string, values []string) map[string]any {
	list := make([]any, 0, len(values))
	for _, v := range values {
		list = append(list, v)
	}
	return map[string]any{"type": "field", "outboundTag": "blocked", key: list}
}

// normalizeCustomDomains accepts bare domains as suffix matches and keeps an
// explicit Xray matcher prefix. Duplicates keep their first position.
func normalizeCustomDomains(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, fmt.Errorf("custom domain must not be empty")
		}
		if strings.ContainsAny(v, " \t\r\n") {
			return nil, fmt.Errorf("custom domain %q must not contain whitespace", raw)
		}
		switch {
		case strings.HasPrefix(v, "domain:"),
			strings.HasPrefix(v, "full:"),
			strings.HasPrefix(v, "regexp:"),
			strings.HasPrefix(v, "keyword:"),
			strings.HasPrefix(v, "geosite:"):
		default:
			v = "domain:" + v
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

func normalizeCustomIPs(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, fmt.Errorf("custom IP must not be empty")
		}
		if net.ParseIP(v) == nil {
			if _, _, err := net.ParseCIDR(v); err != nil {
				return nil, fmt.Errorf("custom IP %q is not an address or CIDR", raw)
			}
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

// blockSelectors are the matcher keys Xray accepts on a routing rule. A
// blocked rule without one of them would swallow every outbound connection.
var blockSelectors = []string{"domain", "ip", "protocol", "port", "network", "source", "user", "inboundTag"}

func validateBlockRule(rule any) error {
	m, ok := rule.(map[string]any)
	if !ok {
		return fmt.Errorf("routing rule is not an object")
	}
	if tag, _ := m["outboundTag"].(string); tag != "blocked" {
		return fmt.Errorf("generated block rule has outboundTag %q instead of blocked", tag)
	}
	for _, key := range blockSelectors {
		if v, ok := m[key]; ok && !emptySelector(v) {
			return nil
		}
	}
	return fmt.Errorf("blocked rule without a selector would block all traffic")
}

func emptySelector(v any) bool {
	switch t := v.(type) {
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	case string:
		return strings.TrimSpace(t) == ""
	case nil:
		return true
	}
	return false
}

// ApplyRoutingBlock merges the block rules into cfg, using cfg's own routing
// rules as the user-owned tail. It is the entry point for `block apply`.
func ApplyRoutingBlock(cfg []byte, st BlockState) ([]byte, BlockState, error) {
	return ApplyRoutingBlockWithRules(cfg, st, nil)
}

// ApplyRoutingBlockWithRules merges the block rules into cfg and uses userRules
// (when non-nil) as the user-owned tail. `config edit` regenerates the config
// from the generator and passes the live non-owned rules here, so an edit never
// drops an operator's hand-written routing rules.
func ApplyRoutingBlockWithRules(cfg []byte, st BlockState, userRules []any) ([]byte, BlockState, error) {
	root, err := parseRuntime(cfg)
	if err != nil {
		return nil, st, err
	}
	if err := requireOutbounds(root); err != nil {
		return nil, st, err
	}
	tags := inboundTags(root)
	if len(tags) == 0 {
		return nil, st, fmt.Errorf("cannot extract inbound tags from the runtime config")
	}
	if userRules == nil {
		rules, err := routingRulesOf(root)
		if err != nil {
			return nil, st, err
		}
		userRules = rules
	}
	user := stripOwnedRules(userRules, st.OwnedRules)
	if len(st.OwnedRules) == 0 {
		// First Go-side apply over a Bash install: Bash has no owned_rules, so
		// recognise the rules it is known to write and rebuild them instead of
		// keeping a stale duplicate.
		user = stripLegacyBashRules(user)
	}
	block, err := BuildBlockRules(st.Block)
	if err != nil {
		return nil, st, err
	}
	if len(user) > 0 && unconditionalBlocked(user[len(user)-1]) {
		return nil, st, fmt.Errorf("the last user routing rule blocks everything; remove it before applying traffic blocking")
	}
	merged := make([]any, 0, len(block)+len(user)+1)
	merged = append(merged, block...)
	merged = append(merged, user...)
	if !hasDirectRule(user) {
		merged = append(merged, directRule(tags))
	}

	strategy, prevStrategy := mergeDomainStrategy(root, st.Block, st.PrevDomainStrategy)
	sniffing, prevSniffing := mergeSniffing(root, st.Block, st.PrevSniffing)

	routing := asMap(root["routing"])
	routing["rules"] = merged
	routing["domainStrategy"] = strategy
	root["routing"] = routing
	if len(sniffing) > 0 {
		for tag, value := range sniffing {
			for _, item := range asSlice(root["inbounds"]) {
				inbound := asMap(item)
				if asString(inbound["tag"]) != tag {
					continue
				}
				if value == nil {
					delete(inbound, "sniffing")
				} else {
					inbound["sniffing"] = value
				}
			}
		}
	}
	applied := st
	applied.OwnedRules = block
	applied.PrevDomainStrategy = prevStrategy
	applied.PrevSniffing = prevSniffing
	return mustJSON(root), applied, nil
}

// RemoveRoutingBlock deletes exactly the rules this manager wrote and restores
// domainStrategy and sniffing to the values captured before the first apply.
func RemoveRoutingBlock(cfg []byte, st BlockState) ([]byte, BlockState, error) {
	root, err := parseRuntime(cfg)
	if err != nil {
		return nil, st, err
	}
	rules, err := routingRulesOf(root)
	if err != nil {
		return nil, st, err
	}
	restored := stripOwnedRules(rules, st.OwnedRules)
	routing := asMap(root["routing"])
	routing["rules"] = restored
	if st.PrevDomainStrategy != "" {
		routing["domainStrategy"] = st.PrevDomainStrategy
	}
	root["routing"] = routing
	if len(st.PrevSniffing) > 0 {
		for _, saved := range st.PrevSniffing {
			for _, item := range asSlice(root["inbounds"]) {
				inbound := asMap(item)
				if asString(inbound["tag"]) != saved.Tag {
					continue
				}
				if saved.Sniffing == nil {
					delete(inbound, "sniffing")
				} else {
					inbound["sniffing"] = saved.Sniffing
				}
			}
		}
	}
	out := st
	out.OwnedRules = nil
	out.PrevDomainStrategy = ""
	out.PrevSniffing = nil
	return mustJSON(root), out, nil
}

func requireOutbounds(root map[string]any) error {
	var blocked, direct bool
	for _, item := range asSlice(root["outbounds"]) {
		switch asString(asMap(item)["tag"]) {
		case "blocked":
			blocked = true
		case "direct":
			direct = true
		}
	}
	if !blocked {
		return fmt.Errorf("runtime config has no outbound tagged blocked; traffic blocking is unavailable")
	}
	if !direct {
		return fmt.Errorf("runtime config has no outbound tagged direct; traffic blocking is unavailable")
	}
	return nil
}

func inboundTags(root map[string]any) []any {
	tags := make([]any, 0)
	for _, item := range asSlice(root["inbounds"]) {
		if tag := asString(asMap(item)["tag"]); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func routingRulesOf(root map[string]any) ([]any, error) {
	routing, ok := root["routing"]
	if !ok || routing == nil {
		return nil, nil
	}
	m, ok := routing.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("routing is not an object")
	}
	return asSlice(m["rules"]), nil
}

// RoutingRulesFromConfig exposes the live routing rules for callers that need
// to inspect or preserve them without parsing the whole config.
func RoutingRulesFromConfig(cfg []byte) ([]any, error) {
	root, err := parseRuntime(cfg)
	if err != nil {
		return nil, err
	}
	return routingRulesOf(root)
}

// NonOwnedRules drops the rules this manager wrote, leaving operator rules.
func NonOwnedRules(rules, owned []any) []any { return stripOwnedRules(rules, owned) }

func stripOwnedRules(rules, owned []any) []any {
	if len(owned) == 0 {
		return append([]any{}, rules...)
	}
	counts := map[string]int{}
	for _, rule := range owned {
		counts[ruleKey(rule)]++
	}
	out := make([]any, 0, len(rules))
	for _, rule := range rules {
		key := ruleKey(rule)
		if counts[key] > 0 {
			counts[key]--
			continue
		}
		out = append(out, rule)
	}
	return out
}

// stripLegacyBashRules removes the exact rule shapes traffic_blocker.sh writes.
// Anything else with outboundTag blocked stays: it is the operator's rule.
func stripLegacyBashRules(rules []any) []any {
	out := make([]any, 0, len(rules))
	for _, rule := range rules {
		if !legacyBashRule(rule) {
			out = append(out, rule)
		}
	}
	return out
}

func legacyBashRule(rule any) bool {
	m, ok := rule.(map[string]any)
	if !ok || asString(m["outboundTag"]) != "blocked" {
		return false
	}
	if len(m) > 3 {
		return false
	}
	for key := range m {
		switch key {
		case "type", "outboundTag", "domain", "ip", "protocol":
		default:
			return false
		}
	}
	if domains := asSlice(m["domain"]); len(domains) == 1 {
		d, _ := domains[0].(string)
		return d == "geosite:category-ads-all" || twoLetter("geosite:", d)
	}
	if ips := asSlice(m["ip"]); len(ips) == 1 {
		v, _ := ips[0].(string)
		return v == "geoip:private" || twoLetter("geoip:", v)
	}
	if protocols := asSlice(m["protocol"]); len(protocols) == 1 {
		v, _ := protocols[0].(string)
		return v == "bittorrent"
	}
	return false
}

func twoLetter(prefix, value string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return countryCode.MatchString(strings.ToLower(strings.TrimPrefix(value, prefix)))
}

// ruleKey canonicalises a rule so objects decoded from different sources (the
// state file and the runtime config) compare equal. json.Marshal sorts object
// keys and renders json.Number without changing its value.
func ruleKey(rule any) string {
	b, err := json.Marshal(rule)
	if err != nil {
		return fmt.Sprintf("%#v", rule)
	}
	return string(b)
}

func unconditionalBlocked(rule any) bool {
	m, ok := rule.(map[string]any)
	if !ok || asString(m["outboundTag"]) != "blocked" {
		return false
	}
	for _, key := range blockSelectors {
		if v, ok := m[key]; ok && !emptySelector(v) {
			return false
		}
	}
	return true
}

func hasDirectRule(rules []any) bool {
	for _, rule := range rules {
		if asString(asMap(rule)["outboundTag"]) == "direct" {
			return true
		}
	}
	return false
}

func directRule(tags []any) map[string]any {
	return map[string]any{"type": "field", "inboundTag": tags, "outboundTag": "direct"}
}

// mergeDomainStrategy mirrors Bash: country codes and private IPs need IP
// matching, so domainStrategy becomes IPIfNonMatch and the old value is
// captured once. Turning those switches off restores the captured value.
func mergeDomainStrategy(root map[string]any, b RoutingBlock, prev string) (string, string) {
	current := asString(asMap(root["routing"])["domainStrategy"])
	if current == "" {
		current = "AsIs"
	}
	if len(b.Countries) > 0 || b.PrivateIP {
		if prev == "" {
			prev = current
		}
		return "IPIfNonMatch", prev
	}
	if prev != "" {
		return prev, ""
	}
	return current, ""
}

// mergeSniffing mirrors Bash: ads/domain matching and BitTorrent need sniffing.
// The per-inbound original is captured once and restored when every switch that
// needs sniffing is off.
func mergeSniffing(root map[string]any, b RoutingBlock, prev []InboundSniffing) (map[string]any, []InboundSniffing) {
	needs := b.BitTorrent || len(b.Countries) > 0 || b.Ads
	if needs {
		saved := prev
		if len(saved) == 0 {
			saved = captureSniffing(root)
		}
		out := map[string]any{}
		for _, item := range asSlice(root["inbounds"]) {
			if tag := asString(asMap(item)["tag"]); tag != "" {
				out[tag] = sniffingTemplate()
			}
		}
		return out, saved
	}
	out := map[string]any{}
	for _, saved := range prev {
		out[saved.Tag] = saved.Sniffing
	}
	return out, nil
}

func captureSniffing(root map[string]any) []InboundSniffing {
	saved := make([]InboundSniffing, 0)
	for _, item := range asSlice(root["inbounds"]) {
		inbound := asMap(item)
		tag := asString(inbound["tag"])
		if tag == "" {
			continue
		}
		saved = append(saved, InboundSniffing{Tag: tag, Sniffing: inbound["sniffing"]})
	}
	return saved
}

func sniffingTemplate() map[string]any {
	return map[string]any{
		"enabled":      true,
		"destOverride": []any{"http", "tls", "quic"},
		"routeOnly":    true,
	}
}

// hasRuleShape reports whether cfg already contains a rule byte-identical to
// want. Used by status/drift reporting.
func hasRuleShape(cfg []byte, want []any) (bool, error) {
	root, err := parseRuntime(cfg)
	if err != nil {
		return false, err
	}
	rules, err := routingRulesOf(root)
	if err != nil {
		return false, err
	}
	index := map[string]bool{}
	for _, rule := range rules {
		index[ruleKey(rule)] = true
	}
	for _, rule := range want {
		if !index[ruleKey(rule)] {
			return false, nil
		}
	}
	return true, nil
}

// OwnedRulesPresent reports whether every owned rule is still in the live
// config. `block status` uses it to flag drift instead of rewriting.
func OwnedRulesPresent(cfg []byte, owned []any) (bool, error) {
	if len(owned) == 0 {
		return false, nil
	}
	return hasRuleShape(cfg, owned)
}

// ConfigEqual compares two runtime configs by canonical JSON.
func ConfigEqual(a, b []byte) bool {
	var da, db any
	if err := decodeStrict(a, &da); err != nil {
		return bytes.Equal(a, b)
	}
	if err := decodeStrict(b, &db); err != nil {
		return bytes.Equal(a, b)
	}
	return ruleKey(da) == ruleKey(db)
}

func decodeStrict(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(out)
}
