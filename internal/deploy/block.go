package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/geodata"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

const (
	// blockStateRel is the same file Bash writes, so both managers can take
	// over from each other.
	blockStateRel      = "etc/idleleo/conf/xray/traffic_blocker.json"
	blockAssetDropIn   = "etc/systemd/system/xray.service.d/50-xray-geodata.conf"
	blockBackupPrefix  = "block-"
	blockGeoMaxAgeDays = 30
)

// geodataEnv is the environment every xray -test call needs once a config
// references geoip:/geosite: rules.
func geodataEnv(root string) []string {
	return []string{"XRAY_LOCATION_ASSET=" + filepath.Join(root, "etc/idleleo/share/xray")}
}

// BlockApplySpec is one `xray block apply` / `xray block off` request.
type BlockApplySpec struct {
	Root                 string
	ConfigPath           string
	DryRun               bool
	NoRestart            bool
	NoProbe              bool
	AllowContainerWrites bool
	// GeodataURL overrides the release origin (tests point it at a local server).
	GeodataURL string
}

// BlockGeoReport describes one GeoData file so status can warn about staleness.
type BlockGeoReport struct {
	Path    string `json:"path"`
	Size    int64  `json:"size,omitempty"`
	ModTime string `json:"mtime,omitempty"`
	Missing bool   `json:"missing,omitempty"`
	Stale   bool   `json:"stale,omitempty"`
}

// BlockCustomReport is one custom list's state.
type BlockCustomReport struct {
	Enabled bool     `json:"enabled"`
	Items   []string `json:"items"`
}

// BlockReport is the read-only view used by `block status` and as the payload
// of apply/off.
type BlockReport struct {
	Configured      bool              `json:"configured"`
	Applied         bool              `json:"applied"`
	Drift           bool              `json:"drift"`
	Ads             bool              `json:"ads"`
	PrivateIP       bool              `json:"privateIp"`
	BitTorrent      bool              `json:"bittorrent"`
	Countries       []string          `json:"countries"`
	CustomDomains   BlockCustomReport `json:"customDomains"`
	CustomIPs       BlockCustomReport `json:"customIps"`
	OwnedRuleCount  int               `json:"ownedRuleCount"`
	DomainStrategy  string            `json:"domainStrategy,omitempty"`
	SniffingEnabled bool              `json:"sniffingEnabled"`
	Geosite         BlockGeoReport    `json:"geosite"`
	Geoip           BlockGeoReport    `json:"geoip"`
	ConfigPath      string            `json:"configPath,omitempty"`
	OldSHA256       string            `json:"oldSha256,omitempty"`
	NewSHA256       string            `json:"newSha256,omitempty"`
	BackupDir       string            `json:"backupDir,omitempty"`
	AssetEnv        string            `json:"assetEnv,omitempty"`
	ServiceRestart  bool              `json:"serviceRestarted"`
	ControlProbe    string            `json:"controlProbe,omitempty"`
	FailurePoint    string            `json:"failurePoint,omitempty"`
	Warnings        []string          `json:"warnings,omitempty"`
}

// blockDoc keeps the raw state document so unknown keys written by Bash (or a
// future version) survive every update.
type blockDoc struct {
	path string
	doc  map[string]any
	raw  []byte
	ok   bool
}

func loadBlockDoc(paths host.Paths) (*blockDoc, error) {
	p, err := paths.Join(blockStateRel, false)
	if err != nil {
		// A sandbox that has never run blocking has no conf directory yet;
		// that is an empty state, not an error.
		if os.IsNotExist(err) {
			return &blockDoc{doc: map[string]any{}}, nil
		}
		return nil, err
	}
	doc := &blockDoc{path: p, doc: map[string]any{}}
	raw, readErr := os.ReadFile(p)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return doc, nil
		}
		return nil, readErr
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc.doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", blockStateRel, err)
	}
	doc.raw, doc.ok = raw, true
	return doc, nil
}

func (d *blockDoc) save(paths host.Paths) error {
	p, err := paths.Join(blockStateRel, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(d.doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(p, append(b, '\n'), 0o644)
}

func objectValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func listValue(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

func stringList(v any) []string {
	l := listValue(v)
	out := make([]string, 0, len(l))
	for _, item := range l {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func customList(v any) BlockCustomReport {
	m := objectValue(v)
	return BlockCustomReport{Enabled: boolValue(m["enabled"]), Items: stringList(m["items"])}
}

func stateFromDoc(d *blockDoc) xraycfg.BlockState {
	st := xraycfg.BlockState{}
	st.Block.Countries = stringList(d.doc["country_block"])
	st.Block.BitTorrent = boolValue(d.doc["bittorrent"])
	st.Block.Ads = boolValue(d.doc["ads"])
	st.Block.PrivateIP = boolValue(d.doc["private_ip"])
	if custom := customList(d.doc["custom_domains"]); custom.Enabled {
		st.Block.CustomDomains = custom.Items
	}
	if custom := customList(d.doc["custom_ips"]); custom.Enabled {
		st.Block.CustomIPs = custom.Items
	}
	st.OwnedRules = listValue(d.doc["owned_rules"])
	st.PrevDomainStrategy = stringValue(d.doc["previous_domain_strategy"])
	for _, item := range listValue(d.doc["previous_sniffing"]) {
		m := objectValue(item)
		if tag := stringValue(m["tag"]); tag != "" {
			st.PrevSniffing = append(st.PrevSniffing, xraycfg.InboundSniffing{Tag: tag, Sniffing: m["sniffing"]})
		}
	}
	return st
}

func (d *blockDoc) setApplied(applied xraycfg.BlockState, live bool) {
	d.doc["applied"] = live
	d.doc["owned_rules"] = applied.OwnedRules
	if applied.PrevDomainStrategy != "" {
		d.doc["previous_domain_strategy"] = applied.PrevDomainStrategy
	} else {
		delete(d.doc, "previous_domain_strategy")
	}
	if len(applied.PrevSniffing) > 0 {
		items := make([]any, 0, len(applied.PrevSniffing))
		for _, saved := range applied.PrevSniffing {
			items = append(items, map[string]any{"tag": saved.Tag, "sniffing": saved.Sniffing})
		}
		d.doc["previous_sniffing"] = items
	} else {
		delete(d.doc, "previous_sniffing")
	}
}

// loadBlockState is the edit path's read-only loader. A state file with every
// switch off and no owned rules is treated as absent so edits keep the strict
// pre-C2 diff scope.
func loadBlockState(paths host.Paths) (xraycfg.BlockState, bool, error) {
	d, err := loadBlockDoc(paths)
	if err != nil {
		return xraycfg.BlockState{}, false, err
	}
	if !d.ok {
		return xraycfg.BlockState{}, false, nil
	}
	st := stateFromDoc(d)
	// Only an applied state may steer config edits: after a failed apply the
	// switches are still configured but nothing is live, and merging them here
	// would turn edit into a silent apply.
	if !boolValue(d.doc["applied"]) {
		return xraycfg.BlockState{}, false, nil
	}
	if !st.Block.Any() && len(st.OwnedRules) == 0 {
		return xraycfg.BlockState{}, false, nil
	}
	return st, true, nil
}

// BlockStatus reports the configured state, whether the live config still
// carries the owned rules (drift) and how old the GeoData files are.
func BlockStatus(root string) (BlockReport, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return BlockReport{}, err
	}
	rep := BlockReport{}
	d, err := loadBlockDoc(paths)
	if err != nil {
		return rep, err
	}
	rep.Configured = d.ok
	st := stateFromDoc(d)
	domains := customList(d.doc["custom_domains"])
	ips := customList(d.doc["custom_ips"])
	rep.Ads, rep.PrivateIP, rep.BitTorrent = st.Block.Ads, st.Block.PrivateIP, st.Block.BitTorrent
	rep.Countries = st.Block.Countries
	if rep.Countries == nil {
		rep.Countries = []string{}
	}
	rep.CustomDomains, rep.CustomIPs = domains, ips
	rep.OwnedRuleCount = len(st.OwnedRules)
	rep.Geosite = geoStatus(paths, "geosite.dat")
	rep.Geoip = geoStatus(paths, "geoip.dat")
	configPath, err := store.ResolveRuntimePath(paths, "")
	if err != nil {
		return rep, err
	}
	rep.ConfigPath = configPath
	raw, _, readErr := store.ReadRegular(configPath, "runtime config")
	if readErr != nil {
		rep.Warnings = append(rep.Warnings, "runtime config is unreadable: "+readErr.Error())
		return rep, nil
	}
	if present, err := xraycfg.OwnedRulesPresent(raw, st.OwnedRules); err == nil {
		rep.Applied = present
		rep.Drift = rep.Configured && len(st.OwnedRules) > 0 && !present
	}
	rep.DomainStrategy, rep.SniffingEnabled = sniffingState(raw)
	for _, geo := range []struct {
		name string
		rep  BlockGeoReport
	}{{"geosite.dat", rep.Geosite}, {"geoip.dat", rep.Geoip}} {
		if geo.rep.Missing {
			rep.Warnings = append(rep.Warnings, geo.name+" is missing; enable blocking again or run 'idleleo schedule install'")
		} else if geo.rep.Stale {
			rep.Warnings = append(rep.Warnings, geo.name+" is older than 30 days; wait for the geodata-refresh job or run it manually")
		}
	}
	if rep.Drift {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("drift: %d owned rules are configured but the live routing rules no longer match; re-run 'idleleo xray block apply'", rep.OwnedRuleCount))
	}
	return rep, nil
}

// sniffingState reports the live routing strategy and whether any inbound
// sniffs. It is used both by `block status` and by the apply report, so the two
// can never disagree about what was written.
func sniffingState(raw []byte) (string, bool) {
	var probe struct {
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
		} `json:"routing"`
		Inbounds []struct {
			Sniffing struct {
				Enabled bool `json:"enabled"`
			} `json:"sniffing"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return "", false
	}
	sniffing := false
	for _, in := range probe.Inbounds {
		if in.Sniffing.Enabled {
			sniffing = true
		}
	}
	return probe.Routing.DomainStrategy, sniffing
}

func geoStatus(paths host.Paths, name string) BlockGeoReport {
	p := filepath.Join(paths.GeodataDir(), name)
	rep := BlockGeoReport{Path: p}
	info, err := os.Stat(p)
	if err != nil {
		rep.Missing = true
		return rep
	}
	rep.Size = info.Size()
	rep.ModTime = info.ModTime().UTC().Format(time.RFC3339)
	rep.Stale = info.ModTime().Before(time.Now().AddDate(0, 0, -blockGeoMaxAgeDays))
	return rep
}

// UpdateBlockSwitches flips the three built-in switches. Nil leaves a switch
// untouched. Only the state file changes; call ApplyBlock to take effect.
func UpdateBlockSwitches(root string, ads, privateIP, bittorrent *bool, allowContainer bool) (BlockReport, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return BlockReport{}, err
	}
	if err := requireWriteAccess(paths, allowContainer); err != nil {
		return BlockReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return BlockReport{}, err
	}
	defer lock.Release()
	d, err := loadBlockDoc(paths)
	if err != nil {
		return BlockReport{}, err
	}
	if ads != nil {
		d.doc["ads"] = *ads
	}
	if privateIP != nil {
		d.doc["private_ip"] = *privateIP
	}
	if bittorrent != nil {
		d.doc["bittorrent"] = *bittorrent
	}
	if err := d.save(paths); err != nil {
		return BlockReport{}, err
	}
	return BlockStatus(root)
}

// UpdateBlockCountries adds/removes ISO codes. Codes are validated with the
// same builder that renders the rules, so an invalid code never reaches disk.
func UpdateBlockCountries(root string, add, remove []string, allowContainer bool) (BlockReport, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return BlockReport{}, err
	}
	if err := requireWriteAccess(paths, allowContainer); err != nil {
		return BlockReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return BlockReport{}, err
	}
	defer lock.Release()
	d, err := loadBlockDoc(paths)
	if err != nil {
		return BlockReport{}, err
	}
	current := stringList(d.doc["country_block"])
	if _, err := xraycfg.BuildBlockRules(xraycfg.RoutingBlock{Countries: add}); err != nil {
		return BlockReport{}, err
	}
	drop := map[string]bool{}
	for _, cc := range remove {
		drop[strings.ToLower(strings.TrimSpace(cc))] = true
	}
	keep := make([]any, 0, len(current)+len(add))
	seen := map[string]bool{}
	for _, cc := range current {
		cc = strings.ToLower(cc)
		if drop[cc] {
			continue
		}
		if !seen[cc] {
			seen[cc] = true
			keep = append(keep, cc)
		}
	}
	for _, cc := range add {
		cc = strings.ToLower(strings.TrimSpace(cc))
		if cc == "" || seen[cc] {
			continue
		}
		seen[cc] = true
		keep = append(keep, cc)
	}
	if len(keep) == 0 {
		delete(d.doc, "country_block")
	} else {
		d.doc["country_block"] = keep
	}
	if err := d.save(paths); err != nil {
		return BlockReport{}, err
	}
	return BlockStatus(root)
}

// UpdateBlockCustom mutates one custom list only. kind is "domain" or "ip".
// add/remove are single-item operations; duplicates are idempotent.
func UpdateBlockCustom(root, kind string, add, remove []string, enabled *bool, allowContainer bool) (BlockReport, error) {
	key, err := customKey(kind)
	if err != nil {
		return BlockReport{}, err
	}
	paths, err := host.NewPaths(root)
	if err != nil {
		return BlockReport{}, err
	}
	if err := requireWriteAccess(paths, allowContainer); err != nil {
		return BlockReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return BlockReport{}, err
	}
	defer lock.Release()
	d, err := loadBlockDoc(paths)
	if err != nil {
		return BlockReport{}, err
	}
	switch kind {
	case "domain":
		_, err = xraycfg.BuildBlockRules(xraycfg.RoutingBlock{CustomDomains: add})
	case "ip":
		_, err = xraycfg.BuildBlockRules(xraycfg.RoutingBlock{CustomIPs: add})
	}
	if err != nil {
		return BlockReport{}, err
	}
	entry := objectValue(d.doc[key])
	current := stringList(entry["items"])
	drop := map[string]bool{}
	for _, v := range remove {
		drop[strings.TrimSpace(v)] = true
	}
	items := make([]any, 0, len(current)+len(add))
	seen := map[string]bool{}
	for _, v := range current {
		if drop[v] || seen[v] {
			continue
		}
		seen[v] = true
		items = append(items, v)
	}
	for _, v := range add {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		items = append(items, v)
	}
	entry["items"] = items
	if enabled != nil {
		entry["enabled"] = *enabled
	} else if _, ok := entry["enabled"]; !ok {
		entry["enabled"] = false
	}
	d.doc[key] = entry
	if err := d.save(paths); err != nil {
		return BlockReport{}, err
	}
	return BlockStatus(root)
}

func customKey(kind string) (string, error) {
	switch kind {
	case "domain", "domains":
		return "custom_domains", nil
	case "ip", "ips":
		return "custom_ips", nil
	}
	return "", fmt.Errorf("--kind must be domain or ip (got %q)", kind)
}

// ApplyBlock writes the block rules, validates them, and restarts Xray. Any
// failure restores both the config and the state file.
func ApplyBlock(ctx context.Context, spec BlockApplySpec) (BlockReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return BlockReport{}, err
	}
	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return BlockReport{}, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return BlockReport{}, err
		}
		defer lock.Release()
	}
	configPath, err := store.ResolveRuntimePath(paths, spec.ConfigPath)
	if err != nil {
		return BlockReport{}, err
	}
	if err := requireNativeInstall(paths); err != nil {
		return BlockReport{}, err
	}
	raw, _, err := store.ReadRegular(configPath, "runtime config")
	if err != nil {
		return BlockReport{}, err
	}
	d, err := loadBlockDoc(paths)
	if err != nil {
		return BlockReport{}, err
	}
	st := stateFromDoc(d)
	if !st.Block.Any() {
		return BlockReport{}, fmt.Errorf("no traffic-block type is enabled; enable ads, private-ip, bittorrent, a country or a custom list first")
	}
	out, applied, err := xraycfg.ApplyRoutingBlock(raw, st)
	if err != nil {
		return BlockReport{}, err
	}
	rep := BlockReport{
		Configured: true, Ads: st.Block.Ads, PrivateIP: st.Block.PrivateIP,
		BitTorrent: st.Block.BitTorrent, Countries: st.Block.Countries,
		CustomDomains: customList(d.doc["custom_domains"]), CustomIPs: customList(d.doc["custom_ips"]),
		OwnedRuleCount: len(applied.OwnedRules), ConfigPath: configPath,
		OldSHA256: store.HashBytes(raw), NewSHA256: store.HashBytes(out),
		Geosite: geoStatus(paths, "geosite.dat"), Geoip: geoStatus(paths, "geoip.dat"),
	}
	rep.DomainStrategy, rep.SniffingEnabled = sniffingState(out)
	if spec.DryRun {
		rep.ControlProbe = "skipped: --dry-run"
		return rep, nil
	}
	needGeosite, needGeoip := st.Block.NeedsGeo()
	if err := ensureGeo(ctx, paths, spec.GeodataURL, needGeosite, needGeoip); err != nil {
		return rep, err
	}
	created, err := ensureAssetEnv(ctx, paths)
	if err != nil {
		return rep, err
	}
	if created {
		rep.AssetEnv = "created " + blockAssetDropIn
	} else {
		rep.AssetEnv = "reused existing XRAY_LOCATION_ASSET"
	}
	bin, err := paths.Join(binaryRel, false)
	if err != nil {
		return rep, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(configPath), ".block-candidate-*.json")
	if err != nil {
		return rep, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return rep, err
	}
	if err := tmp.Close(); err != nil {
		return rep, err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return rep, err
	}
	if err := runXrayTest(ctx, bin, tmpName, geodataEnv(paths.Root)); err != nil {
		return rep, fmt.Errorf("%w; traffic blocking was not applied", err)
	}
	configState, err := captureFile(configPath)
	if err != nil {
		return rep, err
	}
	backupDir, err := writeBlockBackup(paths, configPath, raw, d.raw)
	if err != nil {
		return rep, err
	}
	rep.BackupDir = backupDir

	stateBefore := append([]byte(nil), d.raw...)
	d.setApplied(applied, true)
	if err := d.save(paths); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(configPath, out, configState.mode); err != nil {
		_ = configState.restore()
		_ = restoreBlockDoc(paths, stateBefore)
		return rep, err
	}
	if configState.uid >= 0 && configState.gid >= 0 {
		if err := chownFile(configPath, configState.uid, configState.gid); err != nil {
			_ = configState.restore()
			_ = restoreBlockDoc(paths, stateBefore)
			return rep, err
		}
	}
	rep.Applied = true
	if spec.NoRestart {
		rep.ControlProbe = "skipped: --no-restart"
		return rep, nil
	}
	if err := service(ctx, "restart", "xray"); err != nil {
		return failBlockApply(ctx, spec, rep, configState, paths, stateBefore, "xray-restart", err)
	}
	if state := waitActive(ctx); state != "active" {
		return failBlockApply(ctx, spec, rep, configState, paths, stateBefore, "xray-active",
			fmt.Errorf("xray did not become active after applying blocking (state %s)", state))
	}
	rep.ServiceRestart = true
	if spec.NoProbe {
		rep.ControlProbe = "skipped: --no-probe"
		return rep, nil
	}
	probe, err := blockControlProbe(ctx, paths, out)
	if err != nil {
		return failBlockApply(ctx, spec, rep, configState, paths, stateBefore, "control-probe", err)
	}
	rep.ControlProbe = probe
	return rep, nil
}

// OffBlock removes only the rules this manager wrote and restores the
// domainStrategy/sniffing values captured before the first apply.
func OffBlock(ctx context.Context, spec BlockApplySpec) (BlockReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return BlockReport{}, err
	}
	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return BlockReport{}, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return BlockReport{}, err
		}
		defer lock.Release()
	}
	configPath, err := store.ResolveRuntimePath(paths, spec.ConfigPath)
	if err != nil {
		return BlockReport{}, err
	}
	if err := requireNativeInstall(paths); err != nil {
		return BlockReport{}, err
	}
	raw, _, err := store.ReadRegular(configPath, "runtime config")
	if err != nil {
		return BlockReport{}, err
	}
	d, err := loadBlockDoc(paths)
	if err != nil {
		return BlockReport{}, err
	}
	st := stateFromDoc(d)
	if len(st.OwnedRules) == 0 {
		return BlockReport{}, fmt.Errorf("no traffic-block rules are installed")
	}
	out, restored, err := xraycfg.RemoveRoutingBlock(raw, st)
	if err != nil {
		return BlockReport{}, err
	}
	rep := BlockReport{
		Configured: d.ok, ConfigPath: configPath,
		OldSHA256: store.HashBytes(raw), NewSHA256: store.HashBytes(out),
		Geosite: geoStatus(paths, "geosite.dat"), Geoip: geoStatus(paths, "geoip.dat"),
	}
	rep.DomainStrategy, rep.SniffingEnabled = sniffingState(out)
	if spec.DryRun {
		rep.ControlProbe = "skipped: --dry-run"
		return rep, nil
	}
	configState, err := captureFile(configPath)
	if err != nil {
		return rep, err
	}
	backupDir, err := writeBlockBackup(paths, configPath, raw, d.raw)
	if err != nil {
		return rep, err
	}
	rep.BackupDir = backupDir
	stateBefore := append([]byte(nil), d.raw...)
	d.setApplied(restored, false)
	if err := d.save(paths); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(configPath, out, configState.mode); err != nil {
		_ = configState.restore()
		_ = restoreBlockDoc(paths, stateBefore)
		return rep, err
	}
	if configState.uid >= 0 && configState.gid >= 0 {
		if err := chownFile(configPath, configState.uid, configState.gid); err != nil {
			_ = configState.restore()
			_ = restoreBlockDoc(paths, stateBefore)
			return rep, err
		}
	}
	if spec.NoRestart {
		rep.ControlProbe = "skipped: --no-restart"
		return rep, nil
	}
	if err := service(ctx, "restart", "xray"); err != nil {
		return failBlockApply(ctx, spec, rep, configState, paths, stateBefore, "xray-restart", err)
	}
	if state := waitActive(ctx); state != "active" {
		return failBlockApply(ctx, spec, rep, configState, paths, stateBefore, "xray-active",
			fmt.Errorf("xray did not become active after removing blocking (state %s)", state))
	}
	rep.ServiceRestart = true
	rep.ControlProbe = "not probed: block off only removes rules"
	return rep, nil
}

// failBlockApply rolls the config and the state file back and brings the old
// config back into service, so a failed probe never leaves blocking half on.
func failBlockApply(ctx context.Context, spec BlockApplySpec, rep BlockReport, configState fileState,
	paths host.Paths, stateBefore []byte, point string, cause error) (BlockReport, error) {
	rep.FailurePoint = point
	restoreErr := configState.restore()
	if err := restoreBlockDoc(paths, stateBefore); err != nil {
		restoreErr = joinRollbackErr(restoreErr, "traffic_blocker.json restore", err)
	}
	if !spec.NoRestart {
		if err := service(ctx, "restart", "xray"); err != nil {
			restoreErr = joinRollbackErr(restoreErr, "xray restart", err)
		}
	}
	if restoreErr != nil {
		return rep, fmt.Errorf("%w; rollback failed: %v", cause, restoreErr)
	}
	return rep, fmt.Errorf("%w; previous configuration restored", cause)
}

func restoreBlockDoc(paths host.Paths, raw []byte) error {
	p, err := paths.Join(blockStateRel, true)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeFileAtomic(p, raw, 0o644)
}

// ensureGeo makes sure the files the enabled switches need are present. A
// missing file triggers one verified download; there is no silent downgrade.
func ensureGeo(ctx context.Context, paths host.Paths, url string, geosite, geoip bool) error {
	dir := paths.GeodataDir()
	missing := []string{}
	for _, need := range []struct {
		name string
		want bool
	}{{"geosite.dat", geosite}, {"geoip.dat", geoip}} {
		if !need.want {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, need.name)); err != nil || info.Size() == 0 {
			missing = append(missing, need.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	payloads, err := geodata.Fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("GeoData files %s are missing and the download failed: %w; traffic blocking was not applied",
			strings.Join(missing, ", "), err)
	}
	for _, name := range missing {
		if err := writeFileAtomic(filepath.Join(dir, name), payloads[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ensureAssetEnv makes sure the Xray unit sees XRAY_LOCATION_ASSET. It reuses
// an existing value that points at a usable directory and refuses to fight a
// different one that has no assets.
func ensureAssetEnv(ctx context.Context, paths host.Paths) (bool, error) {
	want := paths.GeodataDir()
	unitPath := filepath.Join(paths.Root, "etc/systemd/system/xray.service")
	dropInDir := filepath.Join(paths.Root, "etc/systemd/system/xray.service.d")
	files := []string{unitPath}
	if entries, err := os.ReadDir(dropInDir); err == nil {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".conf") {
				files = append(files, filepath.Join(dropInDir, entry.Name()))
			}
		}
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			value, ok := strings.CutPrefix(line, "Environment=XRAY_LOCATION_ASSET=")
			if !ok {
				continue
			}
			if strings.Trim(value, `"`) == want {
				return false, nil
			}
			if hasGeoAssets(value) {
				return false, nil
			}
			return false, fmt.Errorf("%s sets XRAY_LOCATION_ASSET=%s which has no GeoData files; point it at %s or remove the line",
				file, value, want)
		}
	}
	target := filepath.Join(paths.Root, blockAssetDropIn)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return false, err
	}
	content := fmt.Sprintf("[Service]\nEnvironment=XRAY_LOCATION_ASSET=%s\n", want)
	if err := writeFileAtomic(target, []byte(content), 0o644); err != nil {
		return false, err
	}
	if !paths.IsSandbox() {
		if err := service(ctx, "daemon-reload"); err != nil {
			return true, err
		}
	}
	return true, nil
}

func hasGeoAssets(dir string) bool {
	for _, name := range geodata.Assets {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Size() == 0 {
			return false
		}
	}
	return true
}

// blockControlProbe proves the service still carries traffic after the rules
// changed. Reality installs reuse the real-client handshake; other modes only
// prove the listener is up and defer the HTTP control to the E2E driver.
func blockControlProbe(ctx context.Context, paths host.Paths, raw []byte) (string, error) {
	base, _, err := editBase(paths, raw)
	if err != nil {
		return "", err
	}
	if base.Mode == xraycfg.ModeReality || base.Mode == xraycfg.ModeRealityNginx || base.Mode == xraycfg.ModeRealityBalance {
		info, err := xraycfg.ShareConfig(raw, xraycfg.ShareOptions{
			InboundIndex: 0, Host: base.Domain, PublicPort: base.PublicPort,
		})
		if err != nil {
			return "", err
		}
		addr := probeAddress(base.PublicPort)
		if base.Mode == xraycfg.ModeReality {
			addr = probeAddress(info.Port)
		}
		if err := verifyRealityHandshake(ctx, paths.Root, info.ShareURI, addr); err != nil {
			return "failed: " + err.Error(), err
		}
		return "ok: vless+reality handshake+request through " + addr, nil
	}
	conn, err := net.DialTimeout("tcp", probeAddress(base.PublicPort), 3*time.Second)
	if err != nil {
		return "failed: " + err.Error(), fmt.Errorf("control probe: xray is not accepting connections on the public port: %w", err)
	}
	_ = conn.Close()
	return fmt.Sprintf("ok: tcp control on %s (HTTP control is covered by the E2E driver)", probeAddress(base.PublicPort)), nil
}

// writeBlockBackup snapshots the config and the state file before a write.
func writeBlockBackup(paths host.Paths, configPath string, config, state []byte) (string, error) {
	dir := filepath.Join(paths.Root, editBackupRel, blockBackupPrefix+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(dir, "config.json"), config, 0o600); err != nil {
		return "", err
	}
	if len(state) > 0 {
		if err := writeFileAtomic(filepath.Join(dir, "traffic_blocker.json"), state, 0o600); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "meta"), []byte("config="+configPath+"\n"), 0o600); err != nil {
		return "", err
	}
	trimBlockBackups(filepath.Join(paths.Root, editBackupRel))
	return dir, nil
}

// trimBlockBackups keeps the backup directory bounded like config edits do.
func trimBlockBackups(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), blockBackupPrefix) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for len(names) > editBackupMax {
		_ = os.RemoveAll(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}
