// Package legacybridge migrates a Bash-managed installation to the Go
// manager. It is deliberately separate from internal/deploy: the bridge only
// switches the entry point after an audit, a snapshot, a read-only
// pre-validation and a committed journal, and it never rewrites the runtime
// Xray config, certificates or user list.
package legacybridge

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	legacyConfigRel  = "etc/idleleo/conf/install_config.json"
	runtimeConfigRel = "etc/idleleo/conf/xray/config.json"
	legacyScriptRel  = "etc/idleleo/install.sh"
	entryRel         = "usr/bin/idleleo"
	certDirRel       = "etc/idleleo/cert"
	nginxConfRel     = "etc/nginx/nginx.conf"
	managedNginxRel  = "etc/idleleo/conf/nginx"
	relayConfRel     = "etc/idleleo/conf/nginx/relay-stream.conf"
	unitXrayRel      = "etc/systemd/system/xray.service"
	unitNginxRel     = "etc/systemd/system/nginx.service"
	geoDirRel        = "etc/idleleo/geo"

	rillConfigRel      = "etc/rill-xray-agent/config.json"
	rillObservationRel = "var/lib/rill-xray-agent-xray/status/xray-observation.json"
	rillBinaryRel      = "opt/rill-xray-agent/bin/rill-xray-agent"
	rillFreshSeconds   = 600

	VerdictConvertible = "convertible"
	VerdictNeedsFix    = "needs-fix"
	VerdictBlocked     = "blocked"

	severityBlock = "block"
	severityFix   = "fix"
	severityWarn  = "warn"
)

// Finding is one audit conclusion. Code is stable for tests.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// UnitInfo is a read-only systemd unit projection.
type UnitInfo struct {
	Path      string `json:"path"`
	Present   bool   `json:"present"`
	SHA256    string `json:"sha256,omitempty"`
	User      string `json:"user,omitempty"`
	Group     string `json:"group,omitempty"`
	ExecStart string `json:"execStart,omitempty"`
	Active    string `json:"active,omitempty"`
	Enabled   string `json:"enabled,omitempty"`
}

// FileFingerprint records a path and its hash. Private certificate contents
// are never copied, only fingerprinted.
type FileFingerprint struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

// EntryInfo describes the current /usr/bin/idleleo entry.
type EntryInfo struct {
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	IsSymlink  bool   `json:"isSymlink"`
	LinkTarget string `json:"linkTarget,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	IsGoBridge bool   `json:"isGoBridge"`
}

// RillInfo projects the Rill/Xray agent handover state. Contents are never
// copied: only hashes, mode and observation age are recorded.
type RillInfo struct {
	Installed             bool   `json:"installed"`
	Binary                string `json:"binary,omitempty"`
	ConfigPath            string `json:"configPath,omitempty"`
	ConfigSHA256          string `json:"configSha256,omitempty"`
	ObservationPath       string `json:"observationPath,omitempty"`
	ObservationSHA256     string `json:"observationSha256,omitempty"`
	ObservationAgeSeconds int64  `json:"observationAgeSeconds"`
	Status                string `json:"status"`
	Mode                  string `json:"mode,omitempty"`
	Enabled               bool   `json:"enabled"`
	Warning               string `json:"warning,omitempty"`
}

// CustomItem is project-external content that cannot be merged automatically.
// Prepare requires --acknowledge-custom before proceeding.
type CustomItem struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

// PermissionFix records a mode (and optionally group) that activation will
// tighten and that rollback must restore.
type PermissionFix struct {
	Path    string `json:"path"`
	OldMode string `json:"oldMode"`
	NewMode string `json:"newMode"`
	OldGID  int    `json:"oldGid"`
	NewGID  int    `json:"newGid"`
	Reason  string `json:"reason"`
}

// Audit is the read-only migration discovery result. It is also the plan.
type Audit struct {
	SchemaVersion    int                 `json:"schemaVersion"`
	Root             string              `json:"root"`
	LegacyVersion    string              `json:"legacyVersion,omitempty"`
	XrayVersion      string              `json:"xrayVersion,omitempty"`
	Role             string              `json:"role"`
	TLS              string              `json:"tls"`
	Transport        string              `json:"transport"`
	NginxRequired    bool                `json:"nginxRequired"`
	Port             int                 `json:"port,omitempty"`
	UserCount        int                 `json:"userCount"`
	RuntimePath      string              `json:"runtimePath,omitempty"`
	RuntimeSHA256    string              `json:"runtimeSha256,omitempty"`
	RuntimeBytes     int                 `json:"runtimeBytes,omitempty"`
	CustomDNS        bool                `json:"customDns"`
	CustomRouting    bool                `json:"customRouting"`
	CustomOutbounds  bool                `json:"customOutbounds"`
	CustomItems      []CustomItem        `json:"customItems"`
	CertFiles        []FileFingerprint   `json:"certFiles"`
	NginxFiles       []FileFingerprint   `json:"nginxFiles"`
	Units            map[string]UnitInfo `json:"units"`
	Entry            EntryInfo           `json:"entry"`
	LegacyScript     FileFingerprint     `json:"legacyScript"`
	GeoLegacyCron    bool                `json:"geoLegacyCron"`
	ProjectCronLines int                 `json:"projectCronLines"`
	RelayConf        FileFingerprint     `json:"relayConf"`
	Rill             RillInfo            `json:"rill"`
	PermissionFixes  []PermissionFix     `json:"permissionFixes"`
	Findings         []Finding           `json:"findings"`
	Verdict          string              `json:"verdict"`
}

type legacyConfig struct {
	Role                 string `json:"role"`
	ShellMode            string `json:"shell_mode"`
	TransportMode        string `json:"transport_mode"`
	Host                 string `json:"host"`
	Port                 int    `json:"port"`
	TLS                  string `json:"tls"`
	Net                  string `json:"net"`
	RealityAddNginx      string `json:"reality_add_nginx"`
	RealityNginxSNIGuard string `json:"reality_nginx_sni_guard"`
	RelayBackendHost     string `json:"relay_backend_host"`
	RelayBackendPort     int    `json:"relay_backend_port"`
	RelayListenPort      int    `json:"relay_listen_port"`
	ShellVersion         string `json:"shell_version"`
	XrayVersion          string `json:"xray_version"`
}

// AuditMigration scans the installation without writing or contacting the
// network. It refuses to run when the current entry already points at the Go
// bridge.
func AuditMigration(root string) (Audit, error) {
	a := Audit{
		SchemaVersion: 1, Root: root,
		Units:           map[string]UnitInfo{},
		Findings:        []Finding{},
		CertFiles:       []FileFingerprint{},
		NginxFiles:      []FileFingerprint{},
		CustomItems:     []CustomItem{},
		PermissionFixes: []PermissionFix{},
		Rill:            RillInfo{Status: "absent"},
	}

	entryPath, _ := resolve(root, entryRel)
	a.Entry.Path = entryPath
	if fi, err := os.Lstat(entryPath); err == nil {
		a.Entry.Exists = true
		if fi.Mode()&os.ModeSymlink != 0 {
			a.Entry.IsSymlink = true
			if target, err := os.Readlink(entryPath); err == nil {
				a.Entry.LinkTarget = target
				a.Entry.Exists = true
			}
		}
		if fi.Mode().IsRegular() {
			if sha, err := hashFile(entryPath); err == nil {
				a.Entry.SHA256 = sha
			}
		}
	}
	if a.Entry.LinkTarget != "" {
		abs := a.Entry.LinkTarget
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, filepath.Dir(entryRel), abs)
		}
		if sha, err := hashFile(abs); err == nil {
			a.Entry.SHA256 = sha
		}
	}
	installedRel := installedRel
	if a.Entry.LinkTarget != "" && strings.Contains(a.Entry.LinkTarget, installedRel) {
		a.Entry.IsGoBridge = true
	}
	if a.Entry.IsSymlink && a.Entry.LinkTarget != "" {
		target := a.Entry.LinkTarget
		if !filepath.IsAbs(target) {
			target = filepath.Join(root, filepath.Dir(entryRel), target)
		}
		target = filepath.Clean(target)
		if root != "/" {
			rootPrefix := filepath.Clean(root) + string(os.PathSeparator)
			if !strings.HasPrefix(target, rootPrefix) && target != filepath.Clean(root) {
				a.block("entry-symlink-escape", "the entry symlink points outside the sandbox root")
			}
		} else {
			allowed := []string{"/etc/idleleo/", "/opt/idleleo/"}
			ok := false
			for _, prefix := range allowed {
				if strings.HasPrefix(target, prefix) {
					ok = true
					break
				}
			}
			if !ok {
				a.block("entry-symlink-escape", "the entry symlink points outside the managed product paths")
			}
		}
	}

	scriptPath, _ := resolve(root, legacyScriptRel)
	a.LegacyScript.Path = scriptPath
	if sha, err := hashFile(scriptPath); err == nil {
		a.LegacyScript.SHA256 = sha
	} else if !os.IsNotExist(err) {
		return a, fmt.Errorf("legacy install.sh unreadable: %w", err)
	}

	cfgPath, _ := resolve(root, legacyConfigRel)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			a.block("legacy-metadata-missing", "no install_config.json; cannot classify the installation")
			a.Verdict = VerdictBlocked
			return a, nil
		}
		return a, err
	}
	var lc legacyConfig
	if err := json.Unmarshal(raw, &lc); err != nil {
		a.block("legacy-metadata-corrupt", "install_config.json is not valid JSON")
		a.Verdict = VerdictBlocked
		return a, nil
	}
	a.LegacyVersion, a.XrayVersion = lc.ShellVersion, lc.XrayVersion
	a.Port = lc.Port
	a.NginxRequired = lc.Role == "relay" || lc.ShellMode == "Relay" || lc.TLS == "TLS" ||
		(lc.TLS == "Reality" && lc.RealityAddNginx == "on")

	if lc.Role == "relay" || lc.ShellMode == "Relay" {
		a.Role, a.TLS, a.Transport = "relay", "None", "stream"
	} else {
		a.Role = "node"
		a.TLS = lc.TLS
		a.Transport = transportOf(lc)
	}

	switch {
	case lc.TLS == "XTLS":
		a.block("legacy-xtls-removed", "the XTLS-only profile was removed; automatic migration is refused")
	case lc.TLS != "Reality" && lc.TLS != "TLS" && lc.TLS != "None":
		a.block("legacy-tls-unknown", fmt.Sprintf("unsupported legacy tls mode %q", lc.TLS))
	}
	if a.Entry.IsGoBridge {
		a.block("already-migrated", "the entry already points at the Go manager")
	}
	if a.Entry.Exists && !a.Entry.IsSymlink && a.Entry.SHA256 == "" {
		a.fix("entry-unreadable", "the existing entry is not a readable regular file")
	}
	if !a.Entry.Exists {
		a.fix("entry-missing", "no /usr/bin/idleleo entry; activation creates one")
	}
	if a.LegacyScript.SHA256 == "" {
		a.block("legacy-script-missing", "no /etc/idleleo/install.sh to keep as a recovery backup")
	}

	if a.Role == "node" {
		if err := a.scanRuntime(root, lc); err != nil {
			a.block("runtime-config-invalid", err.Error())
		}
	} else {
		relayPath, _ := resolve(root, relayConfRel)
		a.RelayConf.Path = relayPath
		if sha, err := hashFile(relayPath); err == nil {
			a.RelayConf.SHA256 = sha
		} else {
			a.block("relay-config-missing", "relay-stream.conf is missing")
		}
	}

	a.scanCerts(root)
	a.scanNginx(root)
	a.scanUnits(root)
	a.scanRill(root)
	a.scanPermissions(root)

	if _, err := os.Stat(mustResolve(root, geoDirRel)); err == nil {
		a.GeoLegacyCron = true
	}
	a.scanCron(root)
	a.computeVerdict()
	return a, nil
}

func (a *Audit) scanRuntime(root string, lc legacyConfig) error {
	path, _ := resolve(root, runtimeConfigRel)
	a.RuntimePath = path
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		a.block("runtime-config-symlink", "the runtime config is a symlink; refusing to follow it")
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("runtime config unreadable: %w", err)
	}
	a.RuntimeBytes = len(b)
	a.RuntimeSHA256 = hashBytes(b)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("runtime config is not valid JSON")
	}
	if _, ok := doc["dns"]; ok {
		a.CustomDNS = true
	}
	if _, ok := doc["routing"]; ok {
		a.CustomRouting = true
	}
	if _, ok := doc["outbounds"]; ok {
		a.CustomOutbounds = true
	}
	known := map[string]bool{
		"log": true, "dns": true, "routing": true, "policy": true, "inbounds": true,
		"outbounds": true, "transport": true, "stats": true, "api": true, "reverse": true,
		"fakedns": true, "browserForwarder": true, "observatory": true, "geodata": true,
		"burstObservatory": true,
	}
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if known[key] {
			continue
		}
		a.CustomItems = append(a.CustomItems, CustomItem{
			Kind: "xray-config-key", Path: runtimeConfigRel,
			Detail: fmt.Sprintf("unknown top-level key %q is preserved but needs a manual merge review", key),
		})
	}
	inbounds, _ := doc["inbounds"].([]any)
	realityKey := false
	for _, rawIn := range inbounds {
		in, _ := rawIn.(map[string]any)
		settings, _ := in["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		a.UserCount += len(clients)
		stream, _ := in["streamSettings"].(map[string]any)
		if stream == nil {
			continue
		}
		if rs, ok := stream["realitySettings"].(map[string]any); ok {
			if k, _ := rs["privateKey"].(string); k != "" {
				realityKey = true
			}
		}
	}
	if a.UserCount == 0 {
		a.block("runtime-users-empty", "the runtime config has no clients")
	}
	if a.TLS == "Reality" && !realityKey {
		a.block("reality-key-missing", "Reality is configured but the runtime config has no privateKey")
	}
	if a.TLS == "Reality" && lc.Port > 0 {
		ports := inboundPorts(doc)
		if len(ports) > 0 && !ports[lc.Port] {
			a.block("runtime-port-conflict", fmt.Sprintf("install_config port %d is not present in the runtime inbounds", lc.Port))
		}
	}
	return nil
}

func inboundPorts(doc map[string]any) map[int]bool {
	out := map[int]bool{}
	inbounds, _ := doc["inbounds"].([]any)
	for _, rawIn := range inbounds {
		in, _ := rawIn.(map[string]any)
		switch p := in["port"].(type) {
		case float64:
			out[int(p)] = true
		case string:
			var n int
			if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
				out[n] = true
			}
		}
	}
	return out
}

func transportOf(lc legacyConfig) string {
	switch {
	case lc.TLS == "Reality":
		return "raw"
	case lc.TransportMode == "wsgRPCxhttp":
		return "multi"
	case lc.TransportMode != "":
		return strings.ToLower(lc.TransportMode)
	default:
		return "none"
	}
}

func (a *Audit) scanCerts(root string) {
	dir := mustResolve(root, certDirRel)
	a.CertFiles = walkFingerprints(dir)
	if a.TLS == "TLS" && len(a.CertFiles) == 0 {
		a.fix("certificates-missing", "TLS is configured but no certificate files were found")
	}
}

func (a *Audit) scanNginx(root string) {
	dir := mustResolve(root, managedNginxRel)
	a.NginxFiles = walkFingerprints(dir)
	for _, fp := range a.NginxFiles {
		if fp.Path == "relay-stream.conf" {
			continue
		}
		a.CustomItems = append(a.CustomItems, CustomItem{
			Kind: "nginx-fragment", Path: filepath.Join(managedNginxRel, fp.Path),
			Detail: "project-external nginx fragment; confirm the merge manually before activation",
		})
	}
}

// scanRill records the Rill handover state without copying any content. Stale
// or missing observations are warnings, not blocks: the bridge never writes
// Rill state, so migration must not fail because the agent is quiet.
func (a *Audit) scanRill(root string) {
	a.Rill = RillInfo{Status: "absent", Enabled: false}
	cfgPath := mustResolve(root, rillConfigRel)
	obsPath := mustResolve(root, rillObservationRel)
	binPath := mustResolve(root, rillBinaryRel)

	installed := false
	if _, err := os.Stat(binPath); err == nil {
		installed = true
		a.Rill.Binary = rillBinaryRel
	}
	if b, err := os.ReadFile(cfgPath); err == nil {
		installed = true
		a.Rill.ConfigPath = rillConfigRel
		a.Rill.ConfigSHA256 = hashBytes(b)
		a.Rill.Enabled = true
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err == nil {
			a.Rill.Mode = rillMode(doc)
			if v, ok := doc["enabled"].(bool); ok {
				a.Rill.Enabled = v
			}
		} else {
			a.Rill.Warning = "config.json is not valid JSON"
			a.warn("rill-config-unreadable", "Rill config.json is present but not valid JSON")
		}
	}
	if !installed {
		return
	}
	a.Rill.Installed = true
	b, err := os.ReadFile(obsPath)
	if err != nil {
		a.Rill.Status = "installed-unobserved"
		a.Rill.Warning = "no xray-observation.json yet"
		a.warn("rill-observation-missing", "Rill is installed but has no xray observation")
		return
	}
	a.Rill.ObservationPath = rillObservationRel
	a.Rill.ObservationSHA256 = hashBytes(b)
	observed := observationTime(b)
	if observed.IsZero() {
		if fi, err := os.Stat(obsPath); err == nil {
			observed = fi.ModTime()
		}
	}
	age := int64(time.Since(observed).Seconds())
	if age < 0 {
		age = 0
	}
	a.Rill.ObservationAgeSeconds = age
	if age <= rillFreshSeconds {
		a.Rill.Status = "active"
	} else {
		a.Rill.Status = "stale"
		a.Rill.Warning = fmt.Sprintf("last observation is %d seconds old", age)
		a.warn("rill-observation-stale", fmt.Sprintf("Rill observation is %d seconds old (freshness limit %ds)", age, rillFreshSeconds))
	}
}

func rillMode(doc map[string]any) string {
	for _, key := range []string{"mode", "agent_mode", "integration_mode"} {
		if v, ok := doc[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func observationTime(b []byte) time.Time {
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return time.Time{}
	}
	for _, key := range []string{"updatedAt", "updated_at", "observedAt", "observed_at", "timestamp", "lastUpdated", "generatedAt"} {
		switch v := doc[key].(type) {
		case string:
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700"} {
				if t, err := time.Parse(layout, v); err == nil {
					return t
				}
			}
		case float64:
			return time.Unix(int64(v), 0)
		}
	}
	return time.Time{}
}

// scanPermissions tightens world-writable config/directories and group/other
// readable private keys. Activation applies the fixes and rollback restores the
// recorded old modes.
func (a *Audit) scanPermissions(root string) {
	// Only file modes are tightened. Directory modes are deliberately left
	// alone: the legacy installer may rely on a specific group/other traversal
	// bit for the xray/nginx users, and changing it can lock the service out.
	xrayGroup := a.Units["xray"].Group
	a.checkPermission(root, runtimeConfigRel, 0o002, 0o644, "", "runtime config is world-writable")
	keyDir := mustResolve(root, certDirRel)
	_ = filepath.Walk(keyDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || !fi.Mode().IsRegular() {
			return nil
		}
		base := strings.ToLower(filepath.Base(p))
		if !strings.Contains(base, "privkey") && !strings.HasSuffix(base, ".key") {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		a.checkPermission(root, filepath.ToSlash(rel), 0o077, 0o640, xrayGroup, "private key is group/other readable")
		return nil
	})
	sort.SliceStable(a.PermissionFixes, func(i, j int) bool { return a.PermissionFixes[i].Path < a.PermissionFixes[j].Path })
}

func (a *Audit) checkPermission(root, rel string, mask, want os.FileMode, wantGroup, reason string) {
	p := mustResolve(root, rel)
	fi, err := os.Lstat(p)
	if err != nil {
		return
	}
	perm := fi.Mode().Perm()
	if perm&mask == 0 {
		return
	}
	fix := PermissionFix{
		Path: rel, OldMode: fmt.Sprintf("%04o", perm), NewMode: fmt.Sprintf("%04o", want), Reason: reason,
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fix.OldGID = int(st.Gid)
		fix.NewGID = fix.OldGID
	}
	if wantGroup != "" {
		if gid, ok := groupID(wantGroup); ok {
			fix.NewGID = gid
		}
	}
	a.PermissionFixes = append(a.PermissionFixes, fix)
	a.fix("permissions-"+strings.ReplaceAll(rel, "/", "-"), fmt.Sprintf("%s: %04o -> %04o", reason, perm, want))
}

func groupID(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	var gid int
	if _, err := fmt.Sscanf(g.Gid, "%d", &gid); err != nil {
		return 0, false
	}
	return gid, true
}

func (a *Audit) scanUnits(root string) {
	for name, rel := range map[string]string{"xray": unitXrayRel, "nginx": unitNginxRel} {
		p := mustResolve(root, rel)
		u := UnitInfo{Path: p}
		b, err := os.ReadFile(p)
		if err == nil {
			u.Present = true
			u.SHA256 = hashBytes(b)
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(line, "User="):
					u.User = strings.TrimPrefix(line, "User=")
				case strings.HasPrefix(line, "Group="):
					u.Group = strings.TrimPrefix(line, "Group=")
				case strings.HasPrefix(line, "ExecStart="):
					u.ExecStart = strings.TrimPrefix(line, "ExecStart=")
				}
			}
		}
		a.Units[name] = u
	}
	if a.Role == "node" && !a.Units["xray"].Present {
		a.fix("xray-unit-missing", "xray.service is missing; service semantics cannot be preserved")
	}
	if a.NginxRequired && !a.Units["nginx"].Present {
		a.fix("nginx-unit-missing", "nginx.service is missing for a TLS/relay installation")
	}
}

// projectCronMarkers are the exact script names this project installs.
// A cron line is only considered ours when it references /etc/idleleo and one
// of these names; unrelated user jobs are never touched.
var projectCronMarkers = []string{"auto_update.sh", "ssl_update.sh", "geo_update.sh", "xray_stats.sh"}

func isProjectCronLine(line string) bool {
	if !strings.Contains(line, "/etc/idleleo") {
		return false
	}
	for _, marker := range projectCronMarkers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func (a *Audit) scanCron(root string) {
	path := mustResolve(root, crontabRel)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !isProjectCronLine(line) {
			continue
		}
		a.ProjectCronLines++
		if strings.Contains(line, "geo_update.sh") {
			a.GeoLegacyCron = true
		}
	}
}

func walkFingerprints(dir string) []FileFingerprint {
	out := []FileFingerprint{}
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || !fi.Mode().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		sha, _ := hashFile(path)
		out = append(out, FileFingerprint{Path: rel, SHA256: sha, Mode: fi.Mode().String()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (a *Audit) block(code, msg string) {
	a.Findings = append(a.Findings, Finding{Code: code, Severity: severityBlock, Message: msg})
}
func (a *Audit) fix(code, msg string) {
	a.Findings = append(a.Findings, Finding{Code: code, Severity: severityFix, Message: msg})
}
func (a *Audit) warn(code, msg string) {
	a.Findings = append(a.Findings, Finding{Code: code, Severity: severityWarn, Message: msg})
}

func (a *Audit) computeVerdict() {
	a.Verdict = VerdictConvertible
	for _, f := range a.Findings {
		switch f.Severity {
		case severityBlock:
			a.Verdict = VerdictBlocked
			return
		case severityFix:
			a.Verdict = VerdictNeedsFix
		}
	}
}
