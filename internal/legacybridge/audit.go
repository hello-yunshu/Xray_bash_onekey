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
	"path/filepath"
	"sort"
	"strings"
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

// Audit is the read-only migration discovery result. It is also the plan.
type Audit struct {
	SchemaVersion   int                 `json:"schemaVersion"`
	Root            string              `json:"root"`
	LegacyVersion   string              `json:"legacyVersion,omitempty"`
	XrayVersion     string              `json:"xrayVersion,omitempty"`
	Role            string              `json:"role"`
	TLS             string              `json:"tls"`
	Transport       string              `json:"transport"`
	NginxRequired   bool                `json:"nginxRequired"`
	Port            int                 `json:"port,omitempty"`
	UserCount       int                 `json:"userCount"`
	RuntimePath     string              `json:"runtimePath,omitempty"`
	RuntimeSHA256   string              `json:"runtimeSha256,omitempty"`
	RuntimeBytes    int                 `json:"runtimeBytes,omitempty"`
	CustomDNS       bool                `json:"customDns"`
	CustomRouting   bool                `json:"customRouting"`
	CustomOutbounds bool                `json:"customOutbounds"`
	CertFiles       []FileFingerprint   `json:"certFiles"`
	NginxFiles      []FileFingerprint   `json:"nginxFiles"`
	Units           map[string]UnitInfo `json:"units"`
	Entry           EntryInfo           `json:"entry"`
	LegacyScript    FileFingerprint     `json:"legacyScript"`
	GeoLegacyCron   bool                `json:"geoLegacyCron"`
	RelayConf       FileFingerprint     `json:"relayConf"`
	Findings        []Finding           `json:"findings"`
	Verdict         string              `json:"verdict"`
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
		Units:      map[string]UnitInfo{},
		Findings:   []Finding{},
		CertFiles:  []FileFingerprint{},
		NginxFiles: []FileFingerprint{},
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
		if strings.Contains(line, "geo_update.sh") && isProjectCronLine(line) {
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
