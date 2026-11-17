package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
)

// The fail2ban layout matches Bash's fail2ban_manager.sh one to one. Files we
// create are recorded in a manifest so an uninstall removes only our own
// artifacts; anything else under jail.d belongs to the operator.
const (
	fail2banConfDirRel       = "etc/fail2ban"
	fail2banJailDirRel       = "etc/fail2ban/jail.d"
	fail2banFilterDirRel     = "etc/fail2ban/filter.d"
	fail2banJailConfRel      = "etc/fail2ban/jail.conf"
	fail2banJailLocalRel     = "etc/fail2ban/jail.local"
	fail2banIncrementalRel   = "etc/fail2ban/jail.d/zzz-idleleo-incremental.local"
	fail2banTrustRel         = "etc/fail2ban/jail.d/zzz-idleleo-trust.local"
	fail2banRestartDropinRel = "etc/systemd/system/fail2ban.service.d/restart-policy.conf"
	fail2banManifestRel      = "etc/idleleo/v1/fail2ban.json"
	fail2banService          = "fail2ban"
	fail2banManifestVersion  = 1
)

// Fail2banInstallHint is printed whenever fail2ban-client is missing. The Go
// manager never runs the distro package manager (see behavior-diff G13).
const Fail2banInstallHint = "fail2ban is not installed; install it first, then re-run:\n" +
	"  Debian/Ubuntu: apt-get update && apt-get install -y fail2ban\n" +
	"  RHEL/Fedora:   dnf install -y fail2ban\n" +
	"  Alpine:        apk add fail2ban\n" +
	"the Go manager never runs the OS package manager (Bash installs it automatically), so nothing was written"

// Seams: unit tests run without fail2ban and without an init system.
var (
	lookPathFail2ban = func() (string, error) { return exec.LookPath("fail2ban-client") }
	runFail2ban      = func(ctx context.Context, bin string, args ...string) (host.ExecResult, error) {
		return host.Run(ctx, host.ExecSpec{Path: bin, Args: args, Timeout: 30 * time.Second})
	}
	sshClientIP = defaultSSHClientIP
)

var jailNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Fail2banSpec is one install request. The two optional Nginx jails default to
// enabled, mirroring Bash's "empty answer means yes".
type Fail2banSpec struct {
	Root                 string
	AllowContainerWrites bool
	DisableNoHost        bool
	DisableTLSError      bool
}

// JailState is one jail as the installer left it.
type JailState struct {
	Name    string `json:"name"`
	Written bool   `json:"written"`
	LogPath string `json:"logPath,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Fail2banReport is the machine-readable result of `fail2ban install`.
type Fail2banReport struct {
	Jails            []JailState `json:"jails"`
	Files            []string    `json:"files"`
	Warnings         []string    `json:"warnings"`
	ServiceRestarted bool        `json:"serviceRestarted"`
	SSHClientIP      string      `json:"sshClientIP,omitempty"`
	TrustHint        string      `json:"trustHint,omitempty"`
}

// JailRuntime is the live state of one jail.
type JailRuntime struct {
	Name            string   `json:"name"`
	CurrentlyBanned int      `json:"currentlyBanned"`
	TotalBanned     int      `json:"totalBanned"`
	BannedIPs       []string `json:"bannedIPs"`
}

// Fail2banStatus is the result of `fail2ban status`.
type Fail2banStatus struct {
	Installed bool          `json:"installed"`
	Jails     []JailRuntime `json:"jails"`
	Raw       string        `json:"raw,omitempty"`
}

type fail2banManifest struct {
	Version int      `json:"version"`
	Files   []string `json:"files"`
}

// jailSpec describes one Bash jail without deciding whether it applies.
type jailSpec struct {
	name     string
	fileRel  string
	filter   string // filter.d file to write, empty for package filters
	logRel   string // relative log path used for existence checks
	logPath  string // absolute log path written into the jail
	maxRetry int
	findTime int
	banTime  int
	body     string
}

// InstallFail2ban writes the same five jails as Bash, skips any jail whose log
// file does not exist, validates the candidate tree with `-t`, then starts the
// service. It never installs the package.
func InstallFail2ban(ctx context.Context, spec Fail2banSpec) (Fail2banReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return Fail2banReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return Fail2banReport{}, err
	}
	bin, err := lookPathFail2ban()
	if err != nil {
		return Fail2banReport{}, errors.New(Fail2banInstallHint)
	}
	rep := Fail2banReport{Jails: []JailState{}, Files: []string{}, Warnings: []string{}}
	files := map[string]string{}
	manifest := loadFail2banManifest(paths)

	nginxDir := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel))
	existing := func(rel string) bool { return fail2banRelExists(paths, rel) }

	// sshd uses the journal, so its precondition is a reachable SSH unit.
	sshJail, sshReason := JailState{Name: "sshd"}, ""
	if !serviceManaged(paths.Root) {
		sshReason = "sandbox root: systemd journal is not reachable"
	} else if unit := activeSSHUnit(ctx); unit == "" {
		sshReason = "no active ssh/sshd unit: systemd cannot read SSH logs"
	} else {
		sshJail.Written = true
		files[fail2banJailDirRel+"/sshd.local"] = sshdJailConfig()
	}
	if !sshJail.Written {
		sshJail.Reason = sshReason
	}
	rep.Jails = append(rep.Jails, sshJail)

	candidates := []struct {
		state   JailState
		spec    jailSpec
		enabled bool
	}{
		{
			state: JailState{Name: "nginx-badbots"},
			spec: jailSpec{
				name: "nginx-badbots", fileRel: fail2banJailDirRel + "/nginx-badbots.local",
				logRel:   nginx.InstallDirRel + "/logs/access.log",
				logPath:  filepath.Join(nginxDir, "logs", "access.log"),
				maxRetry: 5, banTime: 604800,
			},
			enabled: true,
		},
		{
			state: JailState{Name: "nginx-botsearch"},
			spec: jailSpec{
				name: "nginx-botsearch", fileRel: fail2banJailDirRel + "/nginx-botsearch.local",
				logRel:  nginx.InstallDirRel + "/logs/access.log",
				logPath: filepath.Join(nginxDir, "logs", "access.log"),
				banTime: 604800,
			},
			enabled: true,
		},
		{
			state: JailState{Name: "nginx-no-host"},
			spec: jailSpec{
				name: "nginx-no-host", fileRel: fail2banJailDirRel + "/nginx-no-host.local",
				filter: "nginx-no-host", logRel: nginx.InstallDirRel + "/logs/sni_error.log",
				logPath:  filepath.Join(nginxDir, "logs", "sni_error.log"),
				maxRetry: 5, findTime: 120, banTime: 604800,
			},
			enabled: !spec.DisableNoHost,
		},
		{
			state: JailState{Name: "nginx-tls-error"},
			spec: jailSpec{
				name: "nginx-tls-error", fileRel: fail2banJailDirRel + "/nginx-tls-error.local",
				filter: "nginx-tls-error", logRel: nginx.InstallDirRel + "/logs/tls_error.log",
				logPath:  filepath.Join(nginxDir, "logs", "tls_error.log"),
				maxRetry: 8, findTime: 300, banTime: 43200,
			},
			enabled: !spec.DisableTLSError,
		},
	}
	for _, c := range candidates {
		state := c.state
		if !c.enabled {
			state.Reason = "disabled by --no-" + c.spec.name
			rep.Jails = append(rep.Jails, state)
			continue
		}
		if !existing(c.spec.logRel) {
			state.Reason = "log file does not exist yet: " + c.spec.logPath
			rep.Jails = append(rep.Jails, state)
			continue
		}
		state.Written = true
		state.LogPath = c.spec.logPath
		files[c.spec.fileRel] = c.spec.jailConfig()
		if c.spec.filter != "" {
			files[fail2banFilterDirRel+"/"+c.spec.filter+".conf"] = nginxJailFilter()
		}
		rep.Jails = append(rep.Jails, state)
	}

	files[fail2banIncrementalRel] = incrementalJailConfig()

	// Adopt identical files left behind by a Bash install, refuse to clobber
	// files with different content.
	for _, rel := range sortedKeys(files) {
		path, joinErr := paths.Join(rel, true)
		if joinErr != nil {
			return Fail2banReport{}, joinErr
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		if string(body) == files[rel] {
			manifest.Files = append(manifest.Files, rel)
			delete(files, rel)
			rep.Files = append(rep.Files, path)
			continue
		}
		if manifest.contains(rel) {
			continue // ours, rewrite below
		}
		delete(files, rel)
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("left %s untouched: it exists but was not created by Idleleo", path))
	}

	// jail.local is a copy of the package's jail.conf, exactly like Bash.
	if !existing(fail2banJailLocalRel) {
		if confPath, joinErr := paths.Join(fail2banJailConfRel, false); joinErr == nil {
			if body, readErr := os.ReadFile(confPath); readErr == nil {
				files[fail2banJailLocalRel] = string(body)
			}
		}
	}

	if err := validateFail2banConfig(ctx, bin, paths, files); err != nil {
		return Fail2banReport{}, err
	}
	for _, rel := range sortedKeys(files) {
		path, joinErr := paths.Join(rel, true)
		if joinErr != nil {
			return Fail2banReport{}, joinErr
		}
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
			return Fail2banReport{}, mkErr
		}
		if writeErr := writeFileAtomic(path, []byte(files[rel]), 0o644); writeErr != nil {
			return Fail2banReport{}, writeErr
		}
		rep.Files = append(rep.Files, path)
		manifest.Files = append(manifest.Files, rel)
	}

	// Bash writes the restart policy only when it is missing and never updates it.
	if dropinPath, joinErr := paths.Join(fail2banRestartDropinRel, true); joinErr == nil {
		if _, statErr := os.Stat(dropinPath); os.IsNotExist(statErr) {
			if mkErr := os.MkdirAll(filepath.Dir(dropinPath), 0o755); mkErr != nil {
				rep.Warnings = append(rep.Warnings, "restart policy skipped: "+mkErr.Error())
			} else if writeErr := writeFileAtomic(dropinPath, []byte(restartPolicyDropin()), 0o644); writeErr != nil {
				rep.Warnings = append(rep.Warnings, "restart policy skipped: "+writeErr.Error())
			} else {
				rep.Files = append(rep.Files, dropinPath)
				manifest.Files = append(manifest.Files, fail2banRestartDropinRel)
			}
		}
	}

	if serviceManaged(paths.Root) {
		_ = serviceCommand(ctx, "daemon-reload")
		if err := serviceCommand(ctx, "enable", fail2banService); err != nil {
			rep.Warnings = append(rep.Warnings, "enable "+fail2banService+" failed: "+err.Error())
		}
		if err := serviceCommand(ctx, "restart", fail2banService); err != nil {
			rep.Warnings = append(rep.Warnings, "restart "+fail2banService+" failed: "+err.Error())
		} else {
			rep.ServiceRestarted = true
		}
	} else {
		rep.Warnings = append(rep.Warnings, "sandbox root: systemd service not touched")
	}

	if err := saveFail2banManifest(paths, manifest); err != nil {
		return Fail2banReport{}, err
	}

	// Suggest, never apply: a dynamic client address would put a stranger on
	// the whitelist, so the operator types the command themselves.
	if sshJail.Written {
		if ip := sshClientIP(); ip != "" {
			rep.SSHClientIP = ip
			rep.TrustHint = "idleleo fail2ban trust add --jail sshd --ip " + ip
		}
	}
	sort.Strings(rep.Files)
	return rep, nil
}

func activeSSHUnit(ctx context.Context) string {
	for _, unit := range []string{"ssh", "sshd"} {
		if strings.TrimSpace(serviceQuery(ctx, "is-active", unit)) == "active" {
			return unit
		}
	}
	return ""
}

// UninstallFail2banSpec is one removal request.
type UninstallFail2banSpec struct {
	Root                 string
	AllowContainerWrites bool
	Force                bool
}

// UninstallFail2banReport lists what was removed, what was kept and, when the
// manifest is missing, the candidates that need --force.
type UninstallFail2banReport struct {
	Removed          []string `json:"removed"`
	Preserved        []string `json:"preserved"`
	Candidates       []string `json:"candidates,omitempty"`
	NeedForce        bool     `json:"needForce"`
	Warnings         []string `json:"warnings"`
	ServiceRestarted bool     `json:"serviceRestarted"`
}

// UninstallFail2ban removes only files this manager wrote. A host without a
// manifest falls back to listing candidates and requires --force, and even
// then only the fixed set of names Bash could have created is removed.
func UninstallFail2ban(ctx context.Context, spec UninstallFail2banSpec) (UninstallFail2banReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return UninstallFail2banReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return UninstallFail2banReport{}, err
	}
	rep := UninstallFail2banReport{Removed: []string{}, Preserved: []string{}, Warnings: []string{}}
	manifest := loadFail2banManifest(paths)

	actual, warnings := actualFail2banArtifacts(paths)
	rep.Warnings = append(rep.Warnings, warnings...)
	owned := map[string]bool{}
	if manifest.Version > 0 {
		for _, rel := range manifest.Files {
			owned[rel] = true
		}
		for _, rel := range actual {
			if !owned[rel] {
				if strings.HasSuffix(rel, ".local") {
					rep.Preserved = append(rep.Preserved, filepath.Join(paths.Root, rel))
				}
			}
		}
	} else {
		for _, rel := range actual {
			rep.Candidates = append(rep.Candidates, filepath.Join(paths.Root, rel))
		}
		rep.NeedForce = len(rep.Candidates) > 0 && !spec.Force
		if !spec.Force {
			return rep, nil
		}
		for _, rel := range knownFail2banArtifacts() {
			owned[rel] = true
		}
	}

	rels := make([]string, 0, len(owned))
	for rel := range owned {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		if !safeFail2banRel(rel) {
			rep.Warnings = append(rep.Warnings, "skipped unexpected manifest entry: "+rel)
			continue
		}
		path, joinErr := paths.Join(rel, false)
		if joinErr != nil {
			continue
		}
		if rmErr := os.Remove(path); rmErr != nil {
			if os.IsNotExist(rmErr) {
				continue
			}
			return UninstallFail2banReport{}, rmErr
		}
		rep.Removed = append(rep.Removed, path)
	}
	if len(rep.Removed) > 0 && serviceManaged(paths.Root) {
		_ = serviceCommand(ctx, "daemon-reload")
		// Jails are unloaded only by a restart; the package itself stays.
		if err := serviceCommand(ctx, "restart", fail2banService); err != nil {
			rep.Warnings = append(rep.Warnings, "restart "+fail2banService+" failed: "+err.Error())
		} else {
			rep.ServiceRestarted = true
		}
		rep.Warnings = append(rep.Warnings,
			"the fail2ban package is still installed; only the Idleleo jails were removed")
	}
	if manifestPath, joinErr := paths.Join(fail2banManifestRel, false); joinErr == nil {
		_ = os.Remove(manifestPath)
	}
	sort.Strings(rep.Removed)
	sort.Strings(rep.Preserved)
	sort.Strings(rep.Candidates)
	return rep, nil
}

// actualFail2banArtifacts lists files that a Bash or Idleleo install could have
// written, excluding the package's own jail.conf.
func actualFail2banArtifacts(paths host.Paths) ([]string, []string) {
	var rels, warnings []string
	if jailDir, err := paths.Join(fail2banJailDirRel, false); err == nil {
		entries, readErr := os.ReadDir(jailDir)
		if readErr != nil {
			warnings = append(warnings, "cannot read "+jailDir+": "+readErr.Error())
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".local") {
				continue
			}
			rels = append(rels, fail2banJailDirRel+"/"+e.Name())
		}
	}
	for _, rel := range knownFail2banArtifacts() {
		if fail2banRelExists(paths, rel) {
			rels = append(rels, rel)
		}
	}
	return dedupeStrings(rels), warnings
}

// fail2banRelExists stats the mapped path; Join alone does not prove presence.
func fail2banRelExists(paths host.Paths, rel string) bool {
	path, err := paths.Join(rel, false)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

func knownFail2banArtifacts() []string {
	return []string{
		fail2banJailLocalRel,
		fail2banJailDirRel + "/sshd.local",
		fail2banJailDirRel + "/nginx-badbots.local",
		fail2banJailDirRel + "/nginx-botsearch.local",
		fail2banJailDirRel + "/nginx-no-host.local",
		fail2banJailDirRel + "/nginx-tls-error.local",
		fail2banIncrementalRel,
		fail2banTrustRel,
		fail2banFilterDirRel + "/nginx-no-host.conf",
		fail2banFilterDirRel + "/nginx-tls-error.conf",
		fail2banRestartDropinRel,
	}
}

func safeFail2banRel(rel string) bool {
	if rel == fail2banRestartDropinRel {
		return true
	}
	return strings.HasPrefix(rel, fail2banConfDirRel+"/") || rel == fail2banManifestRel
}

// Fail2banBanned reports the live state of every jail, or of one jail.
func Fail2banBanned(ctx context.Context, jail string) (Fail2banStatus, error) {
	bin, err := lookPathFail2ban()
	if err != nil {
		return Fail2banStatus{}, errors.New(Fail2banInstallHint)
	}
	if jail != "" && !jailNamePattern.MatchString(jail) {
		return Fail2banStatus{}, fmt.Errorf("invalid jail name: %s", jail)
	}
	status := Fail2banStatus{Installed: true, Jails: []JailRuntime{}}
	if jail != "" {
		rt, err := readJailRuntime(ctx, bin, jail)
		if err != nil {
			return Fail2banStatus{}, err
		}
		status.Jails = append(status.Jails, rt)
		return status, nil
	}
	out, err := fail2banStatusOutput(ctx, bin)
	if err != nil {
		return Fail2banStatus{}, err
	}
	status.Raw = out
	for _, name := range activeJails(out) {
		rt, err := readJailRuntime(ctx, bin, name)
		if err != nil {
			continue
		}
		status.Jails = append(status.Jails, rt)
	}
	return status, nil
}

// Fail2banStatusReport is the result of `fail2ban status`. It stays read-only
// and never fails just because the package is absent.
func Fail2banStatusReport(ctx context.Context) (Fail2banStatus, error) {
	if _, err := lookPathFail2ban(); err != nil {
		return Fail2banStatus{Installed: false, Jails: []JailRuntime{}}, nil
	}
	return Fail2banBanned(ctx, "")
}

// UnbanReport is the result of one unban attempt.
type UnbanReport struct {
	Jail          string   `json:"jail"`
	IP            string   `json:"ip"`
	WasBanned     bool     `json:"wasBanned"`
	Unbanned      bool     `json:"unbanned"`
	RemainingIPs  []string `json:"remainingIPs"`
	AlreadyAbsent bool     `json:"alreadyAbsent"`
}

// UnbanFail2banIP mirrors Bash's quick unban: the jail must be active, the IP
// must be a single address, and the result is verified against the live list.
func UnbanFail2banIP(ctx context.Context, jail, ip string) (UnbanReport, error) {
	bin, err := lookPathFail2ban()
	if err != nil {
		return UnbanReport{}, errors.New(Fail2banInstallHint)
	}
	if !jailNamePattern.MatchString(jail) {
		return UnbanReport{}, fmt.Errorf("invalid jail name: %s", jail)
	}
	if net.ParseIP(strings.TrimSpace(ip)) == nil {
		return UnbanReport{}, fmt.Errorf("invalid IP address: %s", ip)
	}
	rep := UnbanReport{Jail: jail, IP: ip, RemainingIPs: []string{}}
	out, err := fail2banStatusOutput(ctx, bin)
	if err != nil {
		return UnbanReport{}, err
	}
	if !containsString(activeJails(out), jail) {
		return UnbanReport{}, fmt.Errorf("jail %q is not active; run `idleleo fail2ban banned` to list jails", jail)
	}
	rt, err := readJailRuntime(ctx, bin, jail)
	if err != nil {
		return UnbanReport{}, err
	}
	if !containsString(rt.BannedIPs, ip) {
		rep.AlreadyAbsent = true
		rep.RemainingIPs = rt.BannedIPs
		return rep, nil
	}
	rep.WasBanned = true
	if res, runErr := runFail2ban(ctx, bin, "set", jail, "unbanip", ip); runErr != nil {
		return rep, runErr
	} else if res.ExitCode != 0 {
		return rep, fmt.Errorf("fail2ban-client set %s unbanip %s failed (exit %d): %s",
			jail, ip, res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout))
	}
	after, err := readJailRuntime(ctx, bin, jail)
	if err != nil {
		return rep, err
	}
	rep.RemainingIPs = after.BannedIPs
	if containsString(after.BannedIPs, ip) {
		return rep, fmt.Errorf("%s is still banned in %s after unban; check fail2ban logs", ip, jail)
	}
	rep.Unbanned = true
	return rep, nil
}

// TrustSpec is one ignoreip change. Value accepts a single IP or a CIDR.
type TrustSpec struct {
	Root                 string
	AllowContainerWrites bool
	Jail                 string
	Value                string
	Remove               bool
}

// TrustReport is the result of a trust change.
type TrustReport struct {
	Jail      string   `json:"jail"`
	Value     string   `json:"value"`
	Applied   bool     `json:"applied"`
	Persisted bool     `json:"persisted"`
	File      string   `json:"file,omitempty"`
	Warnings  []string `json:"warnings"`
}

// Fail2banTrust adds or removes a trusted IP/CIDR at runtime and persists it to
// the managed trust file, validating the candidate tree before replacing it.
func Fail2banTrust(ctx context.Context, spec TrustSpec) (TrustReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return TrustReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return TrustReport{}, err
	}
	bin, err := lookPathFail2ban()
	if err != nil {
		return TrustReport{}, errors.New(Fail2banInstallHint)
	}
	if !jailNamePattern.MatchString(spec.Jail) {
		return TrustReport{}, fmt.Errorf("invalid jail name: %s", spec.Jail)
	}
	if !validIPOrCIDR(spec.Value) {
		return TrustReport{}, fmt.Errorf("invalid IP or CIDR: %s", spec.Value)
	}
	out, err := fail2banStatusOutput(ctx, bin)
	if err != nil {
		return TrustReport{}, err
	}
	if !containsString(activeJails(out), spec.Jail) {
		return TrustReport{}, fmt.Errorf("jail %q is not active; run `idleleo fail2ban banned` to list jails", spec.Jail)
	}
	rep := TrustReport{Jail: spec.Jail, Value: spec.Value, Warnings: []string{}}

	action := "addignoreip"
	if spec.Remove {
		action = "delignoreip"
	}
	if res, runErr := runFail2ban(ctx, bin, "set", spec.Jail, action, spec.Value); runErr != nil {
		return rep, runErr
	} else if res.ExitCode != 0 {
		return rep, fmt.Errorf("fail2ban-client set %s %s %s failed (exit %d): %s",
			spec.Jail, action, spec.Value, res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout))
	}
	rep.Applied = true

	filePath, joinErr := paths.Join(fail2banTrustRel, true)
	if joinErr != nil {
		return rep, joinErr
	}
	previous, readErr := os.ReadFile(filePath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return rep, readErr
	}
	candidate := updateTrustFile(string(previous), spec.Jail, spec.Value, spec.Remove)
	files := map[string]string{fail2banTrustRel: candidate}
	if err := validateFail2banConfig(ctx, bin, paths, files); err != nil {
		return rep, fmt.Errorf("runtime change applied but the candidate config was rejected, nothing persisted: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(filePath, []byte(candidate), 0o644); err != nil {
		return rep, err
	}
	rep.File = filePath
	rep.Persisted = true

	manifest := loadFail2banManifest(paths)
	manifest.Files = append(manifest.Files, fail2banTrustRel)
	if err := saveFail2banManifest(paths, manifest); err != nil {
		return rep, err
	}

	if res, runErr := runFail2ban(ctx, bin, "reload"); runErr != nil || res.ExitCode != 0 {
		// Roll back the file so runtime and disk do not drift apart.
		if readErr == nil {
			_ = writeFileAtomic(filePath, previous, 0o644)
		} else {
			_ = os.Remove(filePath)
		}
		_, _ = runFail2ban(ctx, bin, "reload")
		return rep, fmt.Errorf("runtime change applied but reload failed; the file change was rolled back")
	}
	return rep, nil
}

// JailToggleSpec turns one managed jail on or off.
type JailToggleSpec struct {
	Root                 string
	AllowContainerWrites bool
	Jail                 string
	Enable               bool
}

// JailToggleReport is the result of a jail toggle.
type JailToggleReport struct {
	Jail             string   `json:"jail"`
	File             string   `json:"file"`
	Enabled          bool     `json:"enabled"`
	ServiceRestarted bool     `json:"serviceRestarted"`
	Warnings         []string `json:"warnings"`
}

// ToggleFail2banJail flips `enabled` in a jail file this manager owns.
func ToggleFail2banJail(ctx context.Context, spec JailToggleSpec) (JailToggleReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return JailToggleReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return JailToggleReport{}, err
	}
	if !jailNamePattern.MatchString(spec.Jail) {
		return JailToggleReport{}, fmt.Errorf("invalid jail name: %s", spec.Jail)
	}
	rel := fail2banJailDirRel + "/" + spec.Jail + ".local"
	manifest := loadFail2banManifest(paths)
	if !manifest.contains(rel) {
		return JailToggleReport{}, fmt.Errorf("jail %q is not managed by Idleleo; edit its file yourself", spec.Jail)
	}
	bin, err := lookPathFail2ban()
	if err != nil {
		return JailToggleReport{}, errors.New(Fail2banInstallHint)
	}
	path, err := paths.Join(rel, false)
	if err != nil {
		return JailToggleReport{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return JailToggleReport{}, err
	}
	updated := setJailEnabled(string(body), spec.Enable)
	rep := JailToggleReport{Jail: spec.Jail, File: path, Enabled: spec.Enable, Warnings: []string{}}
	if err := validateFail2banConfig(ctx, bin, paths, map[string]string{rel: updated}); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(path, []byte(updated), 0o644); err != nil {
		return rep, err
	}
	if serviceManaged(paths.Root) {
		if err := serviceCommand(ctx, "restart", fail2banService); err != nil {
			rep.Warnings = append(rep.Warnings, "restart "+fail2banService+" failed: "+err.Error())
		} else {
			rep.ServiceRestarted = true
		}
	} else {
		rep.Warnings = append(rep.Warnings, "sandbox root: systemd service not touched")
	}
	return rep, nil
}

func (j jailSpec) jailConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]\n", j.name)
	b.WriteString("enabled  = true\n")
	if j.filter != "" {
		fmt.Fprintf(&b, "filter   = %s\n", j.filter)
	}
	switch j.name {
	case "nginx-badbots":
		b.WriteString("port     = http,https,8080\n")
		b.WriteString("filter   = apache-badbots\n")
	case "nginx-botsearch":
		b.WriteString("filter   = nginx-botsearch\n")
	}
	fmt.Fprintf(&b, "logpath  = %s\n", j.logPath)
	if j.name == "nginx-botsearch" {
		fmt.Fprintf(&b, "           %s\n", filepath.Join(filepath.Dir(j.logPath), "error.log"))
	}
	if j.banTime > 0 {
		fmt.Fprintf(&b, "bantime  = %d\n", j.banTime)
	}
	if j.maxRetry > 0 {
		fmt.Fprintf(&b, "maxretry = %d\n", j.maxRetry)
	}
	if j.findTime > 0 {
		fmt.Fprintf(&b, "findtime = %d\n", j.findTime)
	}
	return b.String()
}

func sshdJailConfig() string {
	return `[sshd]
enabled = true
filter = sshd
logpath = %(sshd_log)s
backend = systemd
maxretry = 5
bantime = 604800
`
}

func incrementalJailConfig() string {
	return `# Idleleo incremental ban policy
# Repeat offenders get progressively longer bans.
# Base bantime/maxretry/findtime per jail are NOT relaxed.
[DEFAULT]
bantime.increment = true
bantime.multipliers = 1 2 4 8 16 32 64
bantime.maxtime = 180d
bantime.rndtime = 10m
bantime.overalljails = false
`
}

// nginxJailFilter is the filter Bash writes for both custom Nginx jails. The
// doubled percent signs stay literal because fail2ban expands the value.
func nginxJailFilter() string {
	return `[Definition]
datepattern = %%d/%%b/%%Y:%%H:%%M:%%S %%z
failregex = ^<HOST> \[[^\]]*\] "[^"]*" \S* \d+$
ignoreregex =
`
}

func restartPolicyDropin() string {
	return `[Unit]
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=10
`
}

// validateFail2banConfig copies the live tree, applies the candidates and asks
// fail2ban itself whether the result parses. Nothing is written on failure.
func validateFail2banConfig(ctx context.Context, bin string, paths host.Paths, files map[string]string) error {
	tmp, err := os.MkdirTemp("", "idleleo-fail2ban-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(paths.Root, filepath.FromSlash(fail2banConfDirRel))
	if st, statErr := os.Stat(src); statErr == nil && st.IsDir() {
		if copyErr := copyTree(src, tmp); copyErr != nil {
			return copyErr
		}
	}
	for rel, body := range files {
		dst := filepath.Join(tmp, filepath.FromSlash(strings.TrimPrefix(rel, fail2banConfDirRel+"/")))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(body), 0o644); err != nil {
			return err
		}
	}
	res, err := runFail2ban(ctx, bin, "-c", tmp, "-t")
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		return fmt.Errorf("fail2ban-client -t rejected the generated config (exit %d): %s", res.ExitCode, msg)
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		defer in.Close()
		out, createErr := os.Create(target)
		if createErr != nil {
			return createErr
		}
		if _, copyErr := io.Copy(out, in); copyErr != nil {
			out.Close()
			return copyErr
		}
		return out.Close()
	})
}

func fail2banStatusOutput(ctx context.Context, bin string) (string, error) {
	res, err := runFail2ban(ctx, bin, "status")
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		return "", fmt.Errorf("fail2ban-client status failed (exit %d): %s", res.ExitCode, msg)
	}
	return res.Stdout, nil
}

func readJailRuntime(ctx context.Context, bin, jail string) (JailRuntime, error) {
	res, err := runFail2ban(ctx, bin, "status", jail)
	if err != nil {
		return JailRuntime{}, err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		return JailRuntime{}, fmt.Errorf("fail2ban-client status %s failed (exit %d): %s", jail, res.ExitCode, msg)
	}
	rt := JailRuntime{Name: jail, BannedIPs: parseBannedIPs(res.Stdout)}
	rt.CurrentlyBanned = parseIntField(res.Stdout, "Currently banned")
	rt.TotalBanned = parseIntField(res.Stdout, "Total banned")
	return rt, nil
}

func activeJails(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "Jail list:")
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+len("Jail list:"):])
		var names []string
		for _, part := range strings.Split(value, ",") {
			if name := strings.TrimSpace(part); name != "" {
				names = append(names, name)
			}
		}
		return names
	}
	return nil
}

func parseBannedIPs(out string) []string {
	ips := []string{}
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "Banned IP list:")
		if idx < 0 {
			continue
		}
		for _, part := range strings.Fields(line[idx+len("Banned IP list:"):]) {
			if net.ParseIP(part) != nil {
				ips = append(ips, part)
			}
		}
	}
	return ips
}

func parseIntField(out, label string) int {
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, label+":")
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+len(label)+1:])
		var n int
		if _, err := fmt.Sscanf(value, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

// updateTrustFile rewrites our managed trust file, one section per jail.
func updateTrustFile(existing, jail, value string, remove bool) string {
	order := []string{}
	sections := map[string][]string{}
	current := ""
	for _, line := range strings.Split(existing, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			current = strings.Trim(trimmed, "[]")
			if _, ok := sections[current]; !ok {
				sections[current] = nil
				order = append(order, current)
			}
			continue
		}
		if current == "" || !strings.HasPrefix(trimmed, "ignoreip") {
			continue
		}
		_, after, _ := strings.Cut(trimmed, "=")
		for _, field := range strings.Fields(after) {
			sections[current] = append(sections[current], field)
		}
	}
	if _, ok := sections[jail]; !ok {
		order = append(order, jail)
	}
	values := sections[jail]
	if remove {
		kept := values[:0]
		for _, v := range values {
			if v != value {
				kept = append(kept, v)
			}
		}
		values = kept
	} else if !containsString(values, value) {
		values = append(values, value)
	}
	sections[jail] = values

	var b strings.Builder
	b.WriteString("# Managed by Idleleo. Trusted IPs/CIDRs survive a fail2ban restart.\n")
	sort.Strings(order)
	for _, name := range order {
		vals := sections[name]
		if len(vals) == 0 {
			continue
		}
		sort.Strings(vals)
		fmt.Fprintf(&b, "[%s]\nignoreip = %s\n", name, strings.Join(vals, " "))
	}
	return b.String()
}

func setJailEnabled(body string, enable bool) string {
	value := "false"
	if enable {
		value = "true"
	}
	re := regexp.MustCompile(`(?m)^(\s*enabled\s*=\s*)\w+`)
	if re.MatchString(body) {
		return re.ReplaceAllString(body, "${1}"+value)
	}
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines)+1)
	for i, line := range lines {
		out = append(out, line)
		if i == 0 && strings.HasPrefix(strings.TrimSpace(line), "[") {
			out = append(out, "enabled = "+value)
		}
	}
	return strings.Join(out, "\n")
}

func loadFail2banManifest(paths host.Paths) fail2banManifest {
	path, err := paths.Join(fail2banManifestRel, false)
	if err != nil {
		return fail2banManifest{}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fail2banManifest{}
	}
	var m fail2banManifest
	if json.Unmarshal(body, &m) != nil {
		return fail2banManifest{}
	}
	return m
}

func saveFail2banManifest(paths host.Paths, m fail2banManifest) error {
	m.Version = fail2banManifestVersion
	m.Files = dedupeStrings(m.Files)
	sort.Strings(m.Files)
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path, err := paths.Join(fail2banManifestRel, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(path, append(body, '\n'), 0o644)
}

func (m fail2banManifest) contains(rel string) bool {
	return containsString(m.Files, rel)
}

func validIPOrCIDR(value string) bool {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func defaultSSHClientIP() string {
	for _, key := range []string{"SSH_CLIENT", "SSH_CONNECTION"} {
		fields := strings.Fields(os.Getenv(key))
		if len(fields) > 0 && net.ParseIP(fields[0]) != nil {
			return fields[0]
		}
	}
	return ""
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func dedupeStrings(list []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
