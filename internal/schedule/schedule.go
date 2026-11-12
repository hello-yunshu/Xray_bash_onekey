// Package schedule is the native Go replacement for the cron jobs that the
// legacy Bash manager installed (auto_update.sh, ssl_update.sh, geo_update.sh
// and xray_stats.sh). Migration removes those cron lines, so these jobs must be
// taken over explicitly instead of being parked in a deferred list.
//
// auto-update keeps one explicit degradation: it uses the Go release channel
// when one is configured and records a degraded result when it is not (the
// legacy Bash updater has been removed, so guessing a URL is not acceptable).
//
// cert-renew drives the native ACME renewal path itself once a certificate is
// inside the 30-day window: it renews with the same internal/acme executor as
// `idleleo xray cert renew`, records the new fingerprint and reloads Xray/Nginx.
// Failures are recorded as "failed" and leave a durable alert file that
// `idleleo status` prints first.
//
// geodata-refresh and stats-collect are fully implemented with the real asset
// origin and the real Xray API.
package schedule

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/release"
)

const (
	// ConfigRel is the schedule definition. It is owned by the Go manager.
	ConfigRel = "etc/idleleo/schedule/jobs.json"
	// StateRel records the last result of every job.
	StateRel = "var/lib/idleleo/schedule/state.json"
	// LogRel is an append-only, human-readable run log.
	LogRel = "var/log/idleleo/schedule/schedule.log"
	// StatsRel stores the raw statsquery output of the last successful run.
	StatsRel = "var/lib/idleleo/schedule/stats.json"

	GeodataDirRel = "etc/idleleo/share/xray"
	RuntimeRel    = "etc/idleleo/conf/xray/config.json"
	CertDirRel    = "etc/idleleo/cert"

	UnitRel  = "etc/systemd/system/idleleo-schedule.service"
	TimerRel = "etc/systemd/system/idleleo-schedule.timer"

	// AlertServiceUnitRel is the OnFailure target of the schedule service.
	AlertServiceUnitRel = "etc/systemd/system/idleleo-alert.service"
	// AlertsDirRel stores durable job alerts. `idleleo status` reads it first.
	AlertsDirRel = "etc/idleleo/alerts"

	// ACMEStagingDirectory is the safe default for direct CLI use. Production
	// paths (install.sh, ssl_update.sh, schedule install) pass --production.
	ACMEStagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ACMEProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

	// CertRenewWindow is the renewal window for cert-renew.
	CertRenewWindow = 30 * 24 * time.Hour

	DefaultIntervalSeconds = 3600
	DefaultGeodataURL      = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

	// RillFreshSeconds bounds how old a Rill observation may be and still
	// count as an active handover signal.
	RillFreshSeconds = 600

	SchemaVersion = 1
)

// Jobs are the four legacy cron responsibilities, in stable order.
var Jobs = []string{"auto-update", "cert-renew", "geodata-refresh", "stats-collect"}

// DegradedJobs documents the remaining product degradation in machine-readable
// form. cert-renew is no longer degraded: it runs the same ACME executor as the
// CLI inside the renewal window.
var DegradedJobs = []string{
	"auto-update: updates the Go binary through the Go release channel only when one is configured; legacy Xray/Nginx auto-update cron is retained until a Go equivalent exists (explicit degradation)",
}

// Config is the persisted schedule definition.
type Config struct {
	SchemaVersion   int      `json:"schemaVersion"`
	IntervalSeconds int      `json:"intervalSeconds"`
	Jobs            []string `json:"jobs"`
	GeodataURL      string   `json:"geodataUrl,omitempty"`
	GeodataDir      string   `json:"geodataDir,omitempty"`

	// Certificate renewal. CertDomain is required before cert-renew can renew;
	// the rest have production-safe defaults so an existing install keeps
	// working after an upgrade.
	CertDomain    string `json:"certDomain,omitempty"`
	CertWebroot   string `json:"certWebroot,omitempty"`
	CertFile      string `json:"certFile,omitempty"`
	CertKeyFile   string `json:"certKeyFile,omitempty"`
	ACMEDirectory string `json:"acmeDirectory,omitempty"`
	ACMEEmail     string `json:"acmeEmail,omitempty"`
	AlertWebhook  string `json:"alertWebhook,omitempty"`
}

// applyDefaults fills every optional field. It is shared by loadConfig and
// Install so a freshly written config and a config read back behave the same.
func (c *Config) applyDefaults() {
	if c.SchemaVersion == 0 {
		c.SchemaVersion = SchemaVersion
	}
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = DefaultIntervalSeconds
	}
	if len(c.Jobs) == 0 {
		c.Jobs = Jobs
	}
	if c.GeodataURL == "" {
		c.GeodataURL = DefaultGeodataURL
	}
	if c.GeodataDir == "" {
		c.GeodataDir = GeodataDirRel
	}
	if c.CertFile == "" {
		c.CertFile = CertDirRel + "/xray.crt"
	}
	if c.CertKeyFile == "" {
		c.CertKeyFile = CertDirRel + "/xray.key"
	}
	if c.CertWebroot == "" {
		c.CertWebroot = "etc/idleleo/conf"
	}
	if c.ACMEDirectory == "" {
		c.ACMEDirectory = ACMEStagingDirectory
	}
}

// validatePaths rejects configuration paths that would escape the selected
// root. Skipping this check used to surface as a confusing empty path such as
// "mkdir : no such file or directory".
func (c Config) validatePaths() error {
	for _, f := range []struct{ name, value string }{
		{"geodataDir", c.GeodataDir},
		{"certFile", c.CertFile},
		{"certKeyFile", c.CertKeyFile},
		{"certWebroot", c.CertWebroot},
	} {
		if _, err := resolve("/", f.value); err != nil {
			return fmt.Errorf("unsafe schedule config path: %s %q", f.name, f.value)
		}
	}
	return nil
}

// JobState is the last recorded result of one job.
type JobState struct {
	LastRun string `json:"lastRun"`
	Result  string `json:"result"`
	Detail  string `json:"detail,omitempty"`
}

// State is the aggregate scheduler state.
type State struct {
	SchemaVersion int                 `json:"schemaVersion"`
	LastRun       string              `json:"lastRun,omitempty"`
	Runs          int                 `json:"runs"`
	Jobs          map[string]JobState `json:"jobs"`
}

// JobResult is one job outcome from a real run.
type JobResult struct {
	Job    string `json:"job"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
	At     string `json:"at"`
}

// Report is the machine-readable result of `schedule run`.
type Report struct {
	SchemaVersion int         `json:"schemaVersion"`
	Root          string      `json:"root"`
	StartedAt     string      `json:"startedAt"`
	Results       []JobResult `json:"results"`
	// LogWarning records a failure to append the run log. It never changes the
	// exit code: a lost log line is visible but is not a job failure.
	LogWarning string `json:"logWarning,omitempty"`
}

// RunOptions selects the root and an optional job subset.
type RunOptions struct {
	Root string
	Jobs []string
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func resolve(root, rel string) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(rel) || clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe schedule path")
	}
	return filepath.Join(root, clean), nil
}

func path(root, rel string) string {
	p, _ := resolve(root, rel)
	return p
}

// RequireWriteAccess gates schedule installation exactly like the bridge gate:
// a non-root target must be a marked disposable sandbox; a container real root
// requires the explicit acknowledgement, while a real host root is allowed and
// recorded in the system-write audit log.
func RequireWriteAccess(root string, ack bool) error {
	return host.RequireSystemWrite(root, ack)
}

// requireRunRoot is deliberately weaker than the install gate: the timer
// service runs as root on the real system and must keep working without a
// container acknowledgement. Sandbox roots still require the sandbox marker.
func requireRunRoot(root string) error {
	if root == "/" {
		if os.Geteuid() != 0 {
			return errors.New("root required to run scheduled jobs on the real root")
		}
		return nil
	}
	p, err := host.NewPaths(root)
	if err != nil {
		return err
	}
	return p.RequireSandbox()
}

func loadConfig(root string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path(root, ConfigRel))
	if err != nil {
		if os.IsNotExist(err) {
			cfg.applyDefaults()
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("schedule config is not valid JSON: %w", err)
	}
	if cfg.SchemaVersion != SchemaVersion {
		return Config{}, fmt.Errorf("schedule config schema %d is not supported", cfg.SchemaVersion)
	}
	cfg.applyDefaults()
	if err := cfg.validatePaths(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// InstallOptions configures `schedule install`.
type InstallOptions struct {
	Root            string
	IntervalSeconds int
	GeodataURL      string

	CertDomain    string
	CertWebroot   string
	CertFile      string
	CertKeyFile   string
	ACMEDirectory string
	ACMEEmail     string
	AlertWebhook  string
}

// InstallReport confirms what was written and enabled.
type InstallReport struct {
	SchemaVersion    int      `json:"schemaVersion"`
	ConfigPath       string   `json:"configPath"`
	ServicePath      string   `json:"servicePath"`
	TimerPath        string   `json:"timerPath"`
	AlertServicePath string   `json:"alertServicePath"`
	IntervalSeconds  int      `json:"intervalSeconds"`
	Jobs             []string `json:"jobs"`
	DegradedJobs     []string `json:"degradedJobs"`
	Systemd          string   `json:"systemd"`
}

// Install writes the schedule config plus the systemd service/timer and starts
// the timer on the real root. It never runs jobs synchronously.
func Install(ctx context.Context, opts InstallOptions) (InstallReport, error) {
	report := InstallReport{SchemaVersion: SchemaVersion, Jobs: Jobs, DegradedJobs: DegradedJobs}
	interval := opts.IntervalSeconds
	if interval <= 0 {
		interval = DefaultIntervalSeconds
	}
	geoURL := opts.GeodataURL
	if geoURL == "" {
		geoURL = DefaultGeodataURL
	}
	cfg := Config{
		SchemaVersion: SchemaVersion, IntervalSeconds: interval, Jobs: Jobs,
		GeodataURL: geoURL, GeodataDir: GeodataDirRel,
		CertDomain: opts.CertDomain, CertWebroot: opts.CertWebroot,
		CertFile: opts.CertFile, CertKeyFile: opts.CertKeyFile,
		ACMEDirectory: opts.ACMEDirectory, ACMEEmail: opts.ACMEEmail,
		AlertWebhook: opts.AlertWebhook,
	}
	cfg.applyDefaults()
	if err := cfg.validatePaths(); err != nil {
		return report, err
	}
	cfgPath := path(opts.Root, ConfigRel)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return report, err
	}
	if err := writeAtomic(cfgPath, append(b, '\n'), 0o640); err != nil {
		return report, err
	}
	report.ConfigPath = cfgPath
	report.IntervalSeconds = interval

	exec := "/usr/bin/idleleo"
	if opts.Root != "/" {
		exec = filepath.Join(opts.Root, "usr/bin/idleleo")
	}
	service := fmt.Sprintf(`[Unit]
Description=idleleo Go scheduled maintenance (Bridge migration takeover)
After=network-online.target
Wants=network-online.target
OnFailure=idleleo-alert.service

[Service]
Type=oneshot
ExecStart=%s schedule run
`, exec)
	alertUnit := fmt.Sprintf(`[Unit]
Description=idleleo scheduled-job failure alert

[Service]
Type=oneshot
ExecStart=%s schedule alert --job service-failure --detail idleleo-schedule.service_failed
`, exec)
	timer := fmt.Sprintf(`[Unit]
Description=idleleo scheduled maintenance timer

[Timer]
OnActiveSec=%ds
OnUnitActiveSec=%ds
AccuracySec=1s
Persistent=true

[Install]
WantedBy=timers.target
`, interval, interval)
	servicePath := path(opts.Root, UnitRel)
	timerPath := path(opts.Root, TimerRel)
	alertServicePath := path(opts.Root, AlertServiceUnitRel)
	if err := writeAtomic(servicePath, []byte(service), 0o644); err != nil {
		return report, err
	}
	if err := writeAtomic(timerPath, []byte(timer), 0o644); err != nil {
		return report, err
	}
	if err := writeAtomic(alertServicePath, []byte(alertUnit), 0o644); err != nil {
		return report, err
	}
	report.ServicePath, report.TimerPath = servicePath, timerPath
	report.AlertServicePath = alertServicePath

	if opts.Root == "/" {
		if err := systemctl(ctx, "daemon-reload"); err != nil {
			return report, fmt.Errorf("daemon-reload failed: %w", err)
		}
		if err := systemctl(ctx, "enable", "--now", "idleleo-schedule.timer"); err != nil {
			return report, fmt.Errorf("enable timer failed: %w", err)
		}
		report.Systemd = "enabled"
	} else {
		report.Systemd = "sandbox-not-queried"
	}
	return report, nil
}

// Remove stops and removes the units. It is safe to call when nothing was
// installed and returns the list of actions that actually happened.
func Remove(ctx context.Context, root string) ([]string, error) {
	actions := []string{}
	servicePath := path(root, UnitRel)
	timerPath := path(root, TimerRel)
	installed := false
	if _, err := os.Stat(timerPath); err == nil {
		installed = true
	}
	if _, err := os.Stat(servicePath); err == nil {
		installed = true
	}
	if _, err := os.Stat(path(root, AlertServiceUnitRel)); err == nil {
		installed = true
	}
	if root == "/" && installed {
		_ = systemctl(ctx, "disable", "--now", "idleleo-schedule.timer")
		actions = append(actions, "stopped idleleo-schedule.timer")
	}
	for _, p := range []string{servicePath, timerPath, path(root, AlertServiceUnitRel)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return actions, err
		}
	}
	if root == "/" && installed {
		if err := systemctl(ctx, "daemon-reload"); err != nil {
			return actions, err
		}
		actions = append(actions, "removed schedule units")
	}
	return actions, nil
}

func systemctl(ctx context.Context, args ...string) error {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: args, Timeout: 20 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl %s failed (exit %d): %s", strings.Join(args, " "), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// Run executes the selected jobs once and records a timestamped line per job.
func Run(ctx context.Context, opts RunOptions) (Report, error) {
	if err := requireRunRoot(opts.Root); err != nil {
		return Report{SchemaVersion: SchemaVersion}, err
	}
	report := Report{SchemaVersion: SchemaVersion, Root: opts.Root, StartedAt: now(), Results: []JobResult{}}
	recordLog := func(res JobResult) {
		if err := appendLog(opts.Root, res); err != nil && report.LogWarning == "" {
			report.LogWarning = err.Error()
		}
	}
	cfg, err := loadConfig(opts.Root)
	if err != nil {
		return report, err
	}
	selected := opts.Jobs
	if len(selected) == 0 {
		selected = cfg.Jobs
	}
	for _, job := range selected {
		if !isKnownJob(job) {
			return report, fmt.Errorf("unknown scheduled job %q", job)
		}
	}

	lock, err := host.AcquireUpdate(pathsFor(opts.Root).LockFile())
	if err != nil {
		if errors.Is(err, host.ErrLocked) {
			for _, job := range selected {
				res := JobResult{Job: job, Result: "skipped", Detail: "another idleleo update holds the update lock", At: now()}
				report.Results = append(report.Results, res)
				recordLog(res)
			}
			return report, nil
		}
		return report, err
	}
	defer lock.Release()

	for _, job := range selected {
		at := now()
		var res JobResult
		switch job {
		case "auto-update":
			res = autoUpdateJob(ctx, opts.Root, at, lock)
		case "cert-renew":
			res = certRenewJob(ctx, opts.Root, cfg, at)
		case "geodata-refresh":
			res = geodataJob(ctx, opts.Root, cfg, at)
		case "stats-collect":
			res = statsJob(ctx, opts.Root, at)
		}
		report.Results = append(report.Results, res)
		recordLog(res)
	}
	if err := writeState(opts.Root, report.Results); err != nil {
		return report, err
	}
	return report, nil
}

func isKnownJob(job string) bool {
	for _, j := range Jobs {
		if j == job {
			return true
		}
	}
	return false
}

func pathsFor(root string) host.Paths {
	p, _ := host.NewPaths(root)
	return p
}

func autoUpdateJob(ctx context.Context, root, at string, lock *host.UpdateLock) JobResult {
	rep := release.AutoUpdate(ctx, root, lock)
	return JobResult{Job: "auto-update", Result: rep.Action, At: at, Detail: rep.Detail}
}

// certObservation is the external-renewal contract: the certificate file that
// currently expires soonest, its DER fingerprint, and any private-key file
// whose mode is world-accessible.
type certObservation struct {
	NotAfter    time.Time
	Name        string
	Path        string
	Fingerprint string
	InsecureKey []string
}

func scanCert(dir string) (certObservation, error) {
	var obs certObservation
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil
		}
		base := strings.ToLower(filepath.Base(p))
		if strings.Contains(base, "privkey") || strings.HasSuffix(base, ".key") {
			if fi.Mode().Perm()&0o004 != 0 {
				obs.InsecureKey = append(obs.InsecureKey, fmt.Sprintf("%s mode %04o is world-readable", p, fi.Mode().Perm()))
			}
			return nil
		}
		if !strings.HasSuffix(base, ".pem") && !strings.HasSuffix(base, ".crt") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for {
			var block *pem.Block
			block, b = pem.Decode(b)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			if obs.NotAfter.IsZero() || cert.NotAfter.Before(obs.NotAfter) {
				obs.NotAfter = cert.NotAfter
				obs.Name = filepath.Base(p)
				obs.Path = p
				obs.Fingerprint = hashRaw(cert.Raw)
			}
		}
		return nil
	})
	return obs, err
}

func hashRaw(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// certState records the last fingerprint that was actually reloaded. Without
// it a renewal job cannot tell "nothing changed" from "someone renewed the
// certificate", and would either never reload or restart on every tick.
type certState struct {
	SchemaVersion int    `json:"schemaVersion"`
	Fingerprint   string `json:"fingerprint"`
	File          string `json:"file"`
	NotAfter      string `json:"notAfter"`
	ReloadedAt    string `json:"reloadedAt,omitempty"`
}

const CertStateRel = "var/lib/idleleo/schedule/cert.json"

func loadCertState(root string) certState {
	var st certState
	if b, err := os.ReadFile(path(root, CertStateRel)); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveCertState(root string, obs certObservation, at string) error {
	st := certState{
		SchemaVersion: SchemaVersion, Fingerprint: obs.Fingerprint, File: obs.Name,
		NotAfter: obs.NotAfter.UTC().Format(time.RFC3339), ReloadedAt: at,
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path(root, CertStateRel), append(b, '\n'), 0o640)
}

// renewCertificate and reloadServices are package variables so tests can prove
// that the in-window branch really drives ACME and reload instead of merely
// reporting "ok".
var (
	renewCertificate = acme.Renew
	reloadServices   = reloadForCert
)

// certFailure records a durable alert and returns the failed job result. A
// persistence failure never downgrades the result, but it is appended to the
// detail so `schedule run` output carries the loss instead of hiding it.
func certFailure(ctx context.Context, root string, cfg Config, at, detail string) JobResult {
	if _, err := WriteAlert(ctx, root, cfg, "cert-renew", "failed", detail, at); err != nil {
		detail += "; alert not persisted: " + err.Error()
	}
	return JobResult{Job: "cert-renew", Result: "failed", At: at, Detail: detail}
}

func certRenewJob(ctx context.Context, root string, cfg Config, at string) JobResult {
	obs, err := scanCert(path(root, CertDirRel))
	switch {
	case err != nil && !os.IsNotExist(err):
		return certFailure(ctx, root, cfg, at, err.Error())
	case obs.NotAfter.IsZero():
		return JobResult{Job: "cert-renew", Result: "skipped", At: at, Detail: "no certificate files to monitor"}
	}
	last := loadCertState(root)
	changed := last.Fingerprint != "" && last.Fingerprint != obs.Fingerprint
	baseline := last.Fingerprint == ""
	days := int(time.Until(obs.NotAfter).Hours() / 24)

	if (changed || baseline) && len(obs.InsecureKey) > 0 && root == "/" {
		return certFailure(ctx, root, cfg, at,
			"refusing to reload a certificate whose private key is world-readable: "+strings.Join(obs.InsecureKey, "; "))
	}

	// Inside the renewal window the scheduler must renew, not just report.
	if time.Until(obs.NotAfter) < CertRenewWindow {
		if cfg.CertDomain == "" {
			return certFailure(ctx, root, cfg, at, fmt.Sprintf(
				"%s expires in %d days; certDomain is not configured; run 'idleleo schedule install --cert-domain <domain>'",
				obs.Name, days))
		}
		certRel := cfg.CertFile
		acmeDir := filepath.Dir(certRel)
		spec := acme.Config{
			DirectoryURL:   cfg.ACMEDirectory,
			Email:          cfg.ACMEEmail,
			Domain:         cfg.CertDomain,
			Webroot:        path(root, cfg.CertWebroot),
			CertFile:       path(root, cfg.CertFile),
			KeyFile:        path(root, cfg.CertKeyFile),
			AccountKeyFile: path(root, filepath.ToSlash(filepath.Join(acmeDir, "acme", "account.key"))),
			StateFile:      path(root, filepath.ToSlash(filepath.Join(acmeDir, "acme", "account.json"))),
			RenewBefore:    CertRenewWindow,
		}
		res, rerr := renewCertificate(ctx, spec)
		if rerr != nil {
			return certFailure(ctx, root, cfg, at, fmt.Sprintf(
				"%s expires in %d days; renewal failed: %v", obs.Name, days, rerr))
		}
		if res.Skipped {
			return certFailure(ctx, root, cfg, at, fmt.Sprintf(
				"%s expires in %d days; renewal was skipped: %s", obs.Name, days, res.Reason))
		}
		renewed, serr := scanCert(path(root, CertDirRel))
		if serr != nil || renewed.NotAfter.IsZero() {
			return certFailure(ctx, root, cfg, at,
				"renewal completed but no readable certificate was produced")
		}
		reloaded, rerr := reloadServices(ctx, root)
		if rerr != nil {
			return certFailure(ctx, root, cfg, at, "renewal succeeded but reload failed: "+rerr.Error())
		}
		if err := saveCertState(root, renewed, at); err != nil {
			return certFailure(ctx, root, cfg, at, "renewal succeeded but state could not be saved: "+err.Error())
		}
		detail := fmt.Sprintf(
			"%s renewed (sha256=%s); %s; expires in %d days",
			renewed.Name, short(renewed.Fingerprint), reloaded, int(time.Until(renewed.NotAfter).Hours()/24))
		if err := ClearAlert(root, "cert-renew"); err != nil {
			detail += "; alert not cleared: " + err.Error()
		}
		return JobResult{Job: "cert-renew", Result: "ok", At: at, Detail: detail}
	}

	detail := obs.Name
	reload := ""
	// A missing state is a baseline, not a renewal: the first observation must
	// never restart services that were healthy before the cron takeover.
	if root == "/" && changed {
		reload, err = reloadServices(ctx, root)
		if err != nil {
			return certFailure(ctx, root, cfg, at, detail+"; "+err.Error())
		}
	}
	switch {
	case changed:
		detail += fmt.Sprintf(" changed (sha256=%s); %s; expires in %d days", short(obs.Fingerprint), reload, days)
	case baseline:
		detail += fmt.Sprintf(" baseline recorded (sha256=%s); no restart; expires in %d days", short(obs.Fingerprint), days)
	default:
		detail += fmt.Sprintf(" unchanged; expires in %d days; no restart", days)
	}
	if err := saveCertState(root, obs, at); err != nil {
		return certFailure(ctx, root, cfg, at, detail+"; state: "+err.Error())
	}
	if err := ClearAlert(root, "cert-renew"); err != nil {
		detail += "; alert not cleared: " + err.Error()
	}
	return JobResult{Job: "cert-renew", Result: "ok", At: at, Detail: detail}
}

// reloadForCert restarts Xray and reloads Nginx only when the certificate
// fingerprint changed. A stopped service is left stopped.
func reloadForCert(ctx context.Context, root string) (string, error) {
	if root != "/" {
		return "sandbox root, no service reload", nil
	}
	actions := []string{}
	for _, svc := range []struct{ unit, verb string }{{"xray", "restart"}, {"nginx", "reload"}} {
		res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-active", svc.unit}, Timeout: 10 * time.Second})
		if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "active" {
			actions = append(actions, svc.unit+" inactive, no "+svc.verb)
			continue
		}
		res, err = host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{svc.verb, svc.unit}, Timeout: 60 * time.Second})
		if err != nil {
			return strings.Join(actions, ", "), err
		}
		if res.ExitCode != 0 {
			return strings.Join(actions, ", "), fmt.Errorf("systemctl %s %s exit %d: %s", svc.verb, svc.unit, res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		actions = append(actions, svc.unit+" "+svc.verb+"ed")
	}
	return strings.Join(actions, ", "), nil
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func geodataJob(ctx context.Context, root string, cfg Config, at string) JobResult {
	base := strings.TrimRight(cfg.GeodataURL, "/")
	assets := []string{"geoip.dat", "geosite.dat"}
	payloads := make(map[string][]byte, len(assets))
	for _, asset := range assets {
		b, err := fetch(ctx, base+"/"+asset)
		if err != nil {
			return JobResult{Job: "geodata-refresh", Result: "failed", At: at, Detail: fmt.Sprintf("%s: %v", asset, err)}
		}
		payloads[asset] = b
	}
	dir := path(root, cfg.GeodataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return JobResult{Job: "geodata-refresh", Result: "failed", At: at, Detail: err.Error()}
	}
	for _, asset := range assets {
		if err := writeAtomic(filepath.Join(dir, asset), payloads[asset], 0o644); err != nil {
			return JobResult{Job: "geodata-refresh", Result: "failed", At: at, Detail: err.Error()}
		}
	}
	detail := fmt.Sprintf("geoip.dat=%d bytes geosite.dat=%d bytes", len(payloads["geoip.dat"]), len(payloads["geosite.dat"]))
	if root == "/" {
		state := "unknown"
		if res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-active", "xray"}, Timeout: 10 * time.Second}); err == nil && res.ExitCode == 0 {
			state = strings.TrimSpace(res.Stdout)
		}
		if state == "active" {
			if res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"restart", "xray"}, Timeout: 30 * time.Second}); err != nil || res.ExitCode != 0 {
				msg := "systemctl restart xray failed"
				if err != nil {
					msg = err.Error()
				}
				return JobResult{Job: "geodata-refresh", Result: "failed", At: at, Detail: detail + "; " + msg}
			}
			detail += "; xray restarted"
		} else {
			detail += "; xray not active, no reload"
		}
	} else {
		detail += "; sandbox root, no service reload"
	}
	return JobResult{Job: "geodata-refresh", Result: "ok", At: at, Detail: detail}
}

var geodataClient = &http.Client{Timeout: 120 * time.Second}

const maxGeodataBytes = 64 << 20

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := geodataClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("origin returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxGeodataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download interrupted: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("origin returned an empty asset")
	}
	if len(b) > maxGeodataBytes {
		return nil, errors.New("origin asset is larger than the 64MiB limit")
	}
	if b[0] == '<' || b[0] == '{' {
		return nil, errors.New("origin returned HTML/JSON instead of a GeoData asset")
	}
	return b, nil
}

func statsJob(ctx context.Context, root, at string) JobResult {
	cfgPath := path(root, RuntimeRel)
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return JobResult{Job: "stats-collect", Result: "skipped", At: at, Detail: "no runtime config (relay role has no Xray stats)"}
		}
		return JobResult{Job: "stats-collect", Result: "failed", At: at, Detail: err.Error()}
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return JobResult{Job: "stats-collect", Result: "failed", At: at, Detail: "runtime config is not valid JSON"}
	}
	server := apiListen(doc)
	if server == "" {
		return JobResult{Job: "stats-collect", Result: "skipped", At: at, Detail: "stats/api.listen is not configured"}
	}
	// geodata-refresh restarts Xray in the same run, so the API can still be
	// binding right after the restart. Retry briefly instead of recording a
	// spurious failure.
	var res host.ExecResult
	for attempt := 0; attempt < 3; attempt++ {
		res, err = host.Run(ctx, host.ExecSpec{
			Path:    "xray",
			Args:    []string{"api", "statsquery", "--server=" + server, "-pattern", "inbound>>>", "-reset=false"},
			Timeout: 30 * time.Second,
		})
		if err == nil && res.ExitCode == 0 {
			break
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	if err != nil {
		return JobResult{Job: "stats-collect", Result: "failed", At: at, Detail: err.Error()}
	}
	if res.ExitCode != 0 {
		return JobResult{Job: "stats-collect", Result: "failed", At: at, Detail: "statsquery exit " + fmt.Sprint(res.ExitCode) + ": " + strings.TrimSpace(res.Stderr)}
	}
	if err := writeAtomic(path(root, StatsRel), []byte(res.Stdout), 0o640); err != nil {
		return JobResult{Job: "stats-collect", Result: "failed", At: at, Detail: err.Error()}
	}
	return JobResult{Job: "stats-collect", Result: "ok", At: at, Detail: fmt.Sprintf("server=%s bytes=%d", server, len(res.Stdout))}
}

func apiListen(doc map[string]any) string {
	api, _ := doc["api"].(map[string]any)
	switch v := api["listen"].(type) {
	case string:
		return v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				return s
			}
		}
	}
	return ""
}

func appendLog(root string, res JobResult) error {
	line := fmt.Sprintf("%s job=%s result=%s detail=%s\n", res.At, res.Job, res.Result, oneLine(res.Detail))
	return appendLine(path(root, LogRel), line)
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "-"
	}
	return s
}

func writeState(root string, results []JobResult) error {
	p := path(root, StateRel)
	st := State{SchemaVersion: SchemaVersion, Jobs: map[string]JobState{}}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &st)
		if st.Jobs == nil {
			st.Jobs = map[string]JobState{}
		}
	}
	st.SchemaVersion = SchemaVersion
	st.Runs++
	st.LastRun = now()
	for _, res := range results {
		st.Jobs[res.Job] = JobState{LastRun: res.At, Result: res.Result, Detail: res.Detail}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(p, append(b, '\n'), 0o640)
}

// StatusReport is the read-only scheduler view.
type StatusReport struct {
	SchemaVersion   int      `json:"schemaVersion"`
	Installed       bool     `json:"installed"`
	IntervalSeconds int      `json:"intervalSeconds"`
	Jobs            []string `json:"jobs"`
	DegradedJobs    []string `json:"degradedJobs"`
	UnitPath        string   `json:"unitPath"`
	TimerPath       string   `json:"timerPath"`
	Timer           string   `json:"timer"`
	ReleaseChannel  bool     `json:"releaseChannelConfigured"`
	State           State    `json:"state"`
	Alerts          []Alert  `json:"alerts,omitempty"`
	// AlertsUnreadable distinguishes "no alerts" from "alerts could not be
	// read". Both used to print nothing, so a lost alert was invisible.
	AlertsUnreadable bool   `json:"alertsUnreadable,omitempty"`
	AlertsError      string `json:"alertsError,omitempty"`
	LastLogLine      string `json:"lastLogLine,omitempty"`
}

// alertErrText renders an alerts read failure for the report. It returns "" so
// the healthy path keeps its existing JSON and text output byte-for-byte.
func alertErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Status reads the units, config and state without writing.
func Status(ctx context.Context, root string) (StatusReport, error) {
	// Alerts are loaded before anything that can fail so `idleleo status` still
	// surfaces a failed renewal even when metadata or config is unreadable.
	alerts, alertsErr := Alerts(root)
	cfg, err := loadConfig(root)
	if err != nil {
		return StatusReport{SchemaVersion: SchemaVersion, Alerts: alerts, AlertsUnreadable: alertsErr != nil, AlertsError: alertErrText(alertsErr)}, err
	}
	report := StatusReport{
		SchemaVersion: SchemaVersion, IntervalSeconds: cfg.IntervalSeconds,
		Jobs: cfg.Jobs, DegradedJobs: DegradedJobs, Alerts: alerts,
		AlertsUnreadable: alertsErr != nil, AlertsError: alertErrText(alertsErr),
		UnitPath: path(root, UnitRel), TimerPath: path(root, TimerRel),
		Timer: "not-installed", State: State{SchemaVersion: SchemaVersion, Jobs: map[string]JobState{}},
	}
	if ch, err := release.LoadChannel(root); err == nil && ch.ManifestURL != "" {
		report.ReleaseChannel = true
	}
	fi, err := os.Stat(report.TimerPath)
	if err == nil && fi.Mode().IsRegular() {
		report.Installed = true
		report.Timer = "installed"
	}
	if report.Installed && root == "/" {
		res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-active", "idleleo-schedule.timer"}, Timeout: 10 * time.Second})
		if err == nil {
			report.Timer = strings.TrimSpace(res.Stdout)
			if res.ExitCode != 0 && report.Timer == "" {
				report.Timer = fmt.Sprintf("exit-%d", res.ExitCode)
			}
		}
	}
	if b, err := os.ReadFile(path(root, StateRel)); err == nil {
		_ = json.Unmarshal(b, &report.State)
		if report.State.Jobs == nil {
			report.State.Jobs = map[string]JobState{}
		}
	}
	if b, err := os.ReadFile(path(root, LogRel)); err == nil {
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(lines) > 0 && lines[0] != "" {
			report.LastLogLine = lines[len(lines)-1]
		}
	}
	return report, nil
}

// SummaryLines renders a compact status for the CLI.
func (r StatusReport) SummaryLines() []string {
	out := []string{}
	if r.AlertsUnreadable {
		out = append(out, "alerts=unreadable "+r.AlertsError)
	}
	for _, a := range r.Alerts {
		out = append(out, fmt.Sprintf("alert=%s result=%s at=%s %s", a.Job, a.Result, a.At, a.Detail))
	}
	out = append(out,
		fmt.Sprintf("installed=%t interval=%ds timer=%s releaseChannel=%t", r.Installed, r.IntervalSeconds, r.Timer, r.ReleaseChannel),
		"jobs="+strings.Join(r.Jobs, ","),
	)
	for _, d := range r.DegradedJobs {
		out = append(out, "degraded="+d)
	}
	names := make([]string, 0, len(r.State.Jobs))
	for name := range r.State.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		js := r.State.Jobs[name]
		out = append(out, fmt.Sprintf("last[%s]=%s at %s %s", name, js.Result, js.LastRun, js.Detail))
	}
	if r.LastLogLine != "" {
		out = append(out, "log="+r.LastLogLine)
	}
	return out
}

func appendLine(p, line string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Remove the temp file on every failure path; after a successful rename
	// this is a harmless ENOENT.
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
