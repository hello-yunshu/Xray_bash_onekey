// Package release implements the Go self-update channel that replaces the
// legacy Bash auto_update.sh cron job.
//
// The channel is deliberately isolated from the Bash release channel: a Go
// manifest is only accepted when its channel field is exactly "go", and the
// version string is never a Bash v3.x tag. An installation with no channel
// configured stays on the explicit degraded path instead of guessing a URL.
package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const (
	// ChannelRel is the channel configuration owned by the Go manager.
	ChannelRel = "etc/idleleo/release/channel.json"
	// StateRel records the last successfully applied release.
	StateRel = "var/lib/idleleo/release/state.json"
	// DefaultInstallRel is where packaging/install.sh puts the Go binary.
	DefaultInstallRel = "opt/idleleo/bin/idleleo"

	SchemaVersion   = 1
	ChannelName     = "go"
	MaxManifestSize = 1 << 20
	MaxAssetSize    = 64 << 20
	HealthTimeout   = 15 * time.Second
)

var (
	// ErrNotConfigured means no release channel is configured on this host.
	ErrNotConfigured = errors.New("no Go release channel is configured")
	// ErrDowngrade means the manifest version is older than the installed one.
	ErrDowngrade = errors.New("release manifest is older than the installed version")
	// ErrRecoveryRequired means the old binary could not be restored after a
	// failed health check and a human must intervene.
	ErrRecoveryRequired = errors.New("RECOVERY_REQUIRED: previous idleleo binary could not be restored")
)

var (
	// writeStateFile and healthCheckBinary are variables so tests can inject a
	// failed state commit or a controlled health result.
	writeStateFile    = writeState
	healthCheckBinary = healthCheck
	// platformKey defaults to the running platform; tests may pin it so the
	// manifest contract can be exercised outside Linux.
	platformKey = Platform
)

// Channel is the persisted `update configure` result.
type Channel struct {
	SchemaVersion int    `json:"schemaVersion"`
	Channel       string `json:"channel"`
	ManifestURL   string `json:"manifestUrl"`
	InstallPath   string `json:"installPath,omitempty"`
}

// Asset is one architecture-pinned release binary.
type Asset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	URL    string `json:"url,omitempty"`
}

// Manifest is the published Go release manifest (assets/go/manifest.json).
type Manifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	Channel       string           `json:"channel"`
	Version       string           `json:"version"`
	Assets        map[string]Asset `json:"assets"`
}

// State is the last applied release record.
type State struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	SHA256        string `json:"sha256"`
	AppliedAt     string `json:"appliedAt"`
}

var versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+([-+].*)?$`)

// Platform returns the manifest key for the running binary.
func Platform() string { return runtime.GOOS + "-" + runtime.GOARCH }

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func joinRoot(root, rel string) (string, error) {
	p, err := host.NewPaths(root)
	if err != nil {
		return "", err
	}
	return p.Join(rel, true)
}

// LoadChannel reads the configured channel. A missing file is reported as ErrNotConfigured.
func LoadChannel(root string) (Channel, error) {
	p, err := joinRoot(root, ChannelRel)
	if err != nil {
		return Channel{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return Channel{}, ErrNotConfigured
		}
		return Channel{}, err
	}
	var ch Channel
	if err := json.Unmarshal(b, &ch); err != nil {
		return Channel{}, fmt.Errorf("release channel config is not valid JSON: %w", err)
	}
	if ch.SchemaVersion != SchemaVersion {
		return Channel{}, fmt.Errorf("release channel schema %d is not supported", ch.SchemaVersion)
	}
	if ch.Channel != ChannelName {
		return Channel{}, fmt.Errorf("release channel %q is not the Go channel", ch.Channel)
	}
	if err := validateManifestURL(ch.ManifestURL); err != nil {
		return Channel{}, err
	}
	if ch.InstallPath == "" {
		ch.InstallPath = DefaultInstallRel
	}
	return ch, nil
}

// Configure writes the channel config. It never downloads or installs.
func Configure(ctx context.Context, root, manifestURL, installPath string) (Channel, error) {
	if err := validateManifestURL(manifestURL); err != nil {
		return Channel{}, err
	}
	if installPath == "" {
		installPath = DefaultInstallRel
	}
	if _, err := joinRoot(root, installPath); err != nil {
		return Channel{}, err
	}
	ch := Channel{SchemaVersion: SchemaVersion, Channel: ChannelName, ManifestURL: manifestURL, InstallPath: installPath}
	p, err := joinRoot(root, ChannelRel)
	if err != nil {
		return Channel{}, err
	}
	b, err := json.MarshalIndent(ch, "", "  ")
	if err != nil {
		return Channel{}, err
	}
	if err := writeAtomic(p, append(b, '\n'), 0o640); err != nil {
		return Channel{}, err
	}
	return ch, nil
}

func validateManifestURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("manifest URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("manifest URL is invalid: %w", err)
	}
	if u.User != nil {
		return errors.New("manifest URL must not contain credentials")
	}
	if u.Host == "" {
		return errors.New("manifest URL has no host")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		// Plain HTTP is only for an explicitly isolated local test origin.
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("manifest URL %q must use HTTPS; plain HTTP is only allowed for loopback test origins", raw)
	default:
		return fmt.Errorf("manifest URL scheme %q is not allowed", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseManifest strictly validates the release contract. A manifest that
// claims another channel or an invalid digest is rejected before any download.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if m.SchemaVersion != SchemaVersion {
		return Manifest{}, fmt.Errorf("manifest schema %d is not supported", m.SchemaVersion)
	}
	if m.Channel != ChannelName {
		return Manifest{}, fmt.Errorf("manifest channel %q is not the Go channel", m.Channel)
	}
	if !versionPattern.MatchString(m.Version) {
		return Manifest{}, fmt.Errorf("manifest version %q is not a Go release version", m.Version)
	}
	if len(m.Assets) == 0 {
		return Manifest{}, errors.New("manifest has no assets")
	}
	for key, a := range m.Assets {
		if key != "linux-amd64" && key != "linux-arm64" {
			return Manifest{}, fmt.Errorf("manifest asset key %q is not a supported platform", key)
		}
		if a.Name == "" {
			return Manifest{}, fmt.Errorf("manifest asset %q has no name", key)
		}
		if len(a.SHA256) != 64 || !isLowerHex(a.SHA256) {
			return Manifest{}, fmt.Errorf("manifest asset %q has an invalid sha256", key)
		}
		if a.Size <= 0 || a.Size > MaxAssetSize {
			return Manifest{}, fmt.Errorf("manifest asset %q size %d is out of range", key, a.Size)
		}
	}
	return m, nil
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// CheckReport is the read-only `update check` result.
type CheckReport struct {
	SchemaVersion  int    `json:"schemaVersion"`
	ManifestURL    string `json:"manifestUrl"`
	Platform       string `json:"platform"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	LatestVersion  string `json:"latestVersion"`
	State          string `json:"state"`
	Asset          Asset  `json:"asset"`
	Verified       bool   `json:"verified"`
	Detail         string `json:"detail,omitempty"`
}

// Check fetches and validates the manifest, then compares versions and verifies
// the downloaded asset digest. It never installs.
func Check(ctx context.Context, root, manifestURL string) (CheckReport, error) {
	rep := CheckReport{SchemaVersion: SchemaVersion, ManifestURL: manifestURL, Platform: Platform()}
	if manifestURL == "" {
		ch, err := LoadChannel(root)
		if err != nil {
			return rep, err
		}
		rep.ManifestURL = ch.ManifestURL
		manifestURL = ch.ManifestURL
	}
	if err := validateManifestURL(manifestURL); err != nil {
		return rep, err
	}
	m, err := fetchManifest(ctx, manifestURL)
	if err != nil {
		return rep, err
	}
	rep.LatestVersion = m.Version
	asset, ok := m.Assets[platformKey()]
	if !ok {
		return rep, fmt.Errorf("manifest has no asset for platform %s", platformKey())
	}
	rep.Asset = asset
	st, _ := ReadState(root)
	rep.CurrentVersion = st.Version

	cmp := compareVersions(rep.CurrentVersion, m.Version)
	switch {
	case rep.CurrentVersion == "":
		rep.State = "available"
		rep.Detail = "no applied Go release recorded; the channel can install this version"
	case cmp > 0:
		rep.State = "refused-downgrade"
		rep.Detail = fmt.Sprintf("installed version %s is newer than manifest version %s; no downgrade", rep.CurrentVersion, m.Version)
		return rep, ErrDowngrade
	case cmp == 0:
		rep.State = "up-to-date"
	default:
		rep.State = "available"
	}
	if err := verifyAssetDigest(ctx, manifestURL, asset); err != nil {
		return rep, err
	}
	rep.Verified = true
	return rep, nil
}

func fetchManifest(ctx context.Context, manifestURL string) (Manifest, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return Manifest{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("manifest origin returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifestSize+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest download interrupted: %w", err)
	}
	if len(b) > MaxManifestSize {
		return Manifest{}, errors.New("manifest is larger than the 1MiB limit")
	}
	return ParseManifest(b)
}

func assetURL(manifestURL string, a Asset) (string, error) {
	base, err := url.Parse(manifestURL)
	if err != nil {
		return "", err
	}
	raw := a.URL
	if raw == "" {
		raw = a.Name
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("asset URL %q is invalid: %w", raw, err)
	}
	u := base.ResolveReference(ref)
	if u.User != nil {
		return "", errors.New("asset URL must not contain credentials")
	}
	// An asset must stay on the trusted manifest origin. Without this a
	// compromised manifest could point the download at any third-party host
	// and the manifest's own digest would be the only (self-attested) check.
	if u.Hostname() != base.Hostname() {
		return "", fmt.Errorf("asset URL host %q is not the trusted manifest host %q", u.Hostname(), base.Hostname())
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(base.Hostname()) {
			return "", fmt.Errorf("asset URL %q must use HTTPS", u.String())
		}
	default:
		return "", fmt.Errorf("asset URL scheme %q is not allowed", u.Scheme)
	}
	return u.String(), nil
}

// download fetches one asset with a hard size limit. A truncated body is an
// error: the caller must never install a partial binary.
func download(ctx context.Context, assetURL string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: 300 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asset download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asset origin returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("asset download interrupted: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, errors.New("asset is larger than the allowed limit")
	}
	if resp.ContentLength >= 0 && int64(len(b)) != resp.ContentLength {
		return nil, fmt.Errorf("asset download interrupted: got %d of %d bytes", len(b), resp.ContentLength)
	}
	if len(b) == 0 {
		return nil, errors.New("asset origin returned an empty body")
	}
	return b, nil
}

func verifyAssetDigest(ctx context.Context, manifestURL string, a Asset) error {
	u, err := assetURL(manifestURL, a)
	if err != nil {
		return err
	}
	b, err := download(ctx, u, MaxAssetSize)
	if err != nil {
		return err
	}
	if int64(len(b)) != a.Size {
		return fmt.Errorf("asset size mismatch: got %d want %d bytes", len(b), a.Size)
	}
	if got := hashBytes(b); got != a.SHA256 {
		return fmt.Errorf("asset sha256 mismatch: got %s want %s", got, a.SHA256)
	}
	return nil
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// verifyELF rejects non-Linux binaries and a wrong CPU architecture before the
// binary can replace a working manager.
func verifyELF(b []byte, goarch string) error {
	if len(b) < 64 {
		return errors.New("asset is too small to be an ELF binary")
	}
	if b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' {
		return errors.New("asset is not an ELF binary")
	}
	if b[4] != 2 {
		return errors.New("asset is not a 64-bit ELF binary")
	}
	if b[5] != 1 {
		return errors.New("asset is not a little-endian ELF binary")
	}
	machine := uint16(b[18]) | uint16(b[19])<<8
	want := map[string]uint16{"amd64": 62, "arm64": 183}[goarch]
	if want == 0 {
		return fmt.Errorf("unsupported GOARCH %q", goarch)
	}
	if machine != want {
		return fmt.Errorf("asset ELF machine %d does not match GOARCH %s (want %d)", machine, goarch, want)
	}
	return nil
}

// ReadState returns the last applied record. A missing file is not an error.
func ReadState(root string) (State, error) {
	p, err := joinRoot(root, StateRel)
	if err != nil {
		return State{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, nil
		}
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("release state is not valid JSON: %w", err)
	}
	return st, nil
}

func writeState(root string, st State) error {
	p, err := joinRoot(root, StateRel)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(p, append(b, '\n'), 0o640)
}

// ApplyReport is the machine-readable `update apply` result.
type ApplyReport struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Action          string `json:"action"`
	ManifestURL     string `json:"manifestUrl"`
	Platform        string `json:"platform"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	NewVersion      string `json:"newVersion,omitempty"`
	PreviousSHA256  string `json:"previousSha256,omitempty"`
	NewSHA256       string `json:"newSha256,omitempty"`
	InstallPath     string `json:"installPath"`
	BackupPath      string `json:"backupPath,omitempty"`
	HealthOutput    string `json:"healthOutput,omitempty"`
}

// Apply performs a verified install. The old binary stays in place until the
// new one has been downloaded, digest-checked, ELF-checked and health-checked;
// a failed health check restores the backup. held is an optional already-held
// update lock (the scheduler owns one for a whole run); nil makes Apply take
// the lock itself.
func Apply(ctx context.Context, root, manifestURL string, held *host.UpdateLock) (ApplyReport, error) {
	rep := ApplyReport{SchemaVersion: SchemaVersion, ManifestURL: manifestURL, Platform: Platform()}
	ch, err := LoadChannel(root)
	if err != nil {
		return rep, err
	}
	if manifestURL == "" {
		manifestURL = ch.ManifestURL
		rep.ManifestURL = manifestURL
	}
	if err := validateManifestURL(manifestURL); err != nil {
		return rep, err
	}
	installRel := ch.InstallPath
	if installRel == "" {
		installRel = DefaultInstallRel
	}
	installPath, err := joinRoot(root, installRel)
	if err != nil {
		return rep, err
	}
	rep.InstallPath = installPath

	if held == nil {
		lock, err := host.AcquireUpdate(filepath.Join(root, "run/lock/idleleo-update.lock"))
		if err != nil {
			if errors.Is(err, host.ErrLocked) {
				return rep, fmt.Errorf("another idleleo update holds the update lock: %w", err)
			}
			return rep, err
		}
		defer lock.Release()
	}

	m, err := fetchManifest(ctx, manifestURL)
	if err != nil {
		return rep, err
	}
	asset, ok := m.Assets[platformKey()]
	if !ok {
		return rep, fmt.Errorf("manifest has no asset for platform %s", platformKey())
	}
	st, err := ReadState(root)
	if err != nil {
		return rep, err
	}
	rep.PreviousVersion = st.Version

	cmp := compareVersions(st.Version, m.Version)
	if cmp > 0 {
		rep.Action = "refused-downgrade"
		return rep, fmt.Errorf("%w: installed %s, manifest %s", ErrDowngrade, st.Version, m.Version)
	}
	if cmp == 0 && st.SHA256 == asset.SHA256 {
		rep.Action = "up-to-date"
		rep.NewVersion = m.Version
		return rep, nil
	}

	u, err := assetURL(manifestURL, asset)
	if err != nil {
		return rep, err
	}
	b, err := download(ctx, u, MaxAssetSize)
	if err != nil {
		return rep, err
	}
	if int64(len(b)) != asset.Size {
		return rep, fmt.Errorf("asset size mismatch: got %d want %d bytes", len(b), asset.Size)
	}
	if got := hashBytes(b); got != asset.SHA256 {
		return rep, fmt.Errorf("asset sha256 mismatch: got %s want %s", got, asset.SHA256)
	}
	if err := verifyELF(b, runtime.GOARCH); err != nil {
		return rep, err
	}

	if err := os.MkdirAll(filepath.Dir(installPath), 0o755); err != nil {
		return rep, err
	}
	if fi, err := os.Lstat(installPath); err == nil && !fi.Mode().IsRegular() {
		return rep, fmt.Errorf("install target is not a regular file: %s", installPath)
	} else if err != nil && !os.IsNotExist(err) {
		return rep, err
	}

	backupPath := installPath + ".previous"
	hadOld := fileExists(installPath)
	if hadOld {
		old, err := os.ReadFile(installPath)
		if err != nil {
			return rep, err
		}
		rep.PreviousSHA256 = hashBytes(old)
		if err := writeAtomic(backupPath, old, 0o755); err != nil {
			return rep, err
		}
	}
	rep.BackupPath = backupPath

	if err := writeAtomic(installPath, b, 0o755); err != nil {
		return rep, err
	}
	rep.NewVersion = m.Version
	rep.NewSHA256 = asset.SHA256

	out, err := healthCheckBinary(ctx, installPath, m.Version)
	rep.HealthOutput = out
	if err != nil {
		restoreErr := restore(installPath, backupPath, hadOld)
		if restoreErr != nil {
			rep.Action = "recovery-required"
			return rep, fmt.Errorf("%w: health check failed (%v); restore failed: %v", ErrRecoveryRequired, err, restoreErr)
		}
		rep.Action = "rolled-back"
		return rep, fmt.Errorf("new binary failed its health check and the previous binary was restored: %w", err)
	}

	final := State{SchemaVersion: SchemaVersion, Version: m.Version, SHA256: asset.SHA256, AppliedAt: now()}
	if err := writeStateFile(root, final); err != nil {
		// The binary is already replaced. Restore the previous binary so the
		// on-disk state and the recorded release cannot disagree; if that also
		// fails, stop with an explicit recovery requirement.
		restoreErr := restore(installPath, backupPath, hadOld)
		if restoreErr != nil {
			rep.Action = "recovery-required"
			return rep, fmt.Errorf("%w: release state could not be recorded (%v); restore failed: %v", ErrRecoveryRequired, err, restoreErr)
		}
		rep.Action = "rolled-back"
		return rep, fmt.Errorf("release state could not be recorded and the previous binary was restored: %w", err)
	}
	rep.Action = "applied"
	return rep, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func restore(installPath, backupPath string, hadOld bool) error {
	if !hadOld {
		// No previous binary existed, so a half-installed new binary is not
		// a working manager. Remove it and report success of the restore.
		if err := os.Remove(installPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncDir(filepath.Dir(installPath))
	}
	old, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return writeAtomic(installPath, old, 0o755)
}

func healthCheck(ctx context.Context, installPath, expectedVersion string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, HealthTimeout)
	defer cancel()
	res, err := host.Run(ctx, host.ExecSpec{Path: installPath, Args: []string{"--version"}, Timeout: HealthTimeout})
	if err != nil {
		return "", err
	}
	out := strings.TrimSpace(res.Stdout)
	if res.ExitCode != 0 {
		return out, fmt.Errorf("health check exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	if !strings.Contains(out, "idleleo") || !strings.Contains(out, expectedVersion) {
		return out, fmt.Errorf("health check output %q does not identify idleleo %s", out, expectedVersion)
	}
	return out, nil
}

// compareVersions compares numeric x.y.z prefixes. Unparsable values sort
// below valid ones, so an unknown current version never blocks an upgrade but
// a valid older manifest still never replaces a valid newer installation.
func compareVersions(a, b string) int {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	switch {
	case !aok && !bok:
		return strings.Compare(a, b)
	case !aok:
		return -1
	case !bok:
		return 1
	}
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			if av[i] < bv[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	if v == "" || !versionPattern.MatchString(v) {
		return out, false
	}
	core := v
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// AutoReport is the scheduler-facing outcome of one auto-update tick.
type AutoReport struct {
	Configured bool   `json:"configured"`
	Action     string `json:"action"`
	Detail     string `json:"detail"`
}

// AutoUpdate runs one scheduled update tick. With no configured channel it
// returns a clear degradation instead of silently doing nothing.
func AutoUpdate(ctx context.Context, root string, held *host.UpdateLock) AutoReport {
	ch, err := LoadChannel(root)
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return AutoReport{Configured: false, Action: "degraded",
				Detail: "no Go release channel is configured; no automatic update runs (explicit product degradation, see `idleleo update configure`)"}
		}
		return AutoReport{Configured: false, Action: "failed", Detail: err.Error()}
	}
	rep, err := Apply(ctx, root, ch.ManifestURL, held)
	if err != nil {
		if errors.Is(err, ErrDowngrade) {
			return AutoReport{Configured: true, Action: "skipped", Detail: err.Error()}
		}
		return AutoReport{Configured: true, Action: "failed", Detail: err.Error()}
	}
	switch rep.Action {
	case "applied":
		return AutoReport{Configured: true, Action: "ok",
			Detail: fmt.Sprintf("updated %s -> %s sha256=%s health=%s", rep.PreviousVersion, rep.NewVersion, rep.NewSHA256, rep.HealthOutput)}
	case "up-to-date":
		return AutoReport{Configured: true, Action: "ok", Detail: "already at " + rep.NewVersion}
	}
	return AutoReport{Configured: true, Action: "ok", Detail: rep.Action}
}

// StatusReport is the read-only `update status` view.
type StatusReport struct {
	SchemaVersion  int    `json:"schemaVersion"`
	Configured     bool   `json:"configured"`
	Channel        string `json:"channel,omitempty"`
	ManifestURL    string `json:"manifestUrl,omitempty"`
	InstallPath    string `json:"installPath,omitempty"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	CurrentSHA256  string `json:"currentSha256,omitempty"`
	AppliedAt      string `json:"appliedAt,omitempty"`
}

// Status reads the channel and state without network or writes.
func Status(root string) (StatusReport, error) {
	rep := StatusReport{SchemaVersion: SchemaVersion}
	ch, err := LoadChannel(root)
	if err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return rep, nil
		}
		return rep, err
	}
	rep.Configured, rep.Channel, rep.ManifestURL = true, ch.Channel, ch.ManifestURL
	rep.InstallPath = ch.InstallPath
	st, err := ReadState(root)
	if err != nil {
		return rep, err
	}
	rep.CurrentVersion, rep.CurrentSHA256, rep.AppliedAt = st.Version, st.SHA256, st.AppliedAt
	return rep, nil
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
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
