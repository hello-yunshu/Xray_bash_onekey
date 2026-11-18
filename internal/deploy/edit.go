package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

const (
	editBackupRel = "etc/idleleo/backup"
	editBackupMax = 20
)

// EditSpec is one `xray config edit` request against a managed install.
type EditSpec struct {
	Root                 string
	ConfigPath           string
	Request              xraycfg.EditRequest
	NoRestart            bool
	NoProbe              bool
	DryRun               bool
	AllowContainerWrites bool
	// RotationConfirmed is set only after the CLI collected the typed phrase.
	// A y/N answer is not enough for a private-key rotation.
	RotationConfirmed bool
}

// EditReport describes what the edit changed and where the backup lives.
type EditReport struct {
	Mode          string   `json:"mode"`
	Transport     string   `json:"transport"`
	Changed       []string `json:"changed"`
	Diff          []string `json:"diff,omitempty"`
	ConfigPath    string   `json:"configPath"`
	OldSHA256     string   `json:"oldSha256"`
	NewSHA256     string   `json:"newSha256,omitempty"`
	BackupDir     string   `json:"backupDir,omitempty"`
	NoChanges     bool     `json:"noChanges"`
	NoRestart     bool     `json:"noRestart"`
	NoProbe       bool     `json:"noProbe,omitempty"`
	DryRun        bool     `json:"dryRun"`
	NginxUpdated  bool     `json:"nginxUpdated"`
	NginxVerified bool     `json:"nginxVerified"`
	ShareURI      string   `json:"shareUri,omitempty"`
	OriginTarget  string   `json:"originTarget,omitempty"`
	OriginProbe   string   `json:"originProbe,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	CertFile      string   `json:"certFile,omitempty"`
	CertKeyFile   string   `json:"certKeyFile,omitempty"`
	CertNotAfter  string   `json:"certNotAfter,omitempty"`
	CertSANs      []string `json:"certSans,omitempty"`
	TLSProbe      string   `json:"tlsProbe,omitempty"`
	TLSServerName string   `json:"tlsServerName,omitempty"`
	TLSVersion    string   `json:"tlsVersion,omitempty"`
	TLSTrusted    bool     `json:"tlsSystemTrusted"`
	// ScheduleUpdated records whether the cert-renew target in jobs.json was
	// moved with the edit; no re-issue ever happens here.
	ScheduleUpdated bool     `json:"scheduleUpdated,omitempty"`
	SchedulePath    string   `json:"schedulePath,omitempty"`
	Disconnect      bool     `json:"disconnect"`
	Warnings        []string `json:"warnings"`
	// Reality credential evidence. ShortIDLinks is read-only output; OldShareURI
	// is what a rollback must bring back; FailurePoint names the failed stage
	// (reality-handshake) so the E2E assertion can key on it.
	ShortIDs             []string              `json:"shortIds,omitempty"`
	ShortIDLinks         []xraycfg.ShortIDLink `json:"shortIdLinks,omitempty"`
	OldShareURI          string                `json:"oldShareUri,omitempty"`
	LinkPrefsUpdated     bool                  `json:"linkPrefsUpdated,omitempty"`
	LinkFingerprint      string                `json:"linkFingerprint,omitempty"`
	LinkSpiderX          string                `json:"linkSpiderX,omitempty"`
	PrivateKeyRotated    bool                  `json:"privateKeyRotated,omitempty"`
	RealityProbe         string                `json:"realityProbe,omitempty"`
	RealityRollbackProbe string                `json:"realityRollbackProbe,omitempty"`
	FailurePoint         string                `json:"failurePoint,omitempty"`
	UpstreamSHA256       string                `json:"upstreamSha256,omitempty"`
	UpstreamUnchanged    bool                  `json:"upstreamUnchanged"`
	// BlockPreserved/BlockRuleCount report that traffic blocking was reapplied
	// and how many owned rules came back.
	BlockPreserved bool `json:"blockPreserved,omitempty"`
	BlockRuleCount int  `json:"blockRuleCount,omitempty"`
}

// RelayEditSpec is one `xray config edit` request against a managed relay.
type RelayEditSpec struct {
	Root                 string
	Target               string
	ListenPort           int
	NoRestart            bool
	DryRun               bool
	AllowContainerWrites bool
}

// RelayEditReport describes the relay patch.
type RelayEditReport struct {
	Target        string `json:"target"`
	ListenPort    int    `json:"listenPort"`
	BackupDir     string `json:"backupDir,omitempty"`
	NoChanges     bool   `json:"noChanges"`
	NoRestart     bool   `json:"noRestart"`
	DryRun        bool   `json:"dryRun"`
	NginxVerified bool   `json:"nginxVerified"`
}

// runXrayTest validates a candidate file with the installed binary. It is a
// seam so sandbox tests can inject a verdict without a real Xray. env carries
// XRAY_LOCATION_ASSET when the candidate uses GeoData rules.
var runXrayTest = func(ctx context.Context, bin, candidate string, env []string) error {
	res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"-test", "-config", candidate}, Env: env, Timeout: 60 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("xray -test rejected the candidate (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// EditConfig applies a patch to the managed runtime config. Nothing is written
// until the candidate passes `xray -test` (and `nginx -t` when a managed front
// exists); a failure after that point restores both trees and the previous
// service state.
func EditConfig(ctx context.Context, spec EditSpec) (EditReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return EditReport{}, err
	}
	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return EditReport{}, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return EditReport{}, err
		}
		defer lock.Release()
	}
	configPath, err := store.ResolveRuntimePath(paths, spec.ConfigPath)
	if err != nil {
		return EditReport{}, err
	}
	if err := requireNativeInstall(paths); err != nil {
		return EditReport{}, err
	}
	raw, _, err := store.ReadRegular(configPath, "runtime config")
	if err != nil {
		return EditReport{}, err
	}
	base, nginxDir, err := editBase(paths, raw)
	if err != nil {
		return EditReport{}, err
	}
	// shareLinkOnly preferences decorate the share URI only. They are loaded
	// here so a key/shortId edit keeps the operator's fp/spx in the new link.
	if meta, _, metaErr := store.LoadMetadata(paths); metaErr == nil && meta.ShareLinkOnly != nil {
		base.LinkFingerprint = meta.ShareLinkOnly.Fingerprint
		base.LinkSpiderX = meta.ShareLinkOnly.SpiderX
	}
	// Traffic blocking lives outside the generator. Loading it here is what
	// keeps `config edit` from silently deleting the block rules.
	if blockState, ok, blockErr := loadBlockState(paths); blockErr != nil {
		return EditReport{}, blockErr
	} else if ok {
		base.RoutingBlock = &blockState
	}
	g, res, err := xraycfg.EditRuntime(raw, base, spec.Request)
	if err != nil {
		return EditReport{}, err
	}
	report := EditReport{
		Mode: res.Mode, Transport: res.Transport, Changed: res.Changed, Diff: res.Diff,
		ConfigPath: configPath, OldSHA256: store.HashBytes(raw),
		NoChanges: res.NoChanges, NoRestart: spec.NoRestart, NoProbe: spec.NoProbe, DryRun: spec.DryRun,
		Disconnect: res.Disconnect, ShareURI: g.ShareURI,
		Domain: res.Domain, CertFile: res.CertFile, CertKeyFile: res.KeyFile,
		ShortIDs: res.ShortIDs, ShortIDLinks: res.ShortIDLinks,
		OldShareURI: res.OldShareURI, LinkFingerprint: res.LinkFingerprint, LinkSpiderX: res.LinkSpiderX,
		PrivateKeyRotated: res.PrivateKeyRotated,
		BlockPreserved:    res.BlockPreserved, BlockRuleCount: res.BlockRuleCount,
	}
	if spec.Request.ListShortIDs {
		// Read-only: the runtime config and the front are untouched.
		report.NoChanges = true
		return report, nil
	}
	runtimeChanged := !bytes.Equal(raw, g.Config)
	// A link-preference change is metadata-only: no runtime rewrite, no restart
	// and no Nginx reload. The new link is the only output.
	if res.LinkPrefsChanged && !runtimeChanged {
		updateMetadataAfterEdit(paths, res, raw, &report)
		report.LinkPrefsUpdated = true
		report.NewSHA256 = report.OldSHA256
		return report, nil
	}
	if res.NoChanges {
		return report, nil
	}
	if spec.Request.RotatePrivateKey && !spec.DryRun && !spec.RotationConfirmed {
		return report, fmt.Errorf("private-key rotation requires the typed confirmation phrase")
	}
	report.NewSHA256 = store.HashBytes(g.Config)
	if err := probeOriginIfRequested(ctx, spec.Request, res, &report, spec.NoProbe); err != nil {
		return report, err
	}

	// The TLS domain and certificate pair own no runtime field but do own the
	// front. Validate the pair against the domain before anything is written:
	// a mismatch would otherwise only surface as failed handshakes. Direct TLS
	// keeps the pair in the runtime config, so it takes the same validation.
	directTLS := res.Mode == xraycfg.ModeTLSDirect
	tlsTouched := (res.Mode == xraycfg.ModeTLS || directTLS) && touchedTLS(res.Changed)
	var pair tlsPairInfo
	if tlsTouched {
		info, warns, err := inspectTLSPair(res.Domain, res.CertFile, res.KeyFile)
		if err != nil {
			return report, err
		}
		pair = info
		report.CertNotAfter = info.NotAfter.UTC().Format(time.RFC3339)
		report.CertSANs = info.SANs
		report.Warnings = append(report.Warnings, warns...)
	}
	if spec.DryRun {
		if tlsTouched {
			report.TLSProbe = "skipped: dry-run"
		}
		return report, nil
	}

	// Self-check the candidate before touching anything on disk.
	bin, err := paths.Join(binaryRel, false)
	if err != nil {
		return report, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(configPath), ".edit-candidate-*.json")
	if err != nil {
		return report, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(g.Config); err != nil {
		tmp.Close()
		return report, err
	}
	if err := tmp.Close(); err != nil {
		return report, err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return report, err
	}
	if err := runXrayTest(ctx, bin, tmpName, geodataEnv(paths.Root)); err != nil {
		return report, fmt.Errorf("%w; configuration was not changed", err)
	}

	schedulePath := ""
	if tlsTouched {
		if p, joinErr := paths.Join(schedule.ConfigRel, false); joinErr == nil {
			schedulePath = p
		}
	}
	// Back up the pair that is serving right now, not the one being installed:
	// the new files are user-owned and stay on disk, while the previous pair is
	// what a manual rollback needs.
	extras := editBackupExtras{CertFile: base.CertFile, KeyFile: base.KeyFile, ScheduleFile: schedulePath}
	if res.PrivateKeyRotated {
		extras.OldShareURI = res.OldShareURI
	}
	if !tlsTouched {
		extras.CertFile, extras.KeyFile, extras.ScheduleFile = "", "", ""
	}
	backupDir, err := writeEditBackup(paths, configPath, raw, nginxDir, res, extras)
	if err != nil {
		return report, err
	}
	report.BackupDir = backupDir

	configState, err := captureFile(configPath)
	if err != nil {
		return report, err
	}
	var scheduleState *fileState
	if schedulePath != "" {
		st, err := captureFile(schedulePath)
		if err != nil {
			return report, err
		}
		scheduleState = &st
	}
	// reality-balance edits are confined to the Xray Reality inbound: the
	// upstream tree is not regenerated, so its content hash must not move.
	frontDir := nginxDir
	if res.Mode == xraycfg.ModeRealityBalance {
		frontDir = ""
	}
	upstreamHash, _ := hashTree(nginxDir)
	report.UpstreamSHA256 = upstreamHash
	nginxSnap := []fileState{}
	if frontDir != "" {
		nginxSnap, err = snapshotRegularFiles(frontDir)
		if err != nil {
			return report, err
		}
	}
	realityProbe := func(uri string) error {
		report.RealityProbe = "skipped: --no-probe"
		switch {
		case spec.NoProbe:
			return nil
		case spec.NoRestart:
			report.RealityProbe = "skipped: --no-restart"
			return nil
		}
		addr := realityProbeAddress(res)
		if err := verifyRealityHandshake(ctx, spec.Root, uri, addr); err != nil {
			report.RealityProbe = "failed: " + err.Error()
			return err
		}
		report.RealityProbe = "ok: vless+reality handshake+request through " + addr
		return nil
	}
	var failAt func(point string, cause error) (EditReport, error)
	fail := func(cause error) (EditReport, error) { return failAt("", cause) }
	failAt = func(point string, cause error) (EditReport, error) {
		report.FailurePoint = point
		restoreErr := restoreEditState(ctx, spec, configState, nginxSnap, frontDir, scheduleState, runtimeChanged)
		// The rollback is only complete if the old credential still works. Run
		// the same real-client handshake with the pre-edit link.
		if point == "reality-handshake" && res.OldShareURI != "" && !spec.NoProbe && !spec.NoRestart {
			if probeErr := verifyRealityHandshake(ctx, spec.Root, res.OldShareURI,
				realityProbeAddress(res)); probeErr != nil {
				report.RealityRollbackProbe = "failed: " + probeErr.Error()
				restoreErr = joinRollbackErr(restoreErr, "old-link handshake probe", probeErr)
			} else {
				report.RealityRollbackProbe = "ok: old link still completes a vless+reality handshake+request"
			}
		}
		if restoreErr != nil {
			return report, fmt.Errorf("%w; rollback failed: %v", cause, restoreErr)
		}
		return report, fmt.Errorf("%w; previous configuration restored", cause)
	}

	if frontDir != "" {
		if err := writeNginxArtifacts(frontDir, &g); err != nil {
			return fail(err)
		}
		// Permissions + syntax check first. The reload waits until Xray is back
		// up so a structural edit never leaves the front pointing at a stopped
		// upstream.
		if err := nginx.Finalize(ctx, nginx.FinalizeSpec{Root: spec.Root, NoService: true}); err != nil {
			return fail(err)
		}
		report.NginxUpdated = true
		report.NginxVerified = true
	}
	if runtimeChanged {
		if err := writeFileAtomic(configPath, g.Config, configState.mode); err != nil {
			return fail(err)
		}
		if configState.uid >= 0 && configState.gid >= 0 {
			if err := chownFile(configPath, configState.uid, configState.gid); err != nil {
				return fail(err)
			}
		}
		if !spec.NoRestart {
			if err := service(ctx, "restart", "xray"); err != nil {
				return fail(err)
			}
			if state := waitActive(ctx); state != "active" {
				return fail(fmt.Errorf("xray did not become active after the edit (state %s)", state))
			}
		}
	}
	if frontDir != "" && !spec.NoRestart {
		if err := nginx.Finalize(ctx, nginx.FinalizeSpec{Root: spec.Root}); err != nil {
			return fail(err)
		}
	}
	// The upstream tree must be byte-identical after a balance edit: only the
	// Reality inbound may move.
	if nginxDir != "" {
		afterHash, _ := hashTree(nginxDir)
		report.UpstreamUnchanged = afterHash == upstreamHash
		if res.Mode == xraycfg.ModeRealityBalance && !report.UpstreamUnchanged {
			return fail(fmt.Errorf("reality-balance upstream tree changed (%s -> %s); the edit must only touch the Reality inbound",
				upstreamHash, afterHash))
		}
	} else {
		report.UpstreamUnchanged = true
	}
	if res.PrivateKeyRotated || res.RealityCredentialMoved {
		if err := realityProbe(g.ShareURI); err != nil {
			return failAt("reality-handshake", err)
		}
	}
	if tlsTouched && !directTLS {
		if schedulePath == "" {
			report.Warnings = append(report.Warnings,
				"no schedule config found; certificate renewal will keep using the old target until a schedule is installed")
		} else {
			updated, warns, err := schedule.SetCertTarget(spec.Root, res.Domain, res.CertFile, res.KeyFile)
			if err != nil {
				return fail(err)
			}
			report.ScheduleUpdated = updated
			report.SchedulePath = schedulePath
			report.Warnings = append(report.Warnings, warns...)
		}
		switch {
		case spec.NoProbe:
			report.TLSProbe = "skipped: --no-probe"
		case spec.NoRestart:
			report.TLSProbe = "skipped: --no-restart"
		case nginxDir == "":
			report.TLSProbe = "skipped: no managed front"
		default:
			if err := probeLocalTLS(ctx, &report, probeAddress(res.PublicPort), res.Domain, pair.LeafDER); err != nil {
				return fail(err)
			}
		}
	}
	if directTLS {
		// The pair lives in the runtime config and this tool does not manage its
		// renewal; say so instead of leaving a silent stale-cert path.
		report.Warnings = append(report.Warnings,
			"direct TLS certificate renewal is not managed by this tool")
		switch {
		case spec.NoProbe:
			report.TLSProbe = "skipped: --no-probe"
		case spec.NoRestart:
			report.TLSProbe = "skipped: --no-restart"
		default:
			if err := probeLocalTLS(ctx, &report, directProbeAddress(res), res.Domain, pair.LeafDER); err != nil {
				return fail(err)
			}
		}
	}
	report.NewSHA256 = store.HashBytes(g.Config)
	updateMetadataAfterEdit(paths, res, g.Config, &report)
	pruneEditBackups(paths)
	return report, nil
}

// directProbeAddress targets the listener the runtime config owns. A wildcard
// listener is reached through loopback.
func directProbeAddress(res xraycfg.EditResult) string {
	host := res.Listen
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(res.Port))
}

// realityProbeAddress is where the local client dials the Reality inbound. The
// direct mode owns its listener; every Nginx-fronted mode only exposes the
// public port. A wildcard listener is probed through loopback.
func realityProbeAddress(res xraycfg.EditResult) string {
	if res.Mode != xraycfg.ModeReality {
		return probeAddress(res.PublicPort)
	}
	host := res.Listen
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(res.Port))
}

// touchedTLS reports whether the patch moved a value only the front owns.
func touchedTLS(changed []string) bool {
	for _, field := range changed {
		switch field {
		case "domain", "cert-file", "cert-key-file":
			return true
		}
	}
	return false
}

// requireNativeInstall refuses a root the Bash manager still owns. Editing
// only the Go view would let the two managers diverge silently while this
// command reports success, which is worse than refusing.
func requireNativeInstall(paths host.Paths) error {
	if _, err := os.Stat(filepath.Join(paths.Root, paths.LegacyConfig())); err == nil {
		return fmt.Errorf("this root is managed by the Bash installer (%s); refusing to edit only the Go copy", paths.LegacyConfig())
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return fmt.Errorf("manager metadata is required before editing: %w", err)
	}
	if meta.Provenance != "" && meta.Provenance != "native" {
		return fmt.Errorf("this root was imported from Bash (provenance %q); refusing to edit only one manager's view", meta.Provenance)
	}
	return nil
}

// restoreEditState puts the config, schedule target and Nginx tree back and
// brings the old configuration back into service.
func restoreEditState(ctx context.Context, spec EditSpec, config fileState, nginxSnap []fileState, nginxDir string, scheduleState *fileState, runtimeChanged bool) error {
	restoreErr := config.restore()
	if scheduleState != nil {
		if err := scheduleState.restore(); err != nil {
			restoreErr = joinRollbackErr(restoreErr, "schedule restore", err)
		}
	}
	if nginxDir != "" {
		if err := restoreRegularFiles(nginxDir, nginxSnap); err != nil {
			restoreErr = joinRollbackErr(restoreErr, "nginx restore", err)
		}
	}
	if !spec.NoRestart && runtimeChanged {
		if err := service(ctx, "restart", "xray"); err != nil {
			restoreErr = joinRollbackErr(restoreErr, "xray restart", err)
		}
	}
	if nginxDir != "" {
		if err := nginx.Finalize(ctx, nginx.FinalizeSpec{Root: spec.Root, NoService: spec.NoRestart}); err != nil {
			restoreErr = joinRollbackErr(restoreErr, "nginx reload", err)
		}
	}
	return restoreErr
}

// joinRollbackErr keeps the first rollback failure readable instead of
// printing "<nil>" in front of a later one.
func joinRollbackErr(current error, step string, err error) error {
	if current == nil {
		return fmt.Errorf("%s: %w", step, err)
	}
	return fmt.Errorf("%v; %s: %w", current, step, err)
}

// editBase inspects the live install to decide which install mode the runtime
// config belongs to and where the managed front lives.
func editBase(paths host.Paths, raw []byte) (xraycfg.EditDefaults, string, error) {
	var probe struct {
		Inbounds []struct {
			Listen         string `json:"listen"`
			Port           int    `json:"port"`
			StreamSettings struct {
				Security    string `json:"security"`
				TLSSettings struct {
					ServerName   string `json:"serverName"`
					Certificates []struct {
						CertificateFile string `json:"certificateFile"`
						KeyFile         string `json:"keyFile"`
					} `json:"certificates"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return xraycfg.EditDefaults{}, "", fmt.Errorf("runtime config is not valid JSON: %w", err)
	}
	security := ""
	if len(probe.Inbounds) > 0 {
		security = probe.Inbounds[0].StreamSettings.Security
	}
	dir, dirErr := joinDir(paths, nginxDirRel)
	if dirErr != nil {
		return xraycfg.EditDefaults{}, "", dirErr
	}
	// A relay install owns only relay-stream.conf; its node config must be
	// edited through the relay patch so a stray regenerate cannot replace it.
	if _, statErr := os.Stat(filepath.Join(dir, "relay-stream.conf")); statErr == nil {
		return xraycfg.EditDefaults{}, "", fmt.Errorf("this installation is a relay; edit it with --relay-target/--relay-listen-port")
	}
	// A managed front always writes 00-xray.conf. Reality fronts keep a stream
	// block there; TLS fronts keep the public server block itself.
	if body, readErr := os.ReadFile(filepath.Join(dir, nginx.MainConf)); readErr == nil {
		conf := string(body)
		if strings.Contains(conf, "stream {") {
			// Metadata is authoritative: a balance primary with no added
			// backends renders the same tree as reality-nginx, so counting
			// upstream lines alone would misclassify it.
			balance := false
			if meta, _, metaErr := store.LoadMetadata(paths); metaErr == nil && meta.BalanceRole == "primary" {
				balance = true
			}
			if balance || realityBackends(dir) > 1 {
				// Balance only edits the Xray Reality inbound; the upstream tree
				// stays as-is and its content hash is asserted after the edit.
				return xraycfg.EditDefaults{Mode: xraycfg.ModeRealityBalance,
					PublicPort: listenPort(conf, 443)}, dir, nil
			}
			// reality-nginx and a balance primary with no extra backends render
			// the same Nginx tree, so a single local backend is the plain front.
			return xraycfg.EditDefaults{Mode: xraycfg.ModeRealityNginx, PublicPort: listenPort(conf, 443)}, dir, nil
		}
		certFile, keyFile := tlsPaths(conf)
		return xraycfg.EditDefaults{
			Mode: xraycfg.ModeTLS, PublicPort: listenPort(conf, 443), Domain: serverName(conf),
			CertFile: certFile, KeyFile: keyFile,
		}, dir, nil
	} else if !os.IsNotExist(readErr) {
		return xraycfg.EditDefaults{}, "", readErr
	}
	switch security {
	case "reality":
		return xraycfg.EditDefaults{Mode: xraycfg.ModeReality}, "", nil
	case "tls":
		// Direct TLS owns its own listener and certificate pair. Read the live
		// values so the patch compares against what is actually served.
		defaults := xraycfg.EditDefaults{Mode: xraycfg.ModeTLSDirect}
		for _, in := range probe.Inbounds {
			if in.StreamSettings.Security != "tls" {
				continue
			}
			defaults.Domain = in.StreamSettings.TLSSettings.ServerName
			if certs := in.StreamSettings.TLSSettings.Certificates; len(certs) > 0 {
				defaults.CertFile = certs[0].CertificateFile
				defaults.KeyFile = certs[0].KeyFile
			}
			defaults.PublicPort = in.Port
			break
		}
		return defaults, "", nil
	default:
		return xraycfg.EditDefaults{Mode: xraycfg.ModeNone}, "", nil
	}
}

var (
	serverNameRe = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	tlsCertRe    = regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^;]+);`)
	tlsKeyRe     = regexp.MustCompile(`(?m)^\s*ssl_certificate_key\s+([^;]+);`)
)

// tlsPaths reads the pair the live TLS front serves. An edit compares against
// these values, so a no-op request does not silently rewrite Nginx.
func tlsPaths(conf string) (string, string) {
	cert, key := "", ""
	if m := tlsCertRe.FindStringSubmatch(conf); len(m) > 1 {
		cert = strings.TrimSpace(m[1])
	}
	if m := tlsKeyRe.FindStringSubmatch(conf); len(m) > 1 {
		key = strings.TrimSpace(m[1])
	}
	return cert, key
}

// listenPort reads the first listen port from an Nginx fragment. Splitting the
// directive keeps bare ports ("listen 443 reuseport") and sockaddrs
// ("listen 127.0.0.1:9403", "listen [::]:443") both correct.
func listenPort(conf string, fallback int) int {
	for _, line := range strings.Split(conf, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "listen" {
			continue
		}
		value := fields[1]
		if strings.HasPrefix(value, "[") {
			if i := strings.LastIndex(value, "]:"); i >= 0 {
				value = value[i+2:]
			}
		} else if i := strings.LastIndex(value, ":"); i >= 0 {
			value = value[i+1:]
		}
		if port, err := strconv.Atoi(value); err == nil {
			return port
		}
	}
	return fallback
}

// serverName reads the first server_name token from an Nginx fragment.
func serverName(conf string) string {
	if m := serverNameRe.FindStringSubmatch(conf); len(m) > 1 {
		if fields := strings.Fields(m[1]); len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

// realityBackends counts the upstream server lines the Reality front loads.
// One line is the local Xray backend that reality-nginx always has; more means
// the operator added load-balancing backends, which this editor does not own.
func realityBackends(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 1
	}
	count := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".realityServers") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "server ") {
				count++
			}
		}
	}
	if count == 0 {
		return 1
	}
	return count
}

func snapshotRegularFiles(dir string) ([]fileState, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(names)
	return captureFiles(names)
}

func restoreRegularFiles(dir string, snap []fileState) error {
	known := map[string]bool{}
	for _, st := range snap {
		known[st.path] = true
		if err := st.restore(); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !known[path] {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// editBackupExtras are the files a front-owned TLS edit references and a
// manual rollback may need: the previous pair and the renewal target.
type editBackupExtras struct {
	CertFile     string
	KeyFile      string
	ScheduleFile string
	// OldShareURI is the pre-rotation link. It is written verbatim so a manual
	// rollback can verify the restored key with the same credential the
	// clients held.
	OldShareURI string
}

// writeEditBackup copies everything this edit may replace into an
// operator-visible directory so a manual recovery never depends on the tool.
func writeEditBackup(paths host.Paths, configPath string, raw []byte, nginxDir string, res xraycfg.EditResult, extras editBackupExtras) (string, error) {
	base, err := joinDir(paths, editBackupRel)
	if err != nil {
		return "", err
	}
	name := "edit-" + time.Now().UTC().Format("20060102T150405")
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(dir, "config.json"), raw, 0o600); err != nil {
		return "", err
	}
	// backfill copies one referenced file; a missing source is not an error
	// because the certificate may have been rotated away between probes.
	backfill := func(src, name string) (bool, error) {
		if src == "" {
			return false, nil
		}
		b, err := os.ReadFile(src)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if err := writeFileAtomic(filepath.Join(dir, name), b, 0o600); err != nil {
			return false, err
		}
		return true, nil
	}
	certSaved, err := backfill(extras.CertFile, "tls-cert.pem")
	if err != nil {
		return "", err
	}
	keySaved, err := backfill(extras.KeyFile, "tls-key.pem")
	if err != nil {
		return "", err
	}
	scheduleSaved, err := backfill(extras.ScheduleFile, "schedule-jobs.json")
	if err != nil {
		return "", err
	}
	if extras.OldShareURI != "" {
		if err := writeFileAtomic(filepath.Join(dir, "old-share-uri.txt"),
			[]byte(extras.OldShareURI+"\n"), 0o600); err != nil {
			return "", err
		}
	}
	if nginxDir != "" {
		entries, err := os.ReadDir(nginxDir)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(nginxDir, entry.Name()))
			if err != nil {
				return "", err
			}
			if err := writeFileAtomic(filepath.Join(dir, "nginx-"+entry.Name()), b, 0o600); err != nil {
				return "", err
			}
		}
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"configPath":     configPath,
		"changed":        res.Changed,
		"diff":           res.Diff,
		"createdAt":      time.Now().UTC().Format(time.RFC3339),
		"tlsDomain":      res.Domain,
		"tlsCertFile":    extras.CertFile,
		"tlsKeyFile":     extras.KeyFile,
		"tlsNewCertFile": res.CertFile,
		"tlsNewKeyFile":  res.KeyFile,
		"tlsCertSaved":   certSaved,
		"tlsKeySaved":    keySaved,
		"scheduleFile":   extras.ScheduleFile,
		"scheduleSaved":  scheduleSaved,
		"oldShareUri":    extras.OldShareURI,
	}, "", "  ")
	manifest = append(manifest, '\n')
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func pruneEditBackups(paths host.Paths) {
	base, err := joinDir(paths, editBackupRel)
	if err != nil {
		return
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "edit-") {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for i, name := range names {
		if i < editBackupMax {
			continue
		}
		_ = os.RemoveAll(filepath.Join(base, name))
	}
}

func updateMetadataAfterEdit(paths host.Paths, res xraycfg.EditResult, config []byte, rep *EditReport) {
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "manager metadata missing; sha256 not recorded")
		return
	}
	path, err := paths.Join(paths.ManagerMetadata(), true)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "manager metadata path unavailable: "+err.Error())
		return
	}
	meta.Transport = res.Transport
	meta.RuntimeSHA256 = store.HashBytes(config)
	// tlsLabel is the install-time spelling ("Reality"/"TLS"/"None");
	// LoadMetadata rejects anything else, so an edit must not invent a
	// lowercase label that would make the next command fail. Direct TLS is an
	// edit-time classification, so it keeps the label the install wrote.
	if res.Mode != xraycfg.ModeTLSDirect {
		meta.TLS = tlsLabel(res.Mode)
	}
	if res.Mode != xraycfg.ModeTLSDirect && meta.Install != nil {
		// Keep the snapshot describing the live origin, not the pre-edit one.
		meta.Install.Target, meta.Install.ServerNames = realityOrigin(config)
	}
	// Persist link-only preferences. An empty pair clears the field instead of
	// writing a meaningless default.
	if res.LinkFingerprint == "" && res.LinkSpiderX == "" {
		meta.ShareLinkOnly = nil
	} else {
		meta.ShareLinkOnly = &store.ShareLinkPrefs{
			Fingerprint: res.LinkFingerprint, SpiderX: res.LinkSpiderX,
		}
	}
	meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	body, _ := json.MarshalIndent(meta, "", "  ")
	body = append(body, '\n')
	if err := writeFileAtomic(path, body, 0o644); err != nil {
		rep.Warnings = append(rep.Warnings, "manager metadata not updated: "+err.Error())
	}
}

// EditRelay rewrites relay-stream.conf while keeping the managed Nginx in
// service. The relay has no Xray config, so nginx -t is the only self-check.
func EditRelay(ctx context.Context, spec RelayEditSpec) (RelayEditReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return RelayEditReport{}, err
	}
	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return RelayEditReport{}, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return RelayEditReport{}, err
		}
		defer lock.Release()
	}
	confPath, err := paths.Join(paths.RelayConfig(), false)
	if err != nil {
		return RelayEditReport{}, fmt.Errorf("this install is not a relay (relay-stream.conf missing)")
	}
	raw, _, err := store.ReadRegular(confPath, "relay config")
	if err != nil {
		return RelayEditReport{}, err
	}
	conf := string(raw)
	currentTarget, listenAddress, currentPort := relayConfParts(conf)
	target := currentTarget
	if spec.Target != "" {
		target = spec.Target
	}
	port := currentPort
	if spec.ListenPort != 0 {
		port = spec.ListenPort
	}
	report := RelayEditReport{Target: target, ListenPort: port, NoRestart: spec.NoRestart, DryRun: spec.DryRun}
	candidate, err := xraycfg.RelayConf(xraycfg.RelaySpec{
		ListenAddress: listenAddress, ListenPort: port, BackendHost: hostOf(target), BackendPort: portOf(target),
	})
	if err != nil {
		return report, err
	}
	if candidate == conf {
		report.NoChanges = true
		return report, nil
	}
	if spec.DryRun {
		return report, nil
	}
	nginxDir, err := joinDir(paths, nginxDirRel)
	if err != nil {
		return report, err
	}
	backupDir, err := writeEditBackup(paths, confPath, raw, nginxDir,
		xraycfg.EditResult{Changed: []string{"relay-target", "relay-listen-port"}}, editBackupExtras{})
	if err != nil {
		return report, err
	}
	report.BackupDir = backupDir
	confState, err := captureFile(confPath)
	if err != nil {
		return report, err
	}
	nginxSnap, err := snapshotRegularFiles(nginxDir)
	if err != nil {
		return report, err
	}
	if err := writeFileAtomic(confPath, []byte(candidate), confState.mode); err != nil {
		return report, err
	}
	if confState.uid >= 0 && confState.gid >= 0 {
		_ = chownFile(confPath, confState.uid, confState.gid)
	}
	if err := nginx.Finalize(ctx, nginx.FinalizeSpec{Root: spec.Root, NoService: spec.NoRestart}); err != nil {
		restoreErr := confState.restore()
		if rbErr := restoreRegularFiles(nginxDir, nginxSnap); rbErr != nil {
			restoreErr = rbErr
		}
		if rbErr := nginx.Finalize(ctx, nginx.FinalizeSpec{Root: spec.Root, NoService: spec.NoRestart}); rbErr != nil {
			return report, fmt.Errorf("%w; rollback failed: %v %v", err, restoreErr, rbErr)
		}
		return report, fmt.Errorf("%w; previous relay config restored", err)
	}
	report.NginxVerified = true
	return report, nil
}

var (
	relayListenRe = regexp.MustCompile(`(?m)^\s*listen\s+([^\s;]+)\s*;`)
	relayProxyRe  = regexp.MustCompile(`(?m)^\s*proxy_pass\s+([^\s;]+)\s*;`)
)

func relayConfParts(conf string) (target, listenAddress string, listenPort int) {
	listenPort = 8443
	if m := relayProxyRe.FindStringSubmatch(conf); len(m) > 1 {
		target = m[1]
	}
	if m := relayListenRe.FindStringSubmatch(conf); len(m) > 1 {
		if addr, port, err := net.SplitHostPort(m[1]); err == nil {
			listenAddress = addr
			if v, err := strconv.Atoi(port); err == nil {
				listenPort = v
			}
		}
	}
	return target, listenAddress, listenPort
}

func hostOf(target string) string {
	h, _, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	return h
}

func portOf(target string) int {
	_, p, err := net.SplitHostPort(target)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(p)
	return port
}
