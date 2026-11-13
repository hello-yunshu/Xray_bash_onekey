// Package deploy performs the Phase 02 container-level fresh install of Xray:
// binary, native config, systemd unit, service account and metadata.
//
// It refuses to write the real root ("/") unless all three conditions hold:
// the caller passed --container, IDLELEO_ALLOW_SYSTEM_WRITES equals the
// documented acknowledgement, and the process really runs inside a container.
// Non-root targets must be a marked disposable sandbox.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

const (
	binaryRel   = "usr/local/bin/xray"
	unitRel     = "etc/systemd/system/xray.service"
	configRel   = "etc/idleleo/conf/xray/config.json"
	nginxDirRel = "etc/idleleo/conf/nginx"
	logDirRel   = "var/log/xray"
	// ContainerWritesAck is the only accepted acknowledgement value.
	ContainerWritesAck = "I_ACCEPT_CONTAINER_ONLY"
)

// InstallSpec is one fresh install request.
type InstallSpec struct {
	Root             string
	SourceBinary     string
	Mode             string
	Transport        string
	Port             int
	Domain           string
	Target           string
	Path             string
	ServiceName      string
	UUID             string
	Email            string
	Flow             string
	PrivateKey       string
	ShortID          string
	CertFile         string
	KeyFile          string
	Listen           string
	PublicPort       int
	ServerNames      []string
	BalanceRole      string
	Backends         []string
	UnknownSNIPolicy string
	AllowNonLoopback bool
	KeepConfig       bool
	// ExternalNginxManaged opts out of the managed Nginx front. By default a
	// mode that needs Nginx installs the verified release artifact; with this
	// flag the operator owns the front and NginxBin must point at a real nginx
	// so the generated artifacts are syntax-verified.
	ExternalNginxManaged bool
	NginxBin             string
	// LocalIP is the host address that the managed front answers with 403.
	LocalIP string
	// RewriteConfig is the explicit opt-in for replacing an existing runtime
	// config. Without it (or KeepConfig) Install refuses to overwrite a live
	// config, so a migration cannot silently change ports, paths, UUIDs or keys.
	RewriteConfig        bool
	NoService            bool
	AllowContainerWrites bool
}

// Report is the machine-readable installation result.
type Report struct {
	Mode           string   `json:"mode"`
	Transport      string   `json:"transport"`
	TLS            string   `json:"tls"`
	BinaryPath     string   `json:"binaryPath"`
	ConfigPath     string   `json:"configPath"`
	UnitPath       string   `json:"unitPath"`
	MetadataPath   string   `json:"metadataPath"`
	ConfigSHA256   string   `json:"configSha256"`
	ServiceActive  string   `json:"serviceActive,omitempty"`
	ServiceEnabled string   `json:"serviceEnabled,omitempty"`
	Preserved      bool     `json:"preservedConfig"`
	ValidatorExit  int      `json:"validatorExit"`
	OwnedResources []string `json:"ownedResources"`
	Warnings       []string `json:"warnings"`
	NginxManaged   bool     `json:"nginxManaged"`
	NginxVerified  bool     `json:"nginxVerified"`
	NginxDir       string   `json:"nginxDir,omitempty"`
}

// UninstallSpec is one removal request.
type UninstallSpec struct {
	Root                 string
	Purge                bool
	KeepNginxConf        bool
	AllowContainerWrites bool
}

// UninstallReport lists what was removed.
type UninstallReport struct {
	Removed         []string `json:"removed"`
	ServiceStopped  bool     `json:"serviceStopped"`
	ServiceDisabled bool     `json:"serviceDisabled"`
	ConfigPreserved bool     `json:"configPreserved"`
	Warnings        []string `json:"warnings"`
}

// Install writes the complete node layout and, when allowed, starts systemd.
//
// serviceCommand/serviceQuery/serviceManaged are variables so tests can inject
// systemctl failures and drive the rollback path without a real init system.
var (
	serviceCommand = service
	serviceQuery   = queryService
	serviceManaged = func(root string) bool { return root == "/" }
)

// Managed Nginx seams. Tests replace them so a deployment test never reaches
// the network or a real init system.
var (
	resolveManagedNginx  = nginx.Resolve
	installManagedNginx  = nginx.Install
	finalizeManagedNginx = nginx.Finalize
)

func Install(ctx context.Context, spec InstallSpec) (Report, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return Report{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return Report{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return Report{}, err
	}
	defer lock.Release()
	// A previous process may have died mid-transaction. Converge it before
	// starting a new one so a crash cannot stack two half-applied states.
	recovery, err := recoverPendingLocked(ctx, paths)
	if err != nil {
		return Report{}, err
	}
	bin, err := host.ResolveBinary(spec.SourceBinary)
	if err != nil {
		return Report{}, err
	}
	res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"version"}, Timeout: 5 * time.Second})
	if err != nil {
		return Report{}, err
	}
	if res.ExitCode != 0 {
		return Report{}, fmt.Errorf("xray version failed with exit %d", res.ExitCode)
	}

	configPath, err := paths.Join(configRel, true)
	if err != nil {
		return Report{}, err
	}
	if _, statErr := os.Lstat(configPath); statErr == nil && !spec.KeepConfig && !spec.RewriteConfig {
		// A migration/reinstall must never regenerate an existing runtime by
		// accident: that would change listening ports, paths, UUIDs, Reality
		// identity and custom routing without telling the operator.
		return Report{}, fmt.Errorf("existing runtime config %s: refusing implicit regeneration; pass --keep-config to adopt it unchanged or --rewrite-config to replace it explicitly", configPath)
	}
	// Modes that expose the public entry through Nginx always get a front. The
	// default is a managed install from the verified release artifact; the
	// explicit opt-out must supply a real binary so the generated artifacts are
	// still syntax-verified.
	if requiresNginx(spec.Mode, spec.BalanceRole) && spec.ExternalNginxManaged && spec.NginxBin == "" {
		return Report{}, fmt.Errorf("mode %s needs Nginx verification: pass --nginx-bin to run nginx -t on the generated artifacts", spec.Mode)
	}
	rep := Report{Mode: spec.Mode, Warnings: []string{}}
	var configBytes []byte
	var generated *xraycfg.Generated
	if spec.KeepConfig {
		if existing, readErr := os.ReadFile(configPath); readErr == nil {
			configBytes = existing
			rep.Preserved = true
		}
	}
	if len(configBytes) == 0 {
		g, genErr := xraycfg.Generate(xraycfg.Spec{
			Mode: spec.Mode, Transport: spec.Transport, Port: spec.Port,
			Domain: spec.Domain, Target: spec.Target, Path: spec.Path,
			ServiceName: spec.ServiceName, UUID: spec.UUID, Email: spec.Email,
			Flow: spec.Flow, PrivateKey: spec.PrivateKey, ShortID: spec.ShortID,
			CertFile: spec.CertFile, KeyFile: spec.KeyFile, Listen: spec.Listen,
			PublicPort: spec.PublicPort, AllowNonLoopback: spec.AllowNonLoopback,
			ServerNames: spec.ServerNames, BalanceRole: spec.BalanceRole,
			Backends: spec.Backends, UnknownSNIPolicy: spec.UnknownSNIPolicy,
		})
		if genErr != nil {
			return Report{}, genErr
		}
		configBytes = g.Config
		generated = &g
		rep.Mode, rep.Transport = g.Mode, g.Transport
	}
	if rep.Mode == "" {
		rep.Mode, rep.Transport, _ = classifyConfig(configBytes)
	}
	rep.TLS = tlsLabel(rep.Mode)

	var nginxDir string
	var nginxFiles []string
	managedNginx := false
	if requiresNginx(rep.Mode, spec.BalanceRole) {
		if generated == nil {
			return Report{}, fmt.Errorf("cannot adopt an existing config for mode %s: Nginx artifacts must be generated explicitly", rep.Mode)
		}
		nginxDir, err = paths.Join(nginxDirRel, true)
		if err != nil {
			return Report{}, err
		}
		nginxFiles = append(nginxFiles, filepath.Join(nginxDir, nginx.MainConf))
		for name := range generated.NginxFragments {
			nginxFiles = append(nginxFiles, filepath.Join(nginxDir, name))
		}
		rep.NginxManaged = true
		rep.NginxDir = nginxDir
		managedNginx = !spec.ExternalNginxManaged
	}
	// Install the managed front before the Xray transaction. This ordering keeps
	// the Xray runtime files untouched until Nginx is in place, but the managed
	// Nginx tree, unit and service are real host mutations: a later failure does
	// not unwind them, it only reports that they are installed.
	if managedNginx {
		artifact, resolveErr := resolveManagedNginx(ctx, nginx.Options{})
		if resolveErr != nil {
			return Report{}, resolveErr
		}
		localIP := spec.LocalIP
		if localIP == "" {
			if detected, ipErr := nginx.LocalAddress(ctx); ipErr != nil {
				rep.Warnings = append(rep.Warnings, "managed nginx: local IP detection failed, local-IP 403 guard skipped: "+ipErr.Error())
			} else {
				localIP = detected
			}
		}
		installed, installErr := installManagedNginx(ctx, nginx.InstallSpec{
			Root: paths.Root, Artifact: artifact,
			Stream:  strings.Contains(generated.NginxConf, "stream {"),
			LocalIP: localIP, NoService: spec.NoService,
		})
		if installErr != nil {
			// Do not roll Nginx back here: it is a separate managed component and
			// a later retry adopts the same build. Report it so the operator knows
			// the host is no longer pristine.
			rep.NginxManaged = true
			rep.NginxDir = filepath.Join(paths.Root, nginxDirRel)
			return rep, fmt.Errorf("%w; managed Nginx is installed at %s and can be removed with 'idleleo xray uninstall'", installErr, rep.NginxDir)
		}
		rep.NginxDir = installed.ConfDir
		rep.NginxVerified = installed.Verified
		rep.Warnings = append(rep.Warnings, installed.Warnings...)
	}

	installedBin, err := paths.Join(binaryRel, true)
	if err != nil {
		return Report{}, err
	}
	unitPath, err := paths.Join(unitRel, true)
	if err != nil {
		return Report{}, err
	}
	metaPath, err := paths.Join(paths.ManagerMetadata(), true)
	if err != nil {
		return Report{}, err
	}

	// xray -test opens the configured logs, so the log directory must exist.
	// Record which ancestors were missing before creating any of them; recovery
	// must remove only what the install created.
	logDir, err := joinDir(paths, logDirRel)
	if err != nil {
		return Report{}, err
	}
	logDirMissing := missingDirChain(logDir)

	// Capture the previous files and service state before the first mutation.
	// A failed install or reinstall must be able to return to exactly this
	// state; if it cannot, the error must say so instead of pretending success.
	targets := []string{configPath, installedBin, unitPath, metaPath}
	targets = append(targets, nginxFiles...)
	backups, err := captureFiles(targets)
	if err != nil {
		return Report{}, err
	}
	snap := captureService(ctx, unitPath, paths.Root, spec.NoService)

	// The durable journal must be fsynced before the first byte of live state
	// changes. From here on a SIGKILL leaves a rollback record for the next
	// process instead of a half-applied install.
	j, err := newJournal(paths, backups, snap, logDirMissing, rep.Mode, rep.Transport)
	if err != nil {
		return Report{}, err
	}
	if recovery.Action == "rolled_back" {
		rep.Warnings = append(rep.Warnings, "recovered unfinished deploy transaction")
	}
	fail := func(cause error) (Report, error) {
		if rbErr := restoreTransaction(ctx, backups, snap, logDirMissing); rbErr != nil {
			journalMarkRecoveryRequired(paths, &j, rbErr)
			return rep, fmt.Errorf("%w; rollback failed: %v; recovery journal kept, inspect and run 'idleleo xray recover'", cause, rbErr)
		}
		_ = journalMarkRolledBack(paths, &j, cause)
		return rep, fmt.Errorf("%w; installation rolled back to the previous state", cause)
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fail(err)
	}

	tmp, err := os.CreateTemp("", "idleleo-candidate-*.json")
	if err != nil {
		return fail(err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(configBytes); err != nil {
		tmp.Close()
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fail(err)
	}
	ver, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"-test", "-config", tmpName}})
	if err != nil {
		return fail(err)
	}
	rep.ValidatorExit = ver.ExitCode
	if ver.ExitCode != 0 {
		return fail(fmt.Errorf("xray -test rejected the candidate (exit %d): %s", ver.ExitCode, strings.TrimSpace(ver.Stderr)))
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(configPath, configBytes, 0o600); err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fail(err)
	}

	if len(nginxFiles) > 0 {
		if err := writeNginxArtifacts(nginxDir, generated); err != nil {
			return fail(err)
		}
		if managedNginx {
			if err := finalizeManagedNginx(ctx, nginx.FinalizeSpec{Root: paths.Root, NoService: spec.NoService}); err != nil {
				// Finalize failing rolls the Xray transaction back but never
				// uninstalls the managed front, so say it is still there.
				nginxHostDir := rep.NginxDir
				if nginxHostDir == "" {
					nginxHostDir = filepath.Join(paths.Root, nginxDirRel)
				}
				return fail(fmt.Errorf("%w; managed Nginx is installed at %s and can be removed with 'idleleo xray uninstall'", err, nginxHostDir))
			}
		} else if err := verifyNginx(ctx, spec.NginxBin, generated.NginxConf, generated.NginxFragments, nginxDir); err != nil {
			return fail(err)
		}
		rep.NginxVerified = true
	}

	if err := copyExecutable(bin, installedBin); err != nil {
		return fail(err)
	}

	account := ""
	if paths.Root == "/" {
		account, err = ensureServiceAccount(ctx)
		if err != nil {
			return fail(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return fail(err)
	}
	unit := unitContent(installedBin, configPath, account)
	if err := writeFileAtomic(unitPath, []byte(unit), 0o644); err != nil {
		return fail(err)
	}
	if account != "" {
		uid, gid := uidOf(account), groupID(account)
		if err := os.Chown(configPath, 0, gid); err == nil {
			_ = os.Chmod(configPath, 0o640)
		}
		// Xray (User=xray) writes access.log/error.log itself, so the directory
		// and any leftover log files must belong to the service account.
		if err := os.Chown(logDir, uid, gid); err == nil {
			_ = os.Chmod(logDir, 0o750)
		}
		for _, name := range []string{"access.log", "error.log"} {
			p := filepath.Join(logDir, name)
			if _, statErr := os.Lstat(p); statErr == nil {
				_ = os.Chown(p, uid, gid)
			}
		}
	}

	owned := []string{binaryRel, configRel, unitRel}
	if len(nginxFiles) > 0 {
		owned = append(owned, nginxDirRel+"/00-xray.conf")
		for name := range generated.NginxFragments {
			owned = append(owned, nginxDirRel+"/"+name)
		}
	}
	meta := store.Metadata{
		SchemaVersion:     store.ManagerSchemaVersion,
		ActiveEngine:      "xray",
		Provenance:        "native",
		Role:              "node",
		TLS:               rep.TLS,
		Transport:         rep.Transport,
		RuntimeConfigPath: configRel,
		RuntimeSHA256:     store.HashBytes(configBytes),
		OwnedResources:    owned,
		UpdatedAt:         time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaBytes = append(metaBytes, '\n')
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		return fail(err)
	}
	if err := writeFileAtomic(metaPath, metaBytes, 0o644); err != nil {
		return fail(err)
	}

	rep.BinaryPath, rep.ConfigPath, rep.UnitPath, rep.MetadataPath = installedBin, configPath, unitPath, metaPath
	rep.ConfigSHA256 = store.HashBytes(configBytes)
	rep.OwnedResources = meta.OwnedResources
	if rep.NginxVerified {
		rep.Warnings = append(rep.Warnings, "nginx-syntax-verified; routing verified only by the Docker e2e harness")
	}
	if spec.NoService || !serviceManaged(paths.Root) {
		if err := journalMarkCommitted(paths, &j); err != nil {
			return fail(err)
		}
		return rep, nil
	}
	if err := serviceCommand(ctx, "daemon-reload"); err != nil {
		return fail(err)
	}
	if err := serviceCommand(ctx, "enable", "xray"); err != nil {
		return fail(err)
	}
	if err := serviceCommand(ctx, "restart", "xray"); err != nil {
		return fail(err)
	}
	rep.ServiceEnabled = serviceQuery(ctx, "is-enabled", "xray")
	rep.ServiceActive = waitActive(ctx)
	if rep.ServiceActive != "active" {
		return fail(fmt.Errorf("xray.service is %q after start", rep.ServiceActive))
	}
	if err := journalMarkCommitted(paths, &j); err != nil {
		return fail(err)
	}
	return rep, nil
}

// requiresNginx reports whether the mode cannot provide a public entry point
// on its own. The primary balance role terminates the public port in Nginx;
// the secondary listens directly and does not need it.
func requiresNginx(mode, role string) bool {
	switch mode {
	case xraycfg.ModeTLS, xraycfg.ModeRealityNginx:
		return true
	case xraycfg.ModeRealityBalance:
		return role == "" || role == xraycfg.BalanceRolePrimary
	}
	return false
}

func writeNginxArtifacts(dir string, g *xraycfg.Generated) error {
	if g.NginxConf == "" {
		return fmt.Errorf("generated mode has no Nginx configuration to install")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	keep := map[string]bool{"00-xray.conf": true}
	for name := range g.NginxFragments {
		keep[name] = true
	}
	// Bash keeps the fragment directory tidy: a mode change must not leave an
	// old site, upstream server or SNI allowlist behind. Only tool-owned names
	// are removed, so operator files in the same directory survive.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if keep[name] || !entry.Type().IsRegular() {
			continue
		}
		stale := name == "01-xray-80.conf" || name == "02-xray-server.conf" || name == "03-isolate.conf"
		for _, suffix := range []string{".serverNames", ".realityServers", ".wsServers", ".grpcServers", ".xhttpServers"} {
			if strings.HasSuffix(name, suffix) {
				stale = true
			}
		}
		if stale {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	if err := writeFileAtomic(filepath.Join(dir, "00-xray.conf"), []byte(g.NginxConf), 0o644); err != nil {
		return err
	}
	for name, body := range g.NginxFragments {
		if err := writeFileAtomic(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// verifyNginx runs a real `nginx -t` against the generated artifacts. Absolute
// Bash-owned paths are rewritten to a throwaway directory only for the test so
// nothing under /etc or /usr/local is touched; the written artifacts stay
// byte-identical to what an operator will include.
func verifyNginx(ctx context.Context, bin, conf string, frags map[string]string, dir string) error {
	if bin == "" {
		return fmt.Errorf("nginx verification requires --nginx-bin")
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("nginx binary %s: %w", bin, err)
	}
	tmp, err := os.MkdirTemp("", "idleleo-nginx-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	fragDir := filepath.Join(tmp, "frags")
	logsDir := filepath.Join(tmp, "logs")
	if err := os.MkdirAll(fragDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return err
	}
	rewrite := func(body string) string {
		body = strings.ReplaceAll(body, "/etc/idleleo/conf/nginx", fragDir)
		body = strings.ReplaceAll(body, "/usr/local/nginx/logs", logsDir)
		return body
	}
	body := rewrite(conf)
	for name, fragment := range frags {
		if err := os.WriteFile(filepath.Join(fragDir, name), []byte(rewrite(fragment)), 0o644); err != nil {
			return err
		}
	}

	var wrapper strings.Builder
	wrapper.WriteString("worker_processes 1;\n")
	wrapper.WriteString("pid " + filepath.Join(tmp, "nginx.pid") + ";\n")
	wrapper.WriteString("error_log " + filepath.Join(tmp, "error.log") + " notice;\n")
	wrapper.WriteString("events { worker_connections 128; }\n")
	stream := strings.Contains(conf, "stream {")
	if stream {
		// Ubuntu ships the stream module dynamically; loading it is required
		// before nginx can parse a stream block.
		if module := streamModule(ctx, bin); module != "" {
			wrapper.WriteString("load_module " + module + ";\n")
		}
		wrapper.WriteString(body)
		// ssl_reject_handshake belongs to ngx_http_ssl_module: the Bash
		// isolate site is included from the http block, never from stream.
		if _, ok := frags["03-isolate.conf"]; ok {
			wrapper.WriteString("http {\n    include " + filepath.Join(fragDir, "03-isolate.conf") + ";\n}\n")
		}
	} else {
		// The TLS site references upstreams that live in the fragment files, so
		// the verification wrapper must include them exactly like the managed
		// main config does.
		wrapper.WriteString("http {\n" + body + "\n    include " + filepath.Join(fragDir, "*.conf") + ";\n}\n")
	}
	wrapperPath := filepath.Join(tmp, "nginx.conf")
	if err := os.WriteFile(wrapperPath, []byte(wrapper.String()), 0o600); err != nil {
		return err
	}
	res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"-t", "-c", wrapperPath, "-p", tmp}, Timeout: 20 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("nginx -t rejected generated artifacts (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// moduleProbeTimeout bounds the nginx -V probe. It is a variable so tests can
// prove the timeout without waiting for the production default.
var moduleProbeTimeout = host.DefaultTimeout

// streamModule reports the dynamic stream module path when nginx was built with
// it. The probe goes through host.Run so it gets the fixed PATH, a hard timeout
// and the same redaction as every other external command.
func streamModule(ctx context.Context, bin string) string {
	res, err := host.Run(ctx, host.ExecSpec{
		Path: bin, Args: []string{"-V"}, Timeout: moduleProbeTimeout,
	})
	if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, "--with-stream=dynamic") {
		return ""
	}
	candidates := []string{
		"/usr/lib/nginx/modules/ngx_stream_module.so",
		"/usr/local/nginx/modules/ngx_stream_module.so",
		filepath.Join(filepath.Dir(bin), "..", "lib", "nginx", "modules", "ngx_stream_module.so"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// Uninstall stops and removes the Go-managed resources. Config is kept unless
// purge is requested, so a reinstall can preserve user customisations.
func Uninstall(ctx context.Context, spec UninstallSpec) (UninstallReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return UninstallReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return UninstallReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return UninstallReport{}, err
	}
	defer lock.Release()
	if _, err := recoverPendingLocked(ctx, paths); err != nil {
		return UninstallReport{}, err
	}
	rep := UninstallReport{Warnings: []string{}}
	unitPath, _ := paths.Join(unitRel, false)
	if _, statErr := os.Stat(unitPath); statErr == nil {
		if paths.Root == "/" {
			if err := service(ctx, "stop", "xray"); err == nil {
				rep.ServiceStopped = true
			}
			if err := service(ctx, "disable", "xray"); err == nil {
				rep.ServiceDisabled = true
			}
			_ = service(ctx, "daemon-reload")
		}
		if err := os.Remove(unitPath); err == nil {
			rep.Removed = append(rep.Removed, unitRel)
		}
	}
	for _, rel := range []string{binaryRel, paths.ManagerMetadata()} {
		p, joinErr := paths.Join(rel, false)
		if joinErr != nil {
			continue
		}
		if err := os.Remove(p); err == nil {
			rep.Removed = append(rep.Removed, rel)
		}
	}
	// The managed front is part of the product: stop it and remove its tree and
	// unit even when the caller keeps the configuration. The fragment directory
	// is removed by default so a reinstall starts clean; --keep-nginx-conf
	// opts out.
	ngRep, ngErr := nginx.Uninstall(ctx, nginx.UninstallSpec{
		Root:     paths.Root,
		KeepConf: spec.KeepNginxConf && !spec.Purge,
	})
	if ngErr != nil {
		rep.Warnings = append(rep.Warnings, ngErr.Error())
	} else {
		rep.Removed = append(rep.Removed, ngRep.Removed...)
		rep.ServiceStopped = rep.ServiceStopped || ngRep.ServiceStopped
		rep.ServiceDisabled = rep.ServiceDisabled || ngRep.ServiceDisabled
		rep.ConfigPreserved = rep.ConfigPreserved || ngRep.ConfigPreserved
		rep.Warnings = append(rep.Warnings, ngRep.Warnings...)
	}
	if spec.Purge {
		for _, rel := range []string{configRel, nginxDirRel, logDirRel} {
			p, joinErr := joinDir(paths, rel)
			if joinErr != nil {
				continue
			}
			if err := os.RemoveAll(p); err == nil {
				rep.Removed = append(rep.Removed, rel)
			}
		}
	} else {
		rep.ConfigPreserved = true
	}
	return rep, ngErr
}

// fileState is the prior content, mode, ownership and link target of one
// install target. A rollback must restore ownership as well: the runtime runs
// as an unprivileged user and a root:root 0640 config would become unreadable
// even though the bytes were "restored".
type fileState struct {
	path        string
	data        []byte
	mode        os.FileMode
	uid         int
	gid         int
	link        string
	exists      bool
	missingDirs []string
}

type serviceState struct {
	managed     bool
	unitExisted bool
	enabled     string
	active      string
}

func captureFiles(paths []string) ([]fileState, error) {
	out := make([]fileState, 0, len(paths))
	for _, p := range paths {
		st, err := captureFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

func captureFile(path string) (fileState, error) {
	st := fileState{path: path, uid: -1, gid: -1, missingDirs: missingDirChain(filepath.Dir(path))}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return fileState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return fileState{}, err
		}
		st.link, st.exists = target, true
		return st, nil
	}
	if !info.Mode().IsRegular() {
		return fileState{}, fmt.Errorf("%s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fileState{}, err
	}
	st.data, st.mode, st.exists = b, info.Mode().Perm(), true
	if raw, ok := info.Sys().(*syscall.Stat_t); ok {
		st.uid, st.gid = int(raw.Uid), int(raw.Gid)
	}
	return st, nil
}

// chownFile is a test seam; production restore must run as root to put back a
// root:xray 0640 config that the unprivileged Xray user can still read.
var chownFile = os.Chown

func (s fileState) restore() error {
	if !s.exists {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		removeEmptyDirs(s.missingDirs)
		return nil
	}
	if s.link != "" {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return os.Symlink(s.link, s.path)
	}
	if err := writeFileAtomic(s.path, s.data, s.mode); err != nil {
		return err
	}
	if s.uid >= 0 && s.gid >= 0 {
		if err := chownFile(s.path, s.uid, s.gid); err != nil {
			return err
		}
	}
	return os.Chmod(s.path, s.mode)
}

// missingDirChain returns the not-yet-existing ancestors of dir, deepest first.
// A fresh install creates them; a rollback may remove only the empty ones.
func missingDirChain(dir string) []string {
	var out []string
	for {
		if _, err := os.Lstat(dir); err == nil || !os.IsNotExist(err) {
			return out
		}
		out = append(out, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			return out
		}
		dir = parent
	}
}

func removeEmptyDirs(dirs []string) {
	for _, dir := range dirs {
		_ = os.Remove(dir)
	}
}

func captureService(ctx context.Context, unitPath, root string, noService bool) serviceState {
	if noService || !serviceManaged(root) {
		return serviceState{}
	}
	st := serviceState{managed: true}
	if _, err := os.Lstat(unitPath); err == nil {
		st.unitExisted = true
	}
	st.enabled = serviceQuery(ctx, "is-enabled", "xray")
	st.active = serviceQuery(ctx, "is-active", "xray")
	return st
}

// restoreTransaction puts back the captured files and service state. When any
// part cannot be restored the error names the remaining manual work; callers
// never report the original failure as if the host were clean.
func restoreTransaction(ctx context.Context, backups []fileState, snap serviceState, logDirMissing []string) error {
	if snap.managed && !snap.unitExisted {
		// A fresh install may have started and enabled the new unit. Stop and
		// disable it before the restored file set removes the unit itself, so
		// no dangling wants/ symlink survives the rollback.
		_ = serviceCommand(ctx, "stop", "xray")
		_ = serviceCommand(ctx, "disable", "xray")
	}
	for i := len(backups) - 1; i >= 0; i-- {
		_ = os.Remove(backups[i].path + ".tmp")
		if err := backups[i].restore(); err != nil {
			return err
		}
	}
	removeEmptyDirs(logDirMissing)
	if err := restoreService(ctx, snap); err != nil {
		return err
	}
	if snap.managed && !snap.unitExisted {
		if err := serviceCommand(ctx, "daemon-reload"); err != nil {
			return err
		}
		if got := serviceQuery(ctx, "is-enabled", "xray"); strings.Contains(got, "enabled") {
			return fmt.Errorf("xray.service is still enabled (%q)", got)
		}
	}
	return nil
}

func restoreService(ctx context.Context, snap serviceState) error {
	if !snap.managed || !snap.unitExisted {
		return nil
	}
	if err := serviceCommand(ctx, "daemon-reload"); err != nil {
		return err
	}
	wantEnabled := strings.Contains(snap.enabled, "enabled")
	if wantEnabled {
		if err := serviceCommand(ctx, "enable", "xray"); err != nil {
			return err
		}
	} else if err := serviceCommand(ctx, "disable", "xray"); err != nil {
		return err
	}
	wantActive := snap.active == "active"
	if wantActive {
		if err := serviceCommand(ctx, "restart", "xray"); err != nil {
			return err
		}
	} else if err := serviceCommand(ctx, "stop", "xray"); err != nil {
		return err
	}
	if gotEnabled := serviceQuery(ctx, "is-enabled", "xray"); strings.Contains(gotEnabled, "enabled") != wantEnabled {
		return fmt.Errorf("service enabled state is %q, want enabled=%v", gotEnabled, wantEnabled)
	}
	if gotActive := serviceQuery(ctx, "is-active", "xray"); (gotActive == "active") != wantActive {
		return fmt.Errorf("service active state is %q, want active=%v", gotActive, wantActive)
	}
	return nil
}

func joinDir(paths host.Paths, rel string) (string, error) {
	p, err := paths.Join(rel, false)
	if err == nil {
		return p, nil
	}
	if os.IsNotExist(err) {
		return paths.Join(rel, true)
	}
	return "", err
}

func requireWriteAccess(paths host.Paths, ack bool) error {
	return host.RequireSystemWrite(paths.Root, ack)
}

func ensureServiceAccount(ctx context.Context) (string, error) {
	if res, err := host.Run(ctx, host.ExecSpec{Path: "id", Args: []string{"-u", "xray"}}); err == nil && res.ExitCode == 0 {
		return "xray", nil
	}
	if res, err := host.Run(ctx, host.ExecSpec{Path: "groupadd", Args: []string{"--system", "xray"}}); err != nil || res.ExitCode != 0 {
		return "", fmt.Errorf("create xray group failed: %s", strings.TrimSpace(res.Stderr))
	}
	if res, err := host.Run(ctx, host.ExecSpec{Path: "useradd", Args: []string{
		"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", "xray", "xray",
	}}); err != nil || res.ExitCode != 0 {
		return "", fmt.Errorf("create xray user failed: %s", strings.TrimSpace(res.Stderr))
	}
	return "xray", nil
}

func uidOf(name string) int {
	if u, err := user.Lookup(name); err == nil {
		var uid int
		if _, err := fmt.Sscanf(u.Uid, "%d", &uid); err == nil {
			return uid
		}
	}
	return -1
}

func groupID(name string) int {
	if g, err := user.LookupGroup(name); err == nil {
		var gid int
		if _, err := fmt.Sscanf(g.Gid, "%d", &gid); err == nil {
			return gid
		}
	}
	return -1
}

func unitContent(bin, config, account string) string {
	userLine := ""
	if account != "" {
		userLine = "User=" + account + "\nGroup=" + account + "\n"
	}
	return fmt.Sprintf(`[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
%sCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=%s run -config %s
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
`, userLine, bin, config)
}

func service(ctx context.Context, args ...string) error {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: args, Timeout: 15 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl %s failed (exit %d): %s", strings.Join(args, " "), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

func queryService(ctx context.Context, args ...string) string {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: args, Timeout: 10 * time.Second})
	if err != nil {
		return "unknown"
	}
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		return fmt.Sprintf("exit-%d", res.ExitCode)
	}
	return out
}

func waitActive(ctx context.Context) string {
	for i := 0; i < 20; i++ {
		state := serviceQuery(ctx, "is-active", "xray")
		if state == "active" || state == "failed" {
			return state
		}
		time.Sleep(250 * time.Millisecond)
	}
	return serviceQuery(ctx, "is-active", "xray")
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func classifyConfig(raw []byte) (mode, transport string, err error) {
	var root struct {
		Inbounds []struct {
			StreamSettings struct {
				Network  string `json:"network"`
				Security string `json:"security"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return "", "", err
	}
	if len(root.Inbounds) == 0 {
		return "", "", fmt.Errorf("config has no inbounds")
	}
	network, security := root.Inbounds[0].StreamSettings.Network, root.Inbounds[0].StreamSettings.Security
	switch security {
	case "reality":
		return xraycfg.ModeReality, xraycfg.TransportRaw, nil
	case "tls":
		return xraycfg.ModeTLS, network, nil
	default:
		return xraycfg.ModeNone, network, nil
	}
}

func tlsLabel(mode string) string {
	switch mode {
	case xraycfg.ModeReality, xraycfg.ModeRealityNginx, xraycfg.ModeRealityBalance:
		return "Reality"
	case xraycfg.ModeTLS:
		return "TLS"
	default:
		return "None"
	}
}
