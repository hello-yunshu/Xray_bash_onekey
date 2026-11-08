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
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

const (
	binaryRel = "usr/local/bin/xray"
	unitRel   = "etc/systemd/system/xray.service"
	configRel = "etc/idleleo/conf/xray/config.json"
	logDirRel = "var/log/xray"
	// ContainerWritesAck is the only accepted acknowledgement value.
	ContainerWritesAck = "I_ACCEPT_CONTAINER_ONLY"
)

// InstallSpec is one fresh install request.
type InstallSpec struct {
	Root                 string
	SourceBinary         string
	Mode                 string
	Transport            string
	Port                 int
	Domain               string
	Target               string
	ServerNames          []string
	KeepConfig           bool
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
}

// UninstallSpec is one removal request.
type UninstallSpec struct {
	Root                 string
	Purge                bool
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
	rep := Report{Mode: spec.Mode, Warnings: []string{}}
	var configBytes []byte
	if spec.KeepConfig {
		if existing, readErr := os.ReadFile(configPath); readErr == nil {
			configBytes = existing
			rep.Preserved = true
		}
	}
	if len(configBytes) == 0 {
		g, genErr := xraycfg.Generate(xraycfg.Spec{
			Mode: spec.Mode, Transport: spec.Transport, Port: spec.Port,
			Domain: spec.Domain, Target: spec.Target, ServerNames: spec.ServerNames,
		})
		if genErr != nil {
			return Report{}, genErr
		}
		configBytes = g.Config
		rep.Mode, rep.Transport = g.Mode, g.Transport
	}
	if rep.Mode == "" {
		rep.Mode, rep.Transport, _ = classifyConfig(configBytes)
	}
	rep.TLS = tlsLabel(rep.Mode)

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
	backups, err := captureFiles([]string{configPath, installedBin, unitPath, metaPath})
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

	meta := store.Metadata{
		SchemaVersion:     store.ManagerSchemaVersion,
		ActiveEngine:      "xray",
		Role:              "node",
		TLS:               rep.TLS,
		Transport:         rep.Transport,
		RuntimeConfigPath: configRel,
		RuntimeSHA256:     store.HashBytes(configBytes),
		OwnedResources:    []string{binaryRel, configRel, unitRel},
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
	if rep.Mode == xraycfg.ModeTLS {
		rep.Warnings = append(rep.Warnings, "nginx-config-not-applied")
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
	if spec.Purge {
		for _, rel := range []string{configRel, logDirRel} {
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
	return rep, nil
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
	case xraycfg.ModeReality, xraycfg.ModeRealityNginx:
		return "Reality"
	case xraycfg.ModeTLS:
		return "TLS"
	default:
		return "None"
	}
}
