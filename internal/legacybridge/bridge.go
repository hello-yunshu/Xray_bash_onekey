package legacybridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

const (
	installedRel    = "opt/idleleo/bin/idleleo"
	candidateRel    = "opt/idleleo/bin/idleleo.candidate"
	recoveryBinRel  = "opt/idleleo/recovery/idleleo-recover"
	legacyBackupRel = "opt/idleleo/recovery/legacy-install.sh"
	crontabRel      = "var/spool/cron/crontabs/root"
	metadataRel     = "etc/idleleo/v1/metadata.json"

	// ContainerWritesAck is the only accepted acknowledgement for real root
	// writes, matching internal/deploy.
	ContainerWritesAck = "I_ACCEPT_CONTAINER_ONLY"
)

// Error carries a stable process exit code.
type Error struct {
	Code int
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// ExitCode lets the CLI map bridge errors without string matching.
func (e *Error) ExitCode() int { return e.Code }

// resolve joins a relative bridge path under root without following the final
// symlink. The entry intentionally is a symlink, so Paths.Join cannot be used.
func resolve(root, rel string) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(rel) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe bridge path")
	}
	return filepath.Join(root, clean), nil
}

func mustResolve(root, rel string) string {
	p, _ := resolve(root, rel)
	return p
}

// requireWriteAccess mirrors internal/deploy: a non-root target must be a
// marked disposable sandbox; the real root requires the container ack.
func requireWriteAccess(root string, ack bool) error {
	if root != "/" {
		paths, err := host.NewPaths(root)
		if err != nil {
			return &Error{Code: 2, Msg: "invalid root", Err: err}
		}
		if err := paths.RequireSandbox(); err != nil {
			return &Error{Code: 2, Msg: "sandbox marker required", Err: err}
		}
		return nil
	}
	if !ack {
		return &Error{Code: 2, Msg: "real root writes require --container"}
	}
	if os.Getenv("IDLELEO_ALLOW_SYSTEM_WRITES") != ContainerWritesAck {
		return &Error{Code: 2, Msg: "real root writes require IDLELEO_ALLOW_SYSTEM_WRITES=" + ContainerWritesAck}
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return nil
		}
	}
	return &Error{Code: 2, Msg: "refusing real root writes outside a container"}
}

// lockForWrite takes the same /run/lock/idleleo-update.lock that the legacy
// Bash updater holds, so Bash/Go updates and Bridge activation can never write
// the same resources concurrently. A Bash parent that already owns the lock
// passes IDLELEO_UPDATE_LOCK_HELD=1 to its Go child, matching the legacy
// semantics without double-locking.
func lockForWrite(root string) (*host.UpdateLock, error) {
	if os.Getenv("IDLELEO_UPDATE_LOCK_HELD") == "1" {
		return nil, nil
	}
	paths, err := host.NewPaths(root)
	if err != nil {
		return nil, &Error{Code: 2, Msg: "invalid root", Err: err}
	}
	l, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		if errors.Is(err, host.ErrLocked) {
			return nil, &Error{Code: 13, Msg: "another idleleo update holds the lock", Err: err}
		}
		return nil, &Error{Code: 13, Msg: "cannot acquire the update lock", Err: err}
	}
	return l, nil
}

// PrepareOptions is one migration staging request.
type PrepareOptions struct {
	Root                 string
	Candidate            string
	Recovery             string
	AllowContainerWrites bool
}

// PrepareReport is the machine-readable staging result.
type PrepareReport struct {
	SchemaVersion    int      `json:"schemaVersion"`
	State            string   `json:"state"`
	Verdict          string   `json:"verdict"`
	PlanPath         string   `json:"planPath"`
	SnapshotPath     string   `json:"snapshotPath"`
	CandidateSHA256  string   `json:"candidateSha256"`
	RecoverySHA256   string   `json:"recoverySha256,omitempty"`
	MetadataPath     string   `json:"metadataPath"`
	ProjectCronLines int      `json:"projectCronLines"`
	Warnings         []string `json:"warnings"`
}

// Prepare audits, snapshots and converts metadata. It never changes the
// entry, cron, services or the runtime Xray config.
func Prepare(ctx context.Context, opts PrepareOptions) (PrepareReport, Audit, error) {
	report := PrepareReport{SchemaVersion: 1, Warnings: []string{}}
	audit, err := AuditMigration(opts.Root)
	if err != nil {
		return report, audit, &Error{Code: 1, Msg: "audit failed", Err: err}
	}
	report.Verdict = audit.Verdict
	if audit.Verdict == VerdictBlocked {
		return report, audit, &Error{Code: 3, Msg: "migration blocked by audit"}
	}
	if err := requireWriteAccess(opts.Root, opts.AllowContainerWrites); err != nil {
		return report, audit, err
	}
	lock, err := lockForWrite(opts.Root)
	if err != nil {
		return report, audit, err
	}
	if lock != nil {
		defer lock.Release()
	}
	if opts.Candidate == "" {
		return report, audit, &Error{Code: 2, Msg: "--candidate is required"}
	}
	if err := runnableFile(opts.Candidate); err != nil {
		return report, audit, &Error{Code: 2, Msg: "candidate is not an executable file", Err: err}
	}
	candSHA, err := hashFile(opts.Candidate)
	if err != nil {
		return report, audit, &Error{Code: 13, Msg: "candidate hash failed", Err: err}
	}
	candPath := mustResolve(opts.Root, candidateRel)
	if err := copyFileAtomic(opts.Candidate, candPath, 0o755); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write candidate failed", Err: err}
	}
	if sha, err := hashFile(candPath); err != nil || sha != candSHA {
		return report, audit, &Error{Code: 13, Msg: "candidate copy verification failed"}
	}
	report.CandidateSHA256 = candSHA

	if opts.Recovery != "" {
		if err := runnableFile(opts.Recovery); err != nil {
			return report, audit, &Error{Code: 2, Msg: "--recovery is not an executable file", Err: err}
		}
		if err := copyFileAtomic(opts.Recovery, mustResolve(opts.Root, recoveryBinRel), 0o755); err != nil {
			return report, audit, &Error{Code: 13, Msg: "write recovery binary failed", Err: err}
		}
		if sha, err := hashFile(mustResolve(opts.Root, recoveryBinRel)); err == nil {
			report.RecoverySHA256 = sha
		}
	} else if sha, err := hashFile(mustResolve(opts.Root, recoveryBinRel)); err == nil {
		report.RecoverySHA256 = sha
	}

	if err := writePlan(opts.Root, audit); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write plan failed", Err: err}
	}
	planPath := mustResolve(opts.Root, planRel)
	report.PlanPath = planPath
	planSHA, _ := hashFile(planPath)

	if err := writeSnapshot(opts.Root, audit); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write snapshot failed", Err: err}
	}
	report.SnapshotPath = mustResolve(opts.Root, snapshotRel)

	if err := writeMetadata(opts.Root, audit); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write metadata failed", Err: err}
	}
	report.MetadataPath = mustResolve(opts.Root, metadataRel)

	if _, _, err := store.LoadMetadata(pathsFor(opts.Root)); err != nil {
		return report, audit, &Error{Code: 13, Msg: "converted metadata does not load", Err: err}
	}

	j, err := readOrCreateJournal(opts.Root)
	if err != nil {
		return report, audit, err
	}
	switch j.State {
	case StateActivating, StateRollbackRequired, StateRecoveryRequired, StateCommitted:
		return report, audit, &Error{Code: 3, Msg: "unfinished or committed bridge transaction in state " + j.State + "; run bridge recover first"}
	}
	j.CandidateSHA256 = candSHA
	if report.RecoverySHA256 != "" {
		j.RecoverySHA256 = report.RecoverySHA256
	}
	j.PlanSHA256 = planSHA
	j.RuntimeSHA256 = audit.RuntimeSHA256
	j.EntryLink = audit.Entry.LinkTarget
	j.DeferredTasks = pendingDeferredTasks(audit, opts.Root)
	j.setState(StatePrepared, "snapshot and plan written")
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write journal failed", Err: err}
	}
	report.State = StatePrepared
	report.ProjectCronLines = countProjectCronLines(opts.Root)
	if len(j.DeferredTasks) > 0 {
		report.Warnings = append(report.Warnings, "deferred-tasks:"+strings.Join(j.DeferredTasks, ","))
	}
	return report, audit, nil
}

func pathsFor(root string) host.Paths {
	p, _ := host.NewPaths(root)
	return p
}

func runnableFile(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if fi.Mode().Perm()&0o111 == 0 {
		return errors.New("not executable")
	}
	return nil
}

func readOrCreateJournal(root string) (Journal, error) {
	j, err := readJournal(root)
	if err != nil {
		if strings.Contains(err.Error(), "no bridge journal") {
			return Journal{SchemaVersion: JournalSchema, State: StateDiscovered}, nil
		}
		return Journal{}, &Error{Code: 5, Msg: "journal unusable", Err: err}
	}
	return j, nil
}

func writePlan(root string, audit Audit) error {
	p := mustResolve(root, planRel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeAtomic(p, b, 0o640)
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
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

// writeSnapshot stores every rollback reference. Certificate and config
// contents are not copied; only hashes are kept.
func writeSnapshot(root string, audit Audit) error {
	dir := mustResolve(root, snapshotRel)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// The legacy script is copied because it is the executable fallback.
	if audit.LegacyScript.SHA256 != "" {
		src := mustResolve(root, legacyScriptRel)
		dst := filepath.Join(dir, "legacy-install.sh")
		if err := copyFileAtomic(src, dst, 0o755); err != nil {
			return err
		}
	}
	// A regular entry is backed up so recovery can restore bytes, not guesses.
	if audit.Entry.Exists && !audit.Entry.IsSymlink && audit.Entry.SHA256 != "" {
		src := mustResolve(root, entryRel)
		dst := filepath.Join(dir, "entry-idleleo")
		if err := copyFileAtomic(src, dst, 0o755); err != nil {
			return err
		}
	}
	for name, u := range audit.Units {
		if !u.Present {
			continue
		}
		rel := unitRelFor(name)
		src := mustResolve(root, rel)
		dst := filepath.Join(dir, "unit-"+name+".service")
		if err := copyFileAtomic(src, dst, 0o644); err != nil {
			return err
		}
	}
	entryJSON, _ := json.MarshalIndent(audit.Entry, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "entry.json"), append(entryJSON, '\n'), 0o640); err != nil {
		return err
	}
	certsJSON, _ := json.MarshalIndent(audit.CertFiles, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "certs.json"), append(certsJSON, '\n'), 0o640); err != nil {
		return err
	}
	nginxJSON, _ := json.MarshalIndent(audit.NginxFiles, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "nginx.json"), append(nginxJSON, '\n'), 0o640); err != nil {
		return err
	}
	// Only project cron lines are recorded; the user's crontab is never copied.
	lines, err := projectCronLines(root)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, "cron.project.lines"), []byte(strings.Join(lines, "\n")), 0o640); err != nil {
		return err
	}
	return nil
}

func unitRelFor(name string) string {
	if name == "nginx" {
		return unitNginxRel
	}
	return unitXrayRel
}

// writeMetadata converts ownership metadata without storing secrets.
func writeMetadata(root string, audit Audit) error {
	meta := store.Metadata{
		SchemaVersion: store.ManagerSchemaVersion,
		ActiveEngine:  "xray",
		Role:          audit.Role,
		TLS:           audit.TLS,
		Transport:     audit.Transport,
		RuntimeSHA256: audit.RuntimeSHA256,
		UpdatedAt:     now(),
	}
	if audit.Role == "node" {
		meta.RuntimeConfigPath = runtimeConfigRel
	}
	resources := []string{}
	if audit.Role == "node" {
		resources = append(resources, runtimeConfigRel, unitXrayRel)
	} else {
		resources = append(resources, relayConfRel)
		meta.RuntimeSHA256 = ""
	}
	if len(audit.CertFiles) > 0 {
		resources = append(resources, certDirRel)
	}
	if len(audit.NginxFiles) > 0 {
		resources = append(resources, managedNginxRel)
	}
	if audit.NginxRequired {
		resources = append(resources, unitNginxRel)
	}
	meta.OwnedResources = resources
	p := mustResolve(root, metadataRel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeAtomic(p, b, 0o640)
}

func pendingDeferredTasks(audit Audit, root string) []string {
	out := []string{}
	lines, _ := projectCronLines(root)
	for _, line := range lines {
		switch {
		case strings.Contains(line, "auto_update.sh"):
			out = append(out, "auto-update (no Go scheduled equivalent yet)")
		case strings.Contains(line, "ssl_update.sh"):
			out = append(out, "certificate-renewal cron (no Go scheduled equivalent yet)")
		case strings.Contains(line, "geo_update.sh"):
			out = append(out, "geodata-refresh cron (no Go scheduled equivalent yet)")
		}
	}
	if audit.GeoLegacyCron && len(out) == 0 {
		out = append(out, "geodata-refresh cron")
	}
	sort.Strings(out)
	return out
}

func projectCronLines(root string) ([]string, error) {
	p := mustResolve(root, crontabRel)
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		if isProjectCronLine(line) {
			out = append(out, line)
		}
	}
	return out, nil
}

func countProjectCronLines(root string) int {
	lines, _ := projectCronLines(root)
	return len(lines)
}

// ValidateOptions describes the read-only pre-flight.
type ValidateOptions struct {
	Root                 string
	XrayBin              string
	NginxBin             string
	AllowContainerWrites bool
}

// ValidateReport records the real validator results.
type ValidateReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	State         string `json:"state"`
	XrayExit      int    `json:"xrayExit"`
	XrayOutput    string `json:"xrayOutput,omitempty"`
	NginxExit     int    `json:"nginxExit"`
	NginxOutput   string `json:"nginxOutput,omitempty"`
	CandidateExit int    `json:"candidateExit"`
	RuntimeSHA256 string `json:"runtimeSha256"`
}

// Validate runs xray -test, nginx -t and the candidate binary without
// modifying the runtime config, certificates, users or services.
func Validate(ctx context.Context, opts ValidateOptions) (ValidateReport, error) {
	report := ValidateReport{SchemaVersion: 1}
	if err := requireWriteAccess(opts.Root, opts.AllowContainerWrites); err != nil {
		return report, err
	}
	lock, err := lockForWrite(opts.Root)
	if err != nil {
		return report, err
	}
	if lock != nil {
		defer lock.Release()
	}
	j, err := readJournal(opts.Root)
	if err != nil {
		return report, &Error{Code: 2, Msg: "prepare first", Err: err}
	}
	switch j.State {
	case StatePrepared, StateValidated:
	case StateActivating, StateCommitted, StateRollbackRequired, StateRecoveryRequired:
		return report, &Error{Code: 3, Msg: "validation is not allowed in state " + j.State}
	}
	audit, err := AuditMigration(opts.Root)
	if err != nil {
		return report, &Error{Code: 1, Msg: "audit failed", Err: err}
	}
	if audit.Verdict == VerdictBlocked {
		return report, &Error{Code: 3, Msg: "migration blocked by audit"}
	}
	if audit.RuntimeSHA256 != "" && j.RuntimeSHA256 != "" && audit.RuntimeSHA256 != j.RuntimeSHA256 {
		return report, &Error{Code: 6, Msg: "runtime config drifted since prepare"}
	}
	report.RuntimeSHA256 = audit.RuntimeSHA256

	candPath := mustResolve(opts.Root, candidateRel)
	candSHA, err := hashFile(candPath)
	if err != nil || candSHA != j.CandidateSHA256 {
		return report, &Error{Code: 4, Msg: "candidate binary changed or is missing"}
	}
	res, err := host.Run(ctx, host.ExecSpec{Path: candPath, Args: []string{"version"}})
	if err != nil {
		return report, &Error{Code: 4, Msg: "candidate binary is not runnable", Err: err}
	}
	report.CandidateExit = res.ExitCode
	if res.ExitCode != 0 {
		return report, &Error{Code: 4, Msg: "candidate binary failed to run: " + strings.TrimSpace(res.Stderr)}
	}

	if audit.Role == "node" {
		if opts.XrayBin == "" {
			return report, &Error{Code: 2, Msg: "--xray validator is required for a node"}
		}
		res, err := host.Run(ctx, host.ExecSpec{Path: opts.XrayBin, Args: []string{"-test", "-config", audit.RuntimePath}})
		if err != nil {
			return report, &Error{Code: 4, Msg: "xray validator could not run", Err: err}
		}
		report.XrayExit, report.XrayOutput = res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout)
		if res.ExitCode != 0 {
			return report, &Error{Code: 4, Msg: "xray -test rejected the migrated config"}
		}
	}
	if audit.NginxRequired {
		if opts.NginxBin == "" {
			return report, &Error{Code: 2, Msg: "--nginx validator is required for this installation"}
		}
		conf := mustResolve(opts.Root, nginxConfRel)
		res, err := host.Run(ctx, host.ExecSpec{Path: opts.NginxBin, Args: []string{"-t", "-c", conf}})
		if err != nil {
			return report, &Error{Code: 4, Msg: "nginx validator could not run", Err: err}
		}
		report.NginxExit, report.NginxOutput = res.ExitCode, strings.TrimSpace(res.Stderr+res.Stdout)
		if res.ExitCode != 0 {
			return report, &Error{Code: 4, Msg: "nginx -t rejected the migrated layout"}
		}
	}
	if err := verifyMetadata(opts.Root); err != nil {
		return report, &Error{Code: 4, Msg: "converted metadata invalid", Err: err}
	}

	j.setState(StateValidated, fmt.Sprintf("xray=%d nginx=%d candidate=%d", report.XrayExit, report.NginxExit, report.CandidateExit))
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, &Error{Code: 13, Msg: "write journal failed", Err: err}
	}
	report.State = StateValidated
	return report, nil
}

func verifyMetadata(root string) error {
	meta, _, err := store.LoadMetadata(pathsFor(root))
	if err != nil {
		return err
	}
	if meta.Role != "node" && meta.Role != "relay" {
		return errors.New("metadata role is invalid")
	}
	return nil
}

// ActivateOptions describes the entry switch.
type ActivateOptions struct {
	Root                 string
	Crontab              string
	Fault                string
	AllowContainerWrites bool
}

// ActivateReport is the committed migration result.
type ActivateReport struct {
	SchemaVersion  int      `json:"schemaVersion"`
	State          string   `json:"state"`
	Entry          string   `json:"entry"`
	EntryLink      string   `json:"entryLink"`
	InstalledSHA   string   `json:"installedSha256"`
	RemovedCron    int      `json:"removedCronLines"`
	DeferredTasks  []string `json:"deferredTasks"`
	RuntimeSHA256  string   `json:"runtimeSha256"`
	ServiceXray    string   `json:"serviceXray"`
	ServiceNginx   string   `json:"serviceNginx"`
	ServiceEnabled string   `json:"serviceEnabled"`
}

// Activate switches /usr/bin/idleleo to the Go binary, removes only project
// cron lines and commits the journal. It never restarts services.
func Activate(ctx context.Context, opts ActivateOptions) (ActivateReport, error) {
	report := ActivateReport{SchemaVersion: 1, DeferredTasks: []string{}}
	if err := requireWriteAccess(opts.Root, opts.AllowContainerWrites); err != nil {
		return report, err
	}
	lock, err := lockForWrite(opts.Root)
	if err != nil {
		return report, err
	}
	if lock != nil {
		defer lock.Release()
	}
	j, err := readJournal(opts.Root)
	if err != nil {
		return report, &Error{Code: 2, Msg: "prepare and validate first", Err: err}
	}
	if j.State != StateValidated {
		return report, &Error{Code: 3, Msg: "activation requires state VALIDATED, got " + j.State}
	}
	installedPath := mustResolve(opts.Root, installedRel)
	candPath := mustResolve(opts.Root, candidateRel)
	candSHA, err := hashFile(candPath)
	if err != nil || candSHA != j.CandidateSHA256 {
		return report, &Error{Code: 4, Msg: "candidate binary missing or changed"}
	}
	recPath := mustResolve(opts.Root, recoveryBinRel)
	if err := runnableFile(recPath); err != nil {
		return report, &Error{Code: 3, Msg: "recovery entry is missing; activation refused", Err: err}
	}
	if sha, err := hashFile(recPath); err != nil || (j.RecoverySHA256 != "" && sha != j.RecoverySHA256) {
		return report, &Error{Code: 3, Msg: "recovery binary hash mismatch; activation refused"}
	}

	j.setState(StateActivating, "activation started")
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, &Error{Code: 13, Msg: "write journal failed", Err: err}
	}
	if opts.Fault == "after-activating" {
		os.Exit(70)
	}

	if err := copyFileAtomic(candPath, installedPath, 0o755); err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "install binary failed", Err: err})
	}
	if sha, err := hashFile(installedPath); err != nil || sha != candSHA {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "installed binary hash mismatch"})
	}
	report.InstalledSHA = candSHA

	legacySrc := mustResolve(opts.Root, legacyScriptRel)
	legacyDst := mustResolve(opts.Root, legacyBackupRel)
	if err := copyFileAtomic(legacySrc, legacyDst, 0o755); err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "backup legacy script failed", Err: err})
	}

	entryPath := mustResolve(opts.Root, entryRel)
	if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "create entry directory failed", Err: err})
	}
	tmpLink := filepath.Join(filepath.Dir(entryPath), ".idleleo-bridge.tmp")
	_ = os.Remove(tmpLink)
	if err := os.Symlink(installedPath, tmpLink); err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "create entry symlink failed", Err: err})
	}
	if err := os.Rename(tmpLink, entryPath); err != nil {
		_ = os.Remove(tmpLink)
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "switch entry failed", Err: err})
	}
	report.Entry, report.EntryLink = entryPath, installedPath
	if opts.Fault == "after-entry-switch" {
		os.Exit(70)
	}

	cronPath := opts.Crontab
	if cronPath == "" {
		cronPath = mustResolve(opts.Root, crontabRel)
	}
	removed, err := rewriteCrontab(cronPath)
	if err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "rewrite cron failed", Err: err})
	}
	report.RemovedCron = removed
	j.RemovedCron = removed
	if opts.Fault == "after-cron" {
		os.Exit(70)
	}

	// Post-checks: the entry must resolve to the installed binary and the
	// binary must run. Services are only inspected, never started.
	if target, err := os.Readlink(entryPath); err != nil || target != installedPath {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "entry does not point at the installed binary"})
	}
	res, err := host.Run(ctx, host.ExecSpec{Path: installedPath, Args: []string{"version"}})
	if err != nil || res.ExitCode != 0 {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "installed binary failed to run"})
	}
	audit, err := AuditMigration(opts.Root)
	if err == nil && audit.RuntimeSHA256 != "" && j.RuntimeSHA256 != "" && audit.RuntimeSHA256 != j.RuntimeSHA256 {
		return failActivation(opts.Root, &j, report, &Error{Code: 6, Msg: "runtime config changed during activation"})
	}
	report.RuntimeSHA256 = j.RuntimeSHA256

	state := serviceState(ctx, opts.Root)
	report.ServiceXray, report.ServiceNginx, report.ServiceEnabled = state.Xray, state.Nginx, state.Enabled

	report.DeferredTasks = append(report.DeferredTasks, pendingDeferredTasks(audit, opts.Root)...)
	j.setState(StateCommitted, fmt.Sprintf("entry switched; removed %d project cron lines", removed))
	j.DeferredTasks = report.DeferredTasks
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, &Error{Code: 13, Msg: "commit journal failed", Err: err}
	}
	report.State = StateCommitted
	return report, nil
}

func failActivation(root string, j *Journal, report ActivateReport, cause error) (ActivateReport, error) {
	rep, rollbackErr := rollback(root, j)
	report.RemovedCron, report.DeferredTasks = 0, []string{}
	if rollbackErr != nil {
		report.State = StateRecoveryRequired
		return report, &Error{Code: 5, Msg: "activation failed and rollback could not complete", Err: fmt.Errorf("%v; %w", cause, rollbackErr)}
	}
	report.State = rep
	return report, cause
}

// RecoverOptions is one recovery request.
type RecoverOptions struct {
	Root                 string
	AllowContainerWrites bool
}

// RecoverReport is the recovery outcome.
type RecoverReport struct {
	SchemaVersion  int      `json:"schemaVersion"`
	PreviousState  string   `json:"previousState"`
	State          string   `json:"state"`
	Actions        []string `json:"actions"`
	RequiresManual bool     `json:"requiresManual"`
	Message        string   `json:"message,omitempty"`
}

// Recover reads the journal and either discards an unactivated candidate or
// restores the previous entry and project cron lines. It never performs a
// silent reverse migration after COMMITTED.
func Recover(opts RecoverOptions) (RecoverReport, error) {
	report := RecoverReport{SchemaVersion: 1, Actions: []string{}}
	if err := requireWriteAccess(opts.Root, opts.AllowContainerWrites); err != nil {
		return report, err
	}
	lock, err := lockForWrite(opts.Root)
	if err != nil {
		return report, err
	}
	if lock != nil {
		defer lock.Release()
	}
	j, err := readJournal(opts.Root)
	if err != nil {
		return report, &Error{Code: 2, Msg: "cannot recover", Err: err}
	}
	report.PreviousState = j.State
	switch j.State {
	case StateCommitted:
		report.State, report.RequiresManual = StateCommitted, true
		report.Message = "migration is committed; no implicit reverse. Restore the legacy entry manually if that is really intended."
		return report, &Error{Code: 3, Msg: report.Message}
	case StateRolledBack:
		report.State, report.Message = StateRolledBack, "already rolled back"
		return report, nil
	case StateDiscovered, StatePrepared, StateValidated:
		report.Actions = append(report.Actions, "discarded unactivated candidate")
		j.setState(StateRolledBack, "discarded before activation")
		if err := writeJournal(opts.Root, &j); err != nil {
			return report, &Error{Code: 13, Msg: "write journal failed", Err: err}
		}
		report.State = StateRolledBack
		return report, nil
	case StateActivating, StateRollbackRequired, StateRecoveryRequired:
		state, actions, rollbackErr := rollbackWithActions(opts.Root, &j)
		report.State, report.Actions = state, actions
		if rollbackErr != nil {
			report.RequiresManual = true
			report.Message = "automatic restore failed; keep the snapshot and inspect manually"
			return report, &Error{Code: 5, Msg: report.Message, Err: rollbackErr}
		}
		return report, nil
	default:
		j.setState(StateRecoveryRequired, "unknown state "+j.State)
		_ = writeJournal(opts.Root, &j)
		report.State, report.RequiresManual = StateRecoveryRequired, true
		return report, &Error{Code: 5, Msg: "unknown journal state"}
	}
}

func rollback(root string, j *Journal) (string, error) {
	state, _, err := rollbackWithActions(root, j)
	return state, err
}

func rollbackWithActions(root string, j *Journal) (string, []string, error) {
	actions := []string{}
	if err := restoreEntry(root); err != nil {
		j.LastError = err.Error()
		j.setState(StateRecoveryRequired, "entry restore failed")
		_ = writeJournal(root, j)
		return StateRecoveryRequired, actions, err
	}
	actions = append(actions, "restored entry")
	if err := restoreCron(root); err != nil {
		j.LastError = err.Error()
		j.setState(StateRecoveryRequired, "cron restore failed")
		_ = writeJournal(root, j)
		return StateRecoveryRequired, actions, err
	}
	actions = append(actions, "restored project cron lines")
	j.LastError = ""
	j.setState(StateRolledBack, "activation rolled back")
	if err := writeJournal(root, j); err != nil {
		return StateRecoveryRequired, actions, err
	}
	return StateRolledBack, actions, nil
}

func restoreEntry(root string) error {
	entryPath := mustResolve(root, entryRel)
	snapDir := mustResolve(root, snapshotRel)
	var info EntryInfo
	if b, err := os.ReadFile(filepath.Join(snapDir, "entry.json")); err == nil {
		_ = json.Unmarshal(b, &info)
	}
	if info.IsSymlink && info.LinkTarget != "" {
		tmp := filepath.Join(filepath.Dir(entryPath), ".idleleo-recover.tmp")
		_ = os.Remove(tmp)
		if err := os.Symlink(info.LinkTarget, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, entryPath); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return syncDir(filepath.Dir(entryPath))
	}
	if info.Exists {
		src := filepath.Join(snapDir, "entry-idleleo")
		return copyFileAtomic(src, entryPath, 0o755)
	}
	if err := os.Remove(entryPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func restoreCron(root string) error {
	removed, err := os.ReadFile(filepath.Join(mustResolve(root, snapshotRel), "cron.project.lines"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cronPath := mustResolve(root, crontabRel)
	current, err := os.ReadFile(cronPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	kept := []string{}
	for _, line := range strings.Split(string(current), "\n") {
		if !isProjectCronLine(line) {
			kept = append(kept, line)
		}
	}
	// Split on "\n" leaves a trailing empty element for a file that ends with a
	// newline. Drop it before re-appending, otherwise recovery inserts a blank
	// line between the surviving user jobs and the restored project jobs.
	for len(kept) > 0 && kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	for _, line := range strings.Split(strings.TrimRight(string(removed), "\n"), "\n") {
		if line != "" {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return writeCrontab(cronPath, "")
	}
	return writeCrontab(cronPath, strings.Join(kept, "\n")+"\n")
}

// rewriteCrontab removes only project lines and keeps everything else.
func rewriteCrontab(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	kept := []string{}
	removed := 0
	for _, line := range strings.Split(string(b), "\n") {
		if isProjectCronLine(line) {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, writeCrontab(path, strings.Join(kept, "\n"))
}

func writeCrontab(path, content string) error {
	fi, err := os.Stat(path)
	mode := os.FileMode(0o600)
	if err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeAtomic(path, []byte(content), mode); err != nil {
		return err
	}
	return nil
}

// StatusReport is the bridge journal view.
type StatusReport struct {
	SchemaVersion int      `json:"schemaVersion"`
	State         string   `json:"state"`
	Verdict       string   `json:"verdict,omitempty"`
	Entry         string   `json:"entry,omitempty"`
	Root          string   `json:"root"`
	DeferredTasks []string `json:"deferredTasks,omitempty"`
	UpdatedAt     string   `json:"updatedAt,omitempty"`
}

// Status reads the journal and the current plan without writing.
func Status(root string) (StatusReport, error) {
	report := StatusReport{SchemaVersion: 1, Root: root}
	if j, err := readJournal(root); err == nil {
		report.State, report.Entry, report.DeferredTasks, report.UpdatedAt = j.State, j.EntryLink, j.DeferredTasks, j.UpdatedAt
	} else if !strings.Contains(err.Error(), "no bridge journal") {
		return report, &Error{Code: 5, Msg: "journal unusable", Err: err}
	}
	if b, err := os.ReadFile(mustResolve(root, planRel)); err == nil {
		var a Audit
		if json.Unmarshal(b, &a) == nil {
			report.Verdict = a.Verdict
		}
	}
	return report, nil
}

func serviceState(ctx context.Context, root string) runtime.ServiceState {
	return runtime.InspectServices(ctx, root)
}
