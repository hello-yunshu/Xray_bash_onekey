package legacybridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
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

// systemWriteGate is a variable so tests can exercise the real-root branch
// without writing to the machine that runs the test suite.
var systemWriteGate = host.RequireSystemWrite

// requireWriteAccess delegates to internal/host. A non-root target must be a
// marked disposable sandbox. The real root allows a genuine host run (no
// container marker) through the shared audit gate, and requires the explicit
// container acknowledgement only when the process really is in a container.
// It never hard-requires /.dockerenv.
func requireWriteAccess(root string, ack bool) error {
	if err := systemWriteGate(root, ack); err != nil {
		return &Error{Code: 2, Msg: "write access refused", Err: err}
	}
	return nil
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
	CandidateManifest    string
	Recovery             string
	AcknowledgeCustom    bool
	Fault                string
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
	CandidateVersion string   `json:"candidateVersion,omitempty"`
	CandidatePinned  bool     `json:"candidatePinned"`
	RecoverySHA256   string   `json:"recoverySha256,omitempty"`
	MetadataPath     string   `json:"metadataPath"`
	ProjectCronLines int      `json:"projectCronLines"`
	RetainedCron     []string `json:"retainedCronLines"`
	CustomItems      int      `json:"customItems"`
	CustomAcked      bool     `json:"customAcknowledged"`
	PermissionFixes  int      `json:"permissionFixes"`
	RillStatus       string   `json:"rillStatus"`
	ScheduledJobs    []string `json:"scheduledJobs"`
	DegradedJobs     []string `json:"degradedJobs"`
	Warnings         []string `json:"warnings"`
}

// Prepare audits, snapshots and converts metadata. It never changes the
// entry, cron, services or the runtime Xray config.
func Prepare(ctx context.Context, opts PrepareOptions) (PrepareReport, Audit, error) {
	report := PrepareReport{
		SchemaVersion: 1, Warnings: []string{},
		ScheduledJobs: schedule.Jobs, DegradedJobs: schedule.DegradedJobs,
	}
	audit, err := AuditMigration(opts.Root)
	if err != nil {
		return report, audit, &Error{Code: 1, Msg: "audit failed", Err: err}
	}
	report.Verdict = audit.Verdict
	report.CustomItems = len(audit.CustomItems)
	report.PermissionFixes = len(audit.PermissionFixes)
	report.RillStatus = audit.Rill.Status
	if audit.Verdict == VerdictBlocked {
		return report, audit, &Error{Code: 3, Msg: "migration blocked by audit"}
	}
	if len(audit.CustomItems) > 0 && !opts.AcknowledgeCustom {
		return report, audit, &Error{Code: 6, Msg: fmt.Sprintf(
			"%d custom item(s) need explicit human merge acknowledgment; re-run with --acknowledge-custom after reviewing the audit summary", len(audit.CustomItems))}
	}
	report.CustomAcked = len(audit.CustomItems) > 0 && opts.AcknowledgeCustom
	if report.CustomAcked {
		report.Warnings = append(report.Warnings, fmt.Sprintf("custom-content:%d acknowledged for manual merge", len(audit.CustomItems)))
	}
	for _, fix := range audit.PermissionFixes {
		report.Warnings = append(report.Warnings, fmt.Sprintf("permission-fix:%s %s->%s %s", fix.Path, fix.OldMode, fix.NewMode, fix.Reason))
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
	candSHA, candVersion, candWarnings, err := verifyCandidate(ctx, opts.Candidate, opts.CandidateManifest)
	if err != nil {
		return report, audit, &Error{Code: 2, Msg: err.Error()}
	}
	report.Warnings = append(report.Warnings, candWarnings...)
	report.CandidateSHA256 = candSHA
	report.CandidateVersion = candVersion
	report.CandidatePinned = opts.CandidateManifest != ""

	// Read the existing transaction before writing anything. A committed,
	// activating or recovery-required journal is the only copy of the
	// rollback evidence; re-entering prepare must fail without touching
	// the candidate, snapshot, plan or metadata.
	j, err := readOrCreateJournal(opts.Root)
	if err != nil {
		return report, audit, err
	}
	switch j.State {
	case StatePreparing, StateActivating, StateRollbackRequired, StateRecoveryRequired, StateCommitted:
		return report, audit, &Error{Code: 3, Msg: "unfinished or committed bridge transaction in state " + j.State + "; run bridge recover first"}
	}

	if opts.Fault == "disk-full" {
		// Injected before the journal so this fault keeps its contract:
		// no journal, plan, metadata, snapshot or entry change survives.
		return report, audit, &Error{Code: 13, Msg: "write plan failed", Err: syscall.ENOSPC}
	}

	// PREPARING must be durable before the first side effect. Without it a
	// crash after the metadata write leaves a root that claims Go ownership
	// while the legacy entry is still installed.
	metaPath := mustResolve(opts.Root, metadataRel)
	j.MetadataStaged = true
	j.MetadataPreexisting = false
	j.MetadataPreviousSHA256 = ""
	if sha, err := hashFile(metaPath); err == nil {
		j.MetadataPreexisting = true
		j.MetadataPreviousSHA256 = sha
	}
	j.CandidateSHA256 = candSHA
	j.setState(StatePreparing, "prepare started; candidate "+candVersion+" verified")
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write journal failed", Err: err}
	}

	candPath := mustResolve(opts.Root, candidateRel)
	if err := copyFileAtomic(opts.Candidate, candPath, 0o755); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write candidate failed", Err: err}
	}
	if sha, err := hashFile(candPath); err != nil || sha != candSHA {
		return report, audit, &Error{Code: 13, Msg: "candidate copy verification failed"}
	}

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
	if j.MetadataPreexisting {
		backup := filepath.Join(report.SnapshotPath, "metadata.prev.json")
		if err := copyFileAtomic(metaPath, backup, 0o640); err != nil {
			return report, audit, &Error{Code: 13, Msg: "back up existing metadata failed", Err: err}
		}
	}

	metaBytes, err := buildMetadata(audit)
	if err != nil {
		return report, audit, &Error{Code: 13, Msg: "build metadata failed", Err: err}
	}
	j.MetadataNewSHA256 = hashBytes(metaBytes)
	j.setState(StatePreparing, "metadata staged; journal updated before writing it")
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write journal failed", Err: err}
	}
	if err := writeAtomic(metaPath, metaBytes, 0o640); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write metadata failed", Err: err}
	}
	report.MetadataPath = metaPath

	if opts.Fault == "crash-after-metadata" {
		// Keeps PREPARING on disk exactly like a process kill between the
		// metadata write and the PREPARED update.
		return report, audit, &Error{Code: 13, Msg: "simulated crash after metadata write", Err: errors.New("crashed between metadata and journal")}
	}

	if _, _, err := store.LoadMetadata(pathsFor(opts.Root)); err != nil {
		return report, audit, &Error{Code: 13, Msg: "converted metadata does not load", Err: err}
	}

	j.CandidateSHA256 = candSHA
	if report.RecoverySHA256 != "" {
		j.RecoverySHA256 = report.RecoverySHA256
	}
	j.PlanSHA256 = planSHA
	j.RuntimeSHA256 = audit.RuntimeSHA256
	j.EntryLink = audit.Entry.LinkTarget
	// The legacy cron jobs are taken over by the native scheduler at
	// activation, except the ones Go cannot execute yet. Those stay installed:
	// a degraded result is not a reason to remove renewal/update coverage.
	j.DeferredTasks = []string{}
	j.ScheduledJobs = schedule.Jobs
	j.DegradedJobs = schedule.DegradedJobs
	j.RetainedCron = retainedCronLines(mustResolve(opts.Root, crontabRel))
	j.setState(StatePrepared, "snapshot and plan written")
	if err := writeJournal(opts.Root, &j); err != nil {
		return report, audit, &Error{Code: 13, Msg: "write journal failed", Err: err}
	}
	report.State = StatePrepared
	report.ProjectCronLines = countProjectCronLines(opts.Root)
	report.RetainedCron = j.RetainedCron
	if len(report.RetainedCron) > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"retained %d legacy cron line(s) for jobs without a Go executor yet (auto_update.sh, ssl_update.sh)",
			len(report.RetainedCron)))
	}
	for _, d := range schedule.DegradedJobs {
		report.Warnings = append(report.Warnings, "degraded:"+d)
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
	// Rill is never written by the bridge; the snapshot only proves that the
	// handover state is byte-identical before and after the migration window.
	rillJSON, _ := json.MarshalIndent(audit.Rill, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "rill.json"), append(rillJSON, '\n'), 0o640); err != nil {
		return err
	}
	customJSON, _ := json.MarshalIndent(audit.CustomItems, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "custom.json"), append(customJSON, '\n'), 0o640); err != nil {
		return err
	}
	permJSON, _ := json.MarshalIndent(audit.PermissionFixes, "", "  ")
	if err := writeAtomic(filepath.Join(dir, "permissions.json"), append(permJSON, '\n'), 0o640); err != nil {
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

// buildMetadata converts ownership metadata without storing secrets. It is
// separated from the write so the journal can record the exact digest before
// the file exists.
func buildMetadata(audit Audit) ([]byte, error) {
	meta := store.Metadata{
		SchemaVersion: store.ManagerSchemaVersion,
		ActiveEngine:  "xray",
		Provenance:    "legacy",
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
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// projectCronLines returns only the cron lines owned by this project.
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
	SchemaVersion            int    `json:"schemaVersion"`
	State                    string `json:"state"`
	XrayExit                 int    `json:"xrayExit"`
	XrayOutput               string `json:"xrayOutput,omitempty"`
	NginxExit                int    `json:"nginxExit"`
	NginxOutput              string `json:"nginxOutput,omitempty"`
	CandidateExit            int    `json:"candidateExit"`
	CandidateStatusExit      int    `json:"candidateStatusExit"`
	CandidateInstalled       bool   `json:"candidateInstalled"`
	CandidateMatchesMetadata bool   `json:"candidateMatchesMetadata"`
	RuntimeSHA256            string `json:"runtimeSha256"`
	RillStatus               string `json:"rillStatus"`
	RillUnchanged            bool   `json:"rillUnchanged"`
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

	// The candidate must load the converted manager.json for real. This is the
	// 03-D closure: not just a Go unit test, but the actual binary reading the
	// metadata written by Prepare.
	statusRes, err := host.Run(ctx, host.ExecSpec{
		Path: candPath, Args: []string{"--root", opts.Root, "status", "--json"}, Timeout: 30 * time.Second,
	})
	if err != nil {
		return report, &Error{Code: 4, Msg: "candidate status could not run", Err: err}
	}
	report.CandidateStatusExit = statusRes.ExitCode
	if statusRes.ExitCode != 0 {
		return report, &Error{Code: 4, Msg: "candidate status failed on converted metadata: " + strings.TrimSpace(statusRes.Stderr)}
	}
	var candidateStatus struct {
		Installed bool `json:"installed"`
		Config    struct {
			MatchesMetadata bool `json:"matchesMetadata"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(statusRes.Stdout), &candidateStatus); err != nil {
		return report, &Error{Code: 4, Msg: "candidate status did not return JSON", Err: err}
	}
	report.CandidateInstalled = candidateStatus.Installed
	report.CandidateMatchesMetadata = candidateStatus.Config.MatchesMetadata
	if !candidateStatus.Installed {
		return report, &Error{Code: 4, Msg: "candidate reported installed=false for converted metadata"}
	}
	if audit.Role == "node" && !candidateStatus.Config.MatchesMetadata {
		return report, &Error{Code: 4, Msg: "candidate metadata/config hash does not match the converted manager.json"}
	}

	report.RillStatus = audit.Rill.Status
	report.RillUnchanged = rillUnchanged(opts.Root, audit.Rill)
	if !report.RillUnchanged {
		return report, &Error{Code: 6, Msg: "Rill handover state changed since prepare"}
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

// rillUnchanged compares only content hashes: the observation age may cross a
// freshness threshold during a slow migration without the state being touched.
func rillUnchanged(root string, current RillInfo) bool {
	b, err := os.ReadFile(filepath.Join(mustResolve(root, snapshotRel), "rill.json"))
	if err != nil {
		return true
	}
	var snap RillInfo
	if err := json.Unmarshal(b, &snap); err != nil {
		return false
	}
	return snap.Installed == current.Installed &&
		snap.ConfigSHA256 == current.ConfigSHA256 &&
		snap.ObservationSHA256 == current.ObservationSHA256
}

func parseMode(s string) (os.FileMode, error) {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(v), nil
}

func applyPermissionFixes(root string) (int, error) {
	b, err := os.ReadFile(filepath.Join(mustResolve(root, snapshotRel), "permissions.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var fixes []PermissionFix
	if err := json.Unmarshal(b, &fixes); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range fixes {
		mode, err := parseMode(f.NewMode)
		if err != nil {
			return n, err
		}
		p := mustResolve(root, f.Path)
		if f.NewGID != f.OldGID && f.NewGID != 0 {
			if err := os.Chown(p, -1, f.NewGID); err != nil {
				return n, err
			}
		}
		if err := os.Chmod(p, mode); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func restorePermissions(root string) (int, error) {
	b, err := os.ReadFile(filepath.Join(mustResolve(root, snapshotRel), "permissions.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var fixes []PermissionFix
	if err := json.Unmarshal(b, &fixes); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range fixes {
		mode, err := parseMode(f.OldMode)
		if err != nil {
			return n, err
		}
		p := mustResolve(root, f.Path)
		if f.NewGID != f.OldGID {
			if err := os.Chown(p, -1, f.OldGID); err != nil {
				return n, err
			}
		}
		if err := os.Chmod(p, mode); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
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
	SchemaVersion   int      `json:"schemaVersion"`
	State           string   `json:"state"`
	Entry           string   `json:"entry"`
	EntryLink       string   `json:"entryLink"`
	InstalledSHA    string   `json:"installedSha256"`
	RemovedCron     int      `json:"removedCronLines"`
	RetainedCron    []string `json:"retainedCronLines"`
	DeferredTasks   []string `json:"deferredTasks"`
	ScheduledJobs   []string `json:"scheduledJobs"`
	DegradedJobs    []string `json:"degradedJobs"`
	RuntimeSHA256   string   `json:"runtimeSha256"`
	ServiceXray     string   `json:"serviceXray"`
	ServiceNginx    string   `json:"serviceNginx"`
	ServiceEnabled  string   `json:"serviceEnabled"`
	Timer           string   `json:"timer"`
	PermissionFixes int      `json:"permissionFixes"`
	RillStatus      string   `json:"rillStatus"`
	RillUnchanged   bool     `json:"rillUnchanged"`
}

// Activate switches /usr/bin/idleleo to the Go binary, removes only project
// cron lines and commits the journal. It never restarts services.
func Activate(ctx context.Context, opts ActivateOptions) (ActivateReport, error) {
	report := ActivateReport{
		SchemaVersion: 1, DeferredTasks: []string{},
		ScheduledJobs: schedule.Jobs, DegradedJobs: schedule.DegradedJobs,
	}
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
	if err := verifyEntrySnapshot(opts.Root); err != nil {
		return report, &Error{Code: 6, Msg: "entry changed since prepare; activation refused", Err: err}
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
	report.RetainedCron = retainedCronLines(cronPath)
	j.RetainedCron = report.RetainedCron
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
	report.RillStatus = audit.Rill.Status
	report.RillUnchanged = rillUnchanged(opts.Root, audit.Rill)
	if !report.RillUnchanged {
		return failActivation(opts.Root, &j, report, &Error{Code: 6, Msg: "Rill handover state changed during activation"})
	}

	// Apply the permission and key-mode fixes recorded at prepare time. The
	// snapshot keeps the old modes so rollback can restore them exactly.
	fixed, err := applyPermissionFixes(opts.Root)
	if err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "apply permission fixes failed", Err: err})
	}
	report.PermissionFixes = fixed

	// Install the native scheduler before committing: after this point the
	// legacy cron lines are gone, so the takeover must already exist.
	sched, err := schedule.Install(ctx, schedule.InstallOptions{Root: opts.Root, IntervalSeconds: schedule.DefaultIntervalSeconds})
	if err != nil {
		return failActivation(opts.Root, &j, report, &Error{Code: 13, Msg: "install native schedule failed", Err: err})
	}
	report.Timer = sched.Systemd
	if opts.Fault == "after-schedule" {
		os.Exit(70)
	}

	state := serviceState(ctx, opts.Root)
	report.ServiceXray, report.ServiceNginx, report.ServiceEnabled = state.Xray, state.Nginx, state.Enabled

	report.DeferredTasks = []string{}
	j.setState(StateCommitted, fmt.Sprintf("entry switched; removed %d project cron lines; retained %d for jobs without a Go executor; native schedule installed", removed, len(report.RetainedCron)))
	j.DeferredTasks = []string{}
	j.ScheduledJobs = schedule.Jobs
	j.DegradedJobs = schedule.DegradedJobs
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
	RillUnchanged  bool     `json:"rillUnchanged"`
	Message        string   `json:"message,omitempty"`
}

// Recover reads the journal and either discards an unactivated candidate or
// restores the previous entry and project cron lines. It never performs a
// silent reverse migration after COMMITTED.
func Recover(opts RecoverOptions) (RecoverReport, error) {
	report := RecoverReport{SchemaVersion: 1, Actions: []string{}, RillUnchanged: true}
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
	report.RillUnchanged = rillUnchanged(opts.Root, currentRill(opts.Root))
	switch j.State {
	case StateCommitted:
		report.State, report.RequiresManual = StateCommitted, true
		report.Message = "migration is committed; no implicit reverse. Restore the legacy entry manually if that is really intended."
		return report, &Error{Code: 3, Msg: report.Message}
	case StateRolledBack:
		report.State, report.Message = StateRolledBack, "already rolled back"
		return report, nil
	case StateDiscovered:
		report.Actions = append(report.Actions, "discarded unactivated candidate")
		j.setState(StateRolledBack, "discarded before activation")
		if err := writeJournal(opts.Root, &j); err != nil {
			return report, &Error{Code: 13, Msg: "write journal failed", Err: err}
		}
		report.State = StateRolledBack
		return report, nil
	case StatePreparing, StatePrepared, StateValidated:
		report.Actions = append(report.Actions, "discarded unactivated candidate")
		actions, discardErr := discardStagedState(opts.Root, &j)
		report.Actions = append(report.Actions, actions...)
		if discardErr != nil {
			j.setState(StateRecoveryRequired, "discard failed: "+discardErr.Error())
			_ = writeJournal(opts.Root, &j)
			report.State, report.RequiresManual = StateRecoveryRequired, true
			report.Message = "automatic discard failed; staged metadata was left untouched for manual inspection"
			return report, &Error{Code: 5, Msg: report.Message, Err: discardErr}
		}
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

// discardStagedState removes what prepare staged but activation never used.
// It exists because a crash after the metadata write used to leave a root whose
// manager metadata claimed ownership while the legacy entry was still active:
// prepare would then refuse to run and the next auditor would see a half
// migration.
func discardStagedState(root string, j *Journal) ([]string, error) {
	actions := []string{}
	if !j.MetadataStaged {
		return actions, nil
	}
	metaPath := mustResolve(root, metadataRel)
	current, err := hashFile(metaPath)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return actions, err
	}
	if j.MetadataPreexisting {
		backup := filepath.Join(mustResolve(root, snapshotRel), "metadata.prev.json")
		switch {
		case !exists:
			// The staged write never landed; nothing to restore.
		case current == j.MetadataPreviousSHA256:
			// Never replaced (or already restored); the backup is identical.
		case j.MetadataNewSHA256 == "" || current != j.MetadataNewSHA256:
			return actions, errors.New("manager metadata changed outside this bridge transaction; refusing to overwrite it")
		default:
			if _, statErr := os.Stat(backup); statErr != nil {
				return actions, fmt.Errorf("previous manager metadata backup is missing: %w", statErr)
			}
			if err := copyFileAtomic(backup, metaPath, 0o640); err != nil {
				return actions, err
			}
			actions = append(actions, "restored pre-migration manager metadata")
		}
	} else if exists {
		if j.MetadataNewSHA256 == "" || current != j.MetadataNewSHA256 {
			return actions, errors.New("manager metadata appeared outside this bridge transaction; refusing to delete it")
		}
		if err := os.Remove(metaPath); err != nil {
			return actions, err
		}
		actions = append(actions, "removed staged manager metadata")
	}

	for _, rel := range []string{planRel, candidateRel} {
		p := mustResolve(root, rel)
		if err := os.Remove(p); err == nil {
			actions = append(actions, "removed "+rel)
		} else if !os.IsNotExist(err) {
			return actions, err
		}
	}
	if err := os.RemoveAll(mustResolve(root, snapshotRel)); err != nil {
		return actions, err
	}
	actions = append(actions, "removed staged snapshot")
	return actions, nil
}

func rollback(root string, j *Journal) (string, error) {
	state, _, err := rollbackWithActions(root, j)
	return state, err
}

func currentRill(root string) RillInfo {
	a, err := AuditMigration(root)
	if err != nil {
		return RillInfo{}
	}
	return a.Rill
}

func rollbackWithActions(root string, j *Journal) (string, []string, error) {
	actions := []string{}
	// Remove the native schedule first: once the entry is restored, a timer
	// pointing at the Go binary must not keep firing.
	if removed, err := schedule.Remove(context.Background(), root); err == nil && len(removed) > 0 {
		actions = append(actions, "removed native schedule units")
	} else if err != nil {
		j.LastError = err.Error()
		j.setState(StateRecoveryRequired, "schedule removal failed")
		_ = writeJournal(root, j)
		return StateRecoveryRequired, actions, err
	}
	if n, err := restorePermissions(root); err != nil {
		j.LastError = err.Error()
		j.setState(StateRecoveryRequired, "permission restore failed")
		_ = writeJournal(root, j)
		return StateRecoveryRequired, actions, err
	} else if n > 0 {
		actions = append(actions, fmt.Sprintf("restored %d file mode(s)", n))
	}
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

// verifyEntrySnapshot refuses activation when the entry no longer matches the
// exact object recorded at prepare time. Another administrator or installer may
// have replaced it between prepare and activate; switching it then would
// silently discard that change.
func verifyEntrySnapshot(root string) error {
	entryPath := mustResolve(root, entryRel)
	snapDir := mustResolve(root, snapshotRel)
	var info EntryInfo
	b, err := os.ReadFile(filepath.Join(snapDir, "entry.json"))
	if err != nil {
		return fmt.Errorf("entry snapshot is missing: %w", err)
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return fmt.Errorf("entry snapshot is invalid: %w", err)
	}
	fi, err := os.Lstat(entryPath)
	if err != nil {
		if os.IsNotExist(err) && !info.Exists && !info.IsSymlink {
			return nil
		}
		return fmt.Errorf("entry disappeared since prepare")
	}
	switch {
	case info.IsSymlink:
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("entry is no longer a symlink")
		}
		target, err := os.Readlink(entryPath)
		if err != nil {
			return err
		}
		if target != info.LinkTarget {
			return fmt.Errorf("entry target changed since prepare")
		}
		return nil
	case info.Exists:
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("entry is no longer a regular file")
		}
		want, err := hashFile(filepath.Join(snapDir, "entry-idleleo"))
		if err != nil {
			return fmt.Errorf("entry snapshot is incomplete: %w", err)
		}
		got, err := hashFile(entryPath)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("entry content changed since prepare")
		}
		return nil
	default:
		return fmt.Errorf("entry appeared since prepare")
	}
}

// entryRestoreSafe reports whether the current entry is still the object this
// transaction installed (or is already the snapshot target). Anything else is a
// third-party change that rollback must preserve instead of overwriting.
func entryRestoreSafe(root, entryPath, snapDir string, info EntryInfo) (bool, error) {
	installedPath := mustResolve(root, installedRel)
	fi, err := os.Lstat(entryPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing is there to preserve; restoring the snapshot is safe.
			return true, nil
		}
		return false, err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(entryPath)
		if err != nil {
			return false, err
		}
		if target == installedPath {
			return true, nil
		}
		if info.IsSymlink && target == info.LinkTarget {
			return true, nil
		}
		return false, nil
	case fi.Mode().IsRegular():
		got, err := hashFile(entryPath)
		if err != nil {
			return false, err
		}
		if installedSHA, err := hashFile(installedPath); err == nil && got == installedSHA {
			return true, nil
		}
		if info.Exists {
			if want, err := hashFile(filepath.Join(snapDir, "entry-idleleo")); err == nil && got == want {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, nil
	}
}

func restoreEntry(root string) error {
	entryPath := mustResolve(root, entryRel)
	snapDir := mustResolve(root, snapshotRel)
	var info EntryInfo
	if b, err := os.ReadFile(filepath.Join(snapDir, "entry.json")); err == nil {
		_ = json.Unmarshal(b, &info)
	}
	if ok, err := entryRestoreSafe(root, entryPath, snapDir, info); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("entry was replaced outside this bridge transaction; refusing to overwrite it")
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

// rewriteCrontab removes only project lines Go can execute, and keeps the
// legacy lines whose jobs have no Go equivalent yet.
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
			if isRetainedCronLine(line) {
				kept = append(kept, line)
				continue
			}
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

// retainedCronLines returns the project cron lines that activation leaves in
// place because Go cannot perform the job yet.
func retainedCronLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		if isRetainedCronLine(line) {
			out = append(out, line)
		}
	}
	return out
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
	ScheduledJobs []string `json:"scheduledJobs,omitempty"`
	DegradedJobs  []string `json:"degradedJobs,omitempty"`
	RillStatus    string   `json:"rillStatus,omitempty"`
	UpdatedAt     string   `json:"updatedAt,omitempty"`
}

// Status reads the journal and the current plan without writing.
func Status(root string) (StatusReport, error) {
	report := StatusReport{SchemaVersion: 1, Root: root}
	if j, err := readJournal(root); err == nil {
		report.State, report.Entry, report.DeferredTasks, report.UpdatedAt = j.State, j.EntryLink, j.DeferredTasks, j.UpdatedAt
		report.ScheduledJobs, report.DegradedJobs = j.ScheduledJobs, j.DegradedJobs
	} else if !strings.Contains(err.Error(), "no bridge journal") {
		return report, &Error{Code: 5, Msg: "journal unusable", Err: err}
	}
	if b, err := os.ReadFile(mustResolve(root, planRel)); err == nil {
		var a Audit
		if json.Unmarshal(b, &a) == nil {
			report.Verdict = a.Verdict
			report.RillStatus = a.Rill.Status
		}
	}
	return report, nil
}

func serviceState(ctx context.Context, root string) runtime.ServiceState {
	return runtime.InspectServices(ctx, root)
}
