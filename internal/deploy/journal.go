package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// Persistent deploy journal. The in-memory backups protect failures inside one
// process; this file protects the same transaction across SIGKILL and reboot.
// A transaction is only considered complete when the journal reaches
// COMMITTED. Anything else is rolled back from the on-disk snapshot by the next
// process that takes the deploy lock.
const (
	deployJournalSchema = 1
	DeployStateDirRel   = "var/lib/idleleo/deploy"

	JournalPrepared         = "PREPARED"
	JournalRollingBack      = "ROLLING_BACK"
	JournalCommitted        = "COMMITTED"
	JournalRolledBack       = "ROLLED_BACK"
	JournalRecoveryRequired = "RECOVERY_REQUIRED"
)

type journalEntry struct {
	Rel         string   `json:"rel"`
	Exists      bool     `json:"exists"`
	Link        string   `json:"link,omitempty"`
	Mode        uint32   `json:"mode,omitempty"`
	UID         int      `json:"uid"`
	GID         int      `json:"gid"`
	MissingDirs []string `json:"missingDirs,omitempty"`
	Snapshot    string   `json:"snapshot,omitempty"`
}

type journalService struct {
	Managed     bool   `json:"managed"`
	UnitExisted bool   `json:"unitExisted"`
	Enabled     string `json:"enabled,omitempty"`
	Active      string `json:"active,omitempty"`
}

type deployJournal struct {
	SchemaVersion int            `json:"schemaVersion"`
	State         string         `json:"state"`
	Root          string         `json:"root"`
	CreatedAt     string         `json:"createdAt"`
	UpdatedAt     string         `json:"updatedAt"`
	Mode          string         `json:"mode,omitempty"`
	Transport     string         `json:"transport,omitempty"`
	Entries       []journalEntry `json:"entries"`
	LogDirMissing []string       `json:"logDirMissing,omitempty"`
	Service       journalService `json:"service"`
	LastError     string         `json:"lastError,omitempty"`
}

// RecoverSpec is one explicit or implicit crash-recovery request.
type RecoverSpec struct {
	Root                 string
	AllowContainerWrites bool
}

// RecoverReport describes what happened to a pending transaction.
type RecoverReport struct {
	JournalState string   `json:"journalState"`
	Action       string   `json:"action"`
	Converged    bool     `json:"converged"`
	Restored     int      `json:"restoredFiles"`
	Warnings     []string `json:"warnings"`
}

func deployDir(paths host.Paths) string {
	return filepath.Join(paths.Root, filepath.FromSlash(DeployStateDirRel))
}

func journalPath(paths host.Paths) string {
	return filepath.Join(deployDir(paths), "journal.json")
}

func snapshotDir(paths host.Paths) string {
	return filepath.Join(deployDir(paths), "snapshot")
}

func relToRoot(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes root: %s", path)
	}
	return rel, nil
}

func applyRoot(paths host.Paths, rel string) (string, error) {
	rel = filepath.FromSlash(rel)
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe journal path: %s", rel)
	}
	out := filepath.Join(paths.Root, clean)
	back, err := filepath.Rel(paths.Root, out)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("journal path escapes root: %s", rel)
	}
	return out, nil
}

func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}

func writeJournal(paths host.Paths, j deployJournal) error {
	j.SchemaVersion = deployJournalSchema
	j.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(deployDir(paths), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeFileAtomic(journalPath(paths), raw, 0o600); err != nil {
		return err
	}
	syncDir(deployDir(paths))
	return nil
}

func loadJournal(paths host.Paths) (*deployJournal, error) {
	raw, err := os.ReadFile(journalPath(paths))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var j deployJournal
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("corrupt deploy journal: %w", err)
	}
	if j.SchemaVersion != deployJournalSchema {
		return nil, fmt.Errorf("unsupported deploy journal schema %d", j.SchemaVersion)
	}
	return &j, nil
}

func cleanupJournal(paths host.Paths) {
	_ = os.RemoveAll(snapshotDir(paths))
	_ = os.Remove(journalPath(paths))
	syncDir(deployDir(paths))
}

// newJournal snapshots every target into the journal directory. Only after the
// journal is fsynced may the caller mutate the live system.
func newJournal(paths host.Paths, backups []fileState, snap serviceState, logDirMissing []string, mode, transport string) (deployJournal, error) {
	if err := os.MkdirAll(snapshotDir(paths), 0o700); err != nil {
		return deployJournal{}, err
	}
	j := deployJournal{
		State:     JournalPrepared,
		Root:      paths.Root,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Mode:      mode,
		Transport: transport,
		Service: journalService{
			Managed: snap.managed, UnitExisted: snap.unitExisted,
			Enabled: snap.enabled, Active: snap.active,
		},
	}
	for i, st := range backups {
		rel, err := relToRoot(paths.Root, st.path)
		if err != nil {
			return deployJournal{}, err
		}
		e := journalEntry{
			Rel: rel, Exists: st.exists, Link: st.link,
			Mode: uint32(st.mode.Perm()), UID: st.uid, GID: st.gid,
		}
		for _, dir := range st.missingDirs {
			drel, relErr := relToRoot(paths.Root, dir)
			if relErr != nil {
				return deployJournal{}, relErr
			}
			e.MissingDirs = append(e.MissingDirs, drel)
		}
		if st.exists && st.link == "" {
			name := fmt.Sprintf("entry-%d", i)
			path := filepath.Join(snapshotDir(paths), name)
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return deployJournal{}, err
			}
			if _, err := f.Write(st.data); err != nil {
				f.Close()
				return deployJournal{}, err
			}
			if err := f.Sync(); err != nil {
				f.Close()
				return deployJournal{}, err
			}
			if err := f.Close(); err != nil {
				return deployJournal{}, err
			}
			e.Snapshot = name
		}
		j.Entries = append(j.Entries, e)
	}
	for _, dir := range logDirMissing {
		drel, err := relToRoot(paths.Root, dir)
		if err != nil {
			return deployJournal{}, err
		}
		j.LogDirMissing = append(j.LogDirMissing, drel)
	}
	syncDir(snapshotDir(paths))
	if err := writeJournal(paths, j); err != nil {
		_ = os.RemoveAll(snapshotDir(paths))
		return deployJournal{}, err
	}
	return j, nil
}

func (e journalEntry) fileState(paths host.Paths) (fileState, error) {
	p, err := applyRoot(paths, e.Rel)
	if err != nil {
		return fileState{}, err
	}
	st := fileState{
		path: p, exists: e.Exists, link: e.Link,
		mode: os.FileMode(e.Mode), uid: e.UID, gid: e.GID,
	}
	for _, dir := range e.MissingDirs {
		dp, err := applyRoot(paths, dir)
		if err != nil {
			return fileState{}, err
		}
		st.missingDirs = append(st.missingDirs, dp)
	}
	if e.Exists && e.Link == "" {
		if e.Snapshot == "" {
			return fileState{}, fmt.Errorf("journal entry %s has no snapshot", e.Rel)
		}
		raw, err := os.ReadFile(filepath.Join(snapshotDir(paths), filepath.Base(e.Snapshot)))
		if err != nil {
			return fileState{}, err
		}
		st.data = raw
	}
	return st, nil
}

func applyJournal(ctx context.Context, paths host.Paths, j deployJournal) error {
	snap := serviceState{
		managed: j.Service.Managed, unitExisted: j.Service.UnitExisted,
		enabled: j.Service.Enabled, active: j.Service.Active,
	}
	restored := make([]fileState, 0, len(j.Entries))
	for _, e := range j.Entries {
		st, err := e.fileState(paths)
		if err != nil {
			return err
		}
		restored = append(restored, st)
	}
	if snap.managed && !snap.unitExisted {
		// A fresh install may have started/enabled the unit before dying.
		_ = serviceCommand(ctx, "stop", "xray")
		_ = serviceCommand(ctx, "disable", "xray")
	}
	for i := len(restored) - 1; i >= 0; i-- {
		// Remove half-written atomic temp files before restoring the target.
		_ = os.Remove(restored[i].path + ".tmp")
		if err := restored[i].restore(); err != nil {
			return err
		}
	}
	var logDirs []string
	for _, rel := range j.LogDirMissing {
		p, err := applyRoot(paths, rel)
		if err != nil {
			return err
		}
		logDirs = append(logDirs, p)
	}
	removeEmptyDirs(logDirs)
	if err := restoreService(ctx, snap); err != nil {
		return err
	}
	if snap.managed && !snap.unitExisted {
		if err := serviceCommand(ctx, "daemon-reload"); err != nil {
			return err
		}
		if got := serviceQuery(ctx, "is-enabled", "xray"); strings.Contains(got, "enabled") {
			return fmt.Errorf("xray.service is still enabled (%q) after recovery", got)
		}
	}
	return nil
}

// recoverPendingLocked converges a journal left by a dead process. The caller
// must already hold the deploy lock.
func recoverPendingLocked(ctx context.Context, paths host.Paths) (RecoverReport, error) {
	rep := RecoverReport{JournalState: "clean", Action: "none", Converged: true, Warnings: []string{}}
	j, err := loadJournal(paths)
	if err != nil {
		return rep, err
	}
	if j == nil {
		return rep, nil
	}
	if j.Root != paths.Root {
		return rep, fmt.Errorf("journal root %q does not match %q", j.Root, paths.Root)
	}
	rep.JournalState = j.State
	switch j.State {
	case JournalCommitted, JournalRolledBack:
		cleanupJournal(paths)
		rep.Action = "cleaned"
		return rep, nil
	case JournalPrepared, JournalRollingBack, JournalRecoveryRequired:
		j.State = JournalRollingBack
		if err := writeJournal(paths, *j); err != nil {
			return rep, err
		}
		if err := applyJournal(ctx, paths, *j); err != nil {
			j.State = JournalRecoveryRequired
			j.LastError = err.Error()
			_ = writeJournal(paths, *j)
			return rep, fmt.Errorf("recovery failed, journal kept as %s: %w", JournalRecoveryRequired, err)
		}
		j.State = JournalRolledBack
		_ = writeJournal(paths, *j)
		cleanupJournal(paths)
		rep.JournalState = JournalRolledBack
		rep.Action = "rolled_back"
		rep.Restored = len(j.Entries)
		return rep, nil
	default:
		return rep, fmt.Errorf("unknown deploy journal state %q", j.State)
	}
}

// Recover is the explicit cross-process recovery entry point.
func Recover(ctx context.Context, spec RecoverSpec) (RecoverReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return RecoverReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return RecoverReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return RecoverReport{}, err
	}
	defer lock.Release()
	return recoverPendingLocked(ctx, paths)
}

func journalMarkCommitted(paths host.Paths, j *deployJournal) error {
	j.State = JournalCommitted
	if err := writeJournal(paths, *j); err != nil {
		return err
	}
	cleanupJournal(paths)
	return nil
}

func journalMarkRolledBack(paths host.Paths, j *deployJournal, cause error) error {
	j.State = JournalRolledBack
	j.LastError = ""
	_ = writeJournal(paths, *j)
	cleanupJournal(paths)
	return cause
}

func journalMarkRecoveryRequired(paths host.Paths, j *deployJournal, cause error) {
	j.State = JournalRecoveryRequired
	j.LastError = cause.Error()
	_ = writeJournal(paths, *j)
}
