package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// Restore transaction states. PREPARED and APPLYING are only observable after
// a hard kill; COMMITTED and ROLLED_BACK are terminal and safe to overwrite.
const (
	RestoreStatePrepared       = "PREPARED"
	RestoreStateApplying       = "APPLYING"
	RestoreStateCommitted      = "COMMITTED"
	RestoreStateRolledBack     = "ROLLED_BACK"
	RestoreStateRecoveryNeeded = "RECOVERY_NEEDED"
)

type restoreFile struct {
	Path      string `json:"path"`
	HadOld    bool   `json:"hadOld"`
	OldSHA256 string `json:"oldSha256,omitempty"`
	OldMode   uint32 `json:"oldMode,omitempty"`
	OldUID    int    `json:"oldUid"`
	OldGID    int    `json:"oldGid"`
	NewSHA256 string `json:"newSha256"`
	Mode      uint32 `json:"mode"`
	Snapshot  string `json:"snapshot,omitempty"`
}

type restoreRecord struct {
	SchemaVersion int           `json:"schemaVersion"`
	ID            string        `json:"id"`
	State         string        `json:"state"`
	Root          string        `json:"root"`
	Archive       string        `json:"archive"`
	ArchiveSHA256 string        `json:"archiveSha256"`
	PreBackup     string        `json:"preBackup,omitempty"`
	StartedAt     string        `json:"startedAt"`
	UpdatedAt     string        `json:"updatedAt"`
	Reason        string        `json:"reason,omitempty"`
	Files         []restoreFile `json:"files"`
}

// RecoverReport describes how an interrupted restore was converged.
type RecoverReport struct {
	SchemaVersion int      `json:"schemaVersion"`
	State         string   `json:"state,omitempty"`
	Action        string   `json:"action"`
	Converged     bool     `json:"converged"`
	Warnings      []string `json:"warnings"`
}

// RecoverOptions controls an explicit convergence pass.
type RecoverOptions struct {
	DryRun bool
	Apply  func(context.Context) error
}

func transactionDir(root string) string {
	return filepath.Join(root, "var/lib/idleleo/transactions")
}

func restoreJournalPath(root string) string {
	return filepath.Join(transactionDir(root), "restore.json")
}

func restoreSnapshotDir(root, id string) string {
	return filepath.Join(transactionDir(root), "restore-"+id)
}

func loadRestoreRecord(root string) (restoreRecord, error) {
	body, err := os.ReadFile(restoreJournalPath(root))
	if err != nil {
		return restoreRecord{}, err
	}
	var rec restoreRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return restoreRecord{}, fmt.Errorf("restore journal is not valid JSON: %w", err)
	}
	return rec, nil
}

func saveRestoreRecord(root string, rec *restoreRecord) error {
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSync(restoreJournalPath(root), append(body, '\n'), 0o600)
}

// restoreFault injects a real SIGKILL at a named point. It is only armed for a
// disposable sandbox root so a production root can never be killed by accident.
func restoreFault(root, name string) {
	if root == "/" {
		return
	}
	if os.Getenv("IDLELEO_RESTORE_FAULT") != name {
		return
	}
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

// restoreApply performs the durable part of a restore. The caller has already
// verified the archive, created the pre-restore backup, staged and validated
// the payload. Any failure rolls back to the snapshot and leaves a terminal
// ROLLED_BACK record; a rollback that itself fails is RECOVERY_NEEDED and must
// be converged with Recover.
func restoreApply(ctx context.Context, root, stage string, manifest Manifest, rep Report, opts RestoreOptions) (Report, error) {
	id := fmt.Sprintf("%d-%d", opts.Now.UnixNano(), os.Getpid())
	if _, err := secureMkdirAll(root, "var/lib/idleleo/transactions", 0o700); err != nil {
		return rep, err
	}
	snapDir := restoreSnapshotDir(root, id)
	if err := os.Mkdir(snapDir, 0o700); err != nil {
		return rep, err
	}

	rec := restoreRecord{
		SchemaVersion: SchemaVersion, ID: id, State: RestoreStatePrepared,
		Root: root, Archive: rep.Archive, ArchiveSHA256: rep.ArchiveSHA256,
		PreBackup: rep.PreBackup, StartedAt: opts.Now.Format(time.RFC3339),
	}
	for i, e := range manifest.Entries {
		dst, err := securePath(root, e.Path, true)
		if err != nil {
			_ = os.RemoveAll(snapDir)
			return rep, err
		}
		file := restoreFile{Path: e.Path, NewSHA256: e.SHA256, Mode: e.Mode}
		fi, statErr := os.Lstat(dst)
		switch {
		case statErr == nil:
			if !fi.Mode().IsRegular() {
				_ = os.RemoveAll(snapDir)
				return rep, fmt.Errorf("refusing to replace a non-regular file: %s", dst)
			}
			body, mode, err := readNoFollow(dst)
			if err != nil {
				_ = os.RemoveAll(snapDir)
				return rep, err
			}
			sum := sha256.Sum256(body)
			file.HadOld = true
			file.OldSHA256 = hex.EncodeToString(sum[:])
			file.OldMode = uint32(mode)
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				file.OldUID = int(st.Uid)
				file.OldGID = int(st.Gid)
			}
			file.Snapshot = fmt.Sprintf("%03d", i)
			if err := writeFileSync(filepath.Join(snapDir, file.Snapshot), body, 0o600); err != nil {
				_ = os.RemoveAll(snapDir)
				return rep, err
			}
		case errors.Is(statErr, os.ErrNotExist):
			// New file: rollback removes it.
		default:
			_ = os.RemoveAll(snapDir)
			return rep, statErr
		}
		rec.Files = append(rec.Files, file)
	}
	if err := saveRestoreRecord(root, &rec); err != nil {
		_ = os.RemoveAll(snapDir)
		return rep, err
	}
	restoreFault(root, "after-prepare")

	rec.State = RestoreStateApplying
	if err := saveRestoreRecord(root, &rec); err != nil {
		return rep, err
	}
	for i := range rec.Files {
		if err := ctx.Err(); err != nil {
			return restoreFailed(root, &rec, rep, err)
		}
		if err := applyRestoreFile(root, stage, &rec.Files[i]); err != nil {
			return restoreFailed(root, &rec, rep, err)
		}
		rep.Restored = append(rep.Restored, rec.Files[i].Path)
		if i == 0 {
			restoreFault(root, "after-first-file")
		}
		if i == len(rec.Files)/2 {
			restoreFault(root, "after-half")
		}
	}
	restoreFault(root, "before-commit")
	if opts.Apply != nil {
		restoreFault(root, "before-service")
		if err := opts.Apply(ctx); err != nil {
			return restoreFailed(root, &rec, rep, fmt.Errorf("service apply failed: %w", err))
		}
		restoreFault(root, "after-service")
	}
	rec.State = RestoreStateCommitted
	if err := saveRestoreRecord(root, &rec); err != nil {
		return rep, err
	}
	_ = os.RemoveAll(snapDir)
	return rep, nil
}

func applyRestoreFile(root, stage string, f *restoreFile) error {
	if _, err := secureMkdirAll(root, filepath.Dir(f.Path), 0o750); err != nil {
		return err
	}
	dst, err := securePath(root, f.Path, true)
	if err != nil {
		return err
	}
	src := filepath.Join(stage, filepath.FromSlash(f.Path))
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	if err := os.Chmod(dst, os.FileMode(f.Mode)); err != nil {
		return err
	}
	// Ownership comes from the target host, never from source metadata. The
	// service account group keeps the file readable after a cold restore.
	if os.Geteuid() == 0 {
		if gid, ok := serviceGroupID(); ok {
			if err := os.Chown(dst, -1, gid); err != nil {
				return err
			}
		}
	}
	syncDir(filepath.Dir(dst))
	return nil
}

func restoreFailed(root string, rec *restoreRecord, rep Report, cause error) (Report, error) {
	if err := rollbackRestore(root, rec); err != nil {
		rec.State = RestoreStateRecoveryNeeded
		rec.Reason = cause.Error() + "; rollback failed: " + err.Error()
		_ = saveRestoreRecord(root, rec)
		return rep, fmt.Errorf("%w (rollback failed: %v; run `idleleo backup recover`)", cause, err)
	}
	rec.State = RestoreStateRolledBack
	rec.Reason = cause.Error()
	_ = saveRestoreRecord(root, rec)
	_ = os.RemoveAll(restoreSnapshotDir(root, rec.ID))
	return rep, cause
}

func rollbackRestore(root string, rec *restoreRecord) error {
	snapDir := restoreSnapshotDir(root, rec.ID)
	for i := len(rec.Files) - 1; i >= 0; i-- {
		f := rec.Files[i]
		if f.HadOld {
			body, err := os.ReadFile(filepath.Join(snapDir, f.Snapshot))
			if err != nil {
				return fmt.Errorf("snapshot for %s is missing: %w", f.Path, err)
			}
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != f.OldSHA256 {
				return fmt.Errorf("snapshot for %s does not match the recorded digest", f.Path)
			}
			if _, err := secureMkdirAll(root, filepath.Dir(f.Path), 0o750); err != nil {
				return err
			}
			dst, err := securePath(root, f.Path, true)
			if err != nil {
				return err
			}
			if err := writeAtomicFile(dst, body, os.FileMode(f.OldMode), f.OldUID, f.OldGID); err != nil {
				return err
			}
			continue
		}
		dst, err := securePath(root, f.Path, true)
		if err != nil {
			return err
		}
		if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Recover converges an interrupted restore under the shared update lock. With
// no journal it reports action=none; it never deletes a snapshot it cannot
// verify.
func Recover(ctx context.Context, root string, opts RecoverOptions) (RecoverReport, error) {
	rep := RecoverReport{SchemaVersion: SchemaVersion, Action: "none", Converged: true, Warnings: []string{}}
	abs, err := ensureRoot(root)
	if err != nil {
		return rep, err
	}
	rec, err := loadRestoreRecord(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rep, nil
		}
		return rep, err
	}
	rep.State = rec.State
	if opts.DryRun {
		rep.Converged = rec.State == RestoreStateCommitted || rec.State == RestoreStateRolledBack
		return rep, nil
	}
	lock, err := host.AcquireUpdate(lockFileFor(abs))
	if err != nil {
		rep.Converged = false
		if errors.Is(err, host.ErrLocked) {
			rep.Warnings = append(rep.Warnings, "update lock is held by another process")
			return rep, fmt.Errorf("another update holds the lock")
		}
		return rep, err
	}
	defer lock.Release()

	switch rec.State {
	case RestoreStateCommitted, RestoreStateRolledBack:
		_ = os.RemoveAll(restoreSnapshotDir(abs, rec.ID))
		return rep, nil
	case RestoreStatePrepared:
		// No file was replaced before APPLYING was recorded.
		rec.State = RestoreStateRolledBack
		rec.Reason = "recovered before any file was replaced"
		if err := saveRestoreRecord(abs, &rec); err != nil {
			return rep, err
		}
		_ = os.RemoveAll(restoreSnapshotDir(abs, rec.ID))
		rep.Action = "rolled-back"
		return rep, nil
	case RestoreStateApplying, RestoreStateRecoveryNeeded:
		if err := rollbackRestore(abs, &rec); err != nil {
			rec.State = RestoreStateRecoveryNeeded
			rec.Reason = "recovery rollback failed: " + err.Error()
			_ = saveRestoreRecord(abs, &rec)
			rep.Converged = false
			rep.Action = "recovery-required"
			rep.Warnings = append(rep.Warnings, rec.Reason)
			return rep, err
		}
		rec.State = RestoreStateRolledBack
		rec.Reason = "recovered from an interrupted restore"
		if err := saveRestoreRecord(abs, &rec); err != nil {
			return rep, err
		}
		_ = os.RemoveAll(restoreSnapshotDir(abs, rec.ID))
		rep.Action = "rolled-back"
		if opts.Apply != nil {
			if err := opts.Apply(ctx); err != nil {
				rep.Warnings = append(rep.Warnings, "service apply failed: "+err.Error())
			}
		}
		return rep, nil
	default:
		rep.Converged = false
		rep.Warnings = append(rep.Warnings, "unknown restore journal state: "+rec.State)
		return rep, fmt.Errorf("unknown restore journal state %q", rec.State)
	}
}

// serviceGroupID resolves the target host's service group. A missing group is
// not an error: sandbox roots and fresh hosts simply keep the process group.
func serviceGroupID() (int, bool) {
	g, err := user.LookupGroup("xray")
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}
