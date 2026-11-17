package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// RecoverReport describes how an interrupted change transaction was converged.
type RecoverReport struct {
	SchemaVersion int      `json:"schemaVersion"`
	JournalState  string   `json:"journalState,omitempty"`
	ID            string   `json:"id,omitempty"`
	Target        string   `json:"target,omitempty"`
	Action        string   `json:"action"`
	Converged     bool     `json:"converged"`
	Warnings      []string `json:"warnings"`
}

// Recover converges a transaction that was interrupted after its PREPARED
// record. It is safe with no pending transaction: the report then says
// action=none and converged=true.
func Recover(ctx context.Context, j Journal, lockPath string) (RecoverReport, error) {
	lock, err := host.AcquireUpdate(lockPath)
	if err != nil {
		if errors.Is(err, host.ErrLocked) {
			return RecoverReport{SchemaVersion: 1, Action: "none", Converged: false,
					Warnings: []string{"update lock is held by another process"}},
				&ConflictError{Msg: "update lock is held by another process"}
		}
		return RecoverReport{SchemaVersion: 1, Action: "none", Converged: false},
			&IOError{Msg: "acquire lock: " + err.Error()}
	}
	defer lock.Release()
	return recoverLocked(ctx, j)
}

// recoverLocked must be called with the update lock held.
func recoverLocked(ctx context.Context, j Journal) (RecoverReport, error) {
	rep := RecoverReport{SchemaVersion: 1, Action: "none", Converged: true, Warnings: []string{}}
	entries, err := readEntries(j.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil
		}
		return rep, &IOError{Msg: "journal: " + err.Error()}
	}
	if len(entries) == 0 {
		return rep, nil
	}
	last := entries[len(entries)-1]
	rep.JournalState = last.State
	rep.ID = last.ID
	rep.Target = last.Target
	if last.State != StatePrepared {
		return rep, nil
	}
	if last.Target == "" {
		return recoveryRequired(rep, j, last, "journal has no target")
	}
	snap, err := store.ReadRuntimeSnapshot(last.Target)
	if err != nil {
		return recoveryRequired(rep, j, last, "target is unreadable: "+err.Error())
	}
	dir := filepath.Dir(last.Target)
	rollbackPath := filepath.Join(dir, ".idleleo-phase01-rollback")
	rollback, rollbackErr := os.ReadFile(rollbackPath)
	// Candidate temp files only survive a hard kill; they are never valid state.
	cleanCandidates(dir)

	switch {
	case rollbackErr == nil:
		// A kill before the commit rename leaves the old file in place; the
		// snapshot is identical to it, so only cleanup is needed and the
		// running service must not be restarted.
		if snap.SHA == last.OldSHA256 {
			_ = os.Remove(rollbackPath)
			rep.Action = "rolled-back"
			recordRecovered(j, last, StateRolledBack, "recovered: no commit happened")
			return rep, nil
		}
		if err := writeAtomic(last.Target, rollback, snap.Mode, snap.UID, snap.GID); err != nil {
			return recoveryRequired(rep, j, last, "rollback write failed: "+err.Error())
		}
		if last.ServicePath != "" {
			if err := (runtime.CommandService{Path: last.ServicePath}).Apply(ctx); err != nil {
				return recoveryRequired(rep, j, last, "rollback applied but service restart failed: "+err.Error())
			}
		} else {
			rep.Warnings = append(rep.Warnings,
				"no service command was recorded; verify the service reloads the restored config")
		}
		_ = os.Remove(rollbackPath)
		rep.Action = "rolled-back"
		recordRecovered(j, last, StateRolledBack, "recovered after interrupted transaction")
		return rep, nil
	case !os.IsNotExist(rollbackErr):
		return recoveryRequired(rep, j, last, "rollback snapshot unreadable: "+rollbackErr.Error())
	case last.NewSHA256 != "" && snap.SHA == last.NewSHA256:
		// The commit rename and the service restart both finished; only the
		// final journal record was lost.
		rep.Action = "finalized"
		recordRecovered(j, last, StateCommitted, "recovered: commit had completed before the journal update")
		return rep, nil
	case snap.SHA == last.OldSHA256:
		rep.Action = "rolled-back"
		recordRecovered(j, last, StateRolledBack, "recovered: no commit happened")
		return rep, nil
	default:
		return recoveryRequired(rep, j, last, "target changed outside the transaction")
	}
}

func recoveryRequired(rep RecoverReport, j Journal, last Entry, reason string) (RecoverReport, error) {
	rep.Action = "recovery-required"
	rep.Converged = false
	rep.Warnings = append(rep.Warnings, reason)
	last.State = StateRecoveryRequired
	last.Reason = reason
	last.UpdatedAt = now()
	_ = j.Record(last)
	return rep, &RecoveryError{Msg: reason}
}

func recordRecovered(j Journal, last Entry, state, reason string) {
	last.State = state
	last.Reason = reason
	last.UpdatedAt = now()
	_ = j.Record(last)
}

func readEntries(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("journal is not valid JSON: %w", err)
	}
	return entries, nil
}

func cleanCandidates(dir string) {
	paths, err := filepath.Glob(filepath.Join(dir, ".idleleo-phase01-candidate-*"))
	if err != nil {
		return
	}
	for _, p := range paths {
		_ = os.Remove(p)
	}
}
