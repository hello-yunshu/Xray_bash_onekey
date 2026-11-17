package change

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// crashState reproduces the on-disk state after a hard kill at the given
// window: PREPARED journal entry plus whatever reached the filesystem.
func crashState(t *testing.T, root, cfgPath string) (Journal, string, string, []byte, []byte) {
	t.Helper()
	oldRaw := []byte(cfg)
	newRaw, err := SetInboundPort(oldRaw, 0, 8443)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(cfgPath)
	journalPath := filepath.Join(root, "var/lib/idleleo/transactions/phase01.json")
	return Journal{Path: journalPath}, dir, journalPath, oldRaw, newRaw
}

func writePrepared(t *testing.T, j Journal, target, service string, oldRaw, newRaw []byte) {
	t.Helper()
	j.Record(Entry{
		ID: "tx-crash", State: StatePrepared, Target: target, ServicePath: service,
		OldSHA256: store.HashBytes(oldRaw), NewSHA256: store.HashBytes(newRaw),
		StartedAt: now(),
	})
}

func TestRecoverNoPendingTransactionConverges(t *testing.T) {
	root, cfgPath := sandbox(t)
	j, _, _, _, _ := crashState(t, root, cfgPath)
	rep, err := Recover(context.Background(), j, filepath.Join(root, "run/lock/idleleo-update.lock"))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !rep.Converged || rep.Action != "none" {
		t.Fatalf("report=%+v", rep)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverRollsBackCrashAfterRename(t *testing.T) {
	root, cfgPath := sandbox(t)
	j, dir, journalPath, oldRaw, newRaw := crashState(t, root, cfgPath)
	service := script(t, root, "service", `echo "$@" >> "$0.log"`)
	if err := os.WriteFile(cfgPath, newRaw, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".idleleo-phase01-rollback"), oldRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".idleleo-phase01-candidate-dead"), []byte("torn"), 0600); err != nil {
		t.Fatal(err)
	}
	writePrepared(t, j, cfgPath, service, oldRaw, newRaw)

	rep, err := Recover(context.Background(), j, filepath.Join(root, "run/lock/idleleo-update.lock"))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !rep.Converged || rep.Action != "rolled-back" {
		t.Fatalf("report=%+v", rep)
	}
	got, _ := os.ReadFile(cfgPath)
	if string(got) != string(oldRaw) {
		t.Fatalf("target not restored:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".idleleo-phase01-rollback")); !os.IsNotExist(err) {
		t.Fatal("rollback file left behind")
	}
	if _, err := os.Stat(filepath.Join(dir, ".idleleo-phase01-candidate-dead")); !os.IsNotExist(err) {
		t.Fatal("candidate temp file left behind")
	}
	if journalState(t, journalPath) != StateRolledBack {
		t.Fatal("journal state")
	}
	log, _ := os.ReadFile(service + ".log")
	if strings.TrimSpace(string(log)) != "apply" {
		t.Fatalf("service must reload the restored config, got %q", string(log))
	}
}

func TestRecoverRollsBackCrashBeforeRenameWithoutRestart(t *testing.T) {
	root, cfgPath := sandbox(t)
	j, dir, journalPath, oldRaw, newRaw := crashState(t, root, cfgPath)
	service := script(t, root, "service", `echo "$@" >> "$0.log"`)
	if err := os.WriteFile(filepath.Join(dir, ".idleleo-phase01-rollback"), oldRaw, 0600); err != nil {
		t.Fatal(err)
	}
	writePrepared(t, j, cfgPath, service, oldRaw, newRaw)

	rep, err := Recover(context.Background(), j, filepath.Join(root, "run/lock/idleleo-update.lock"))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rep.Action != "rolled-back" || !rep.Converged {
		t.Fatalf("report=%+v", rep)
	}
	got, _ := os.ReadFile(cfgPath)
	if string(got) != string(oldRaw) {
		t.Fatal("target changed")
	}
	if _, err := os.Stat(service + ".log"); !os.IsNotExist(err) {
		t.Fatal("service must not restart when nothing changed")
	}
	if journalState(t, journalPath) != StateRolledBack {
		t.Fatal("journal state")
	}
}

func TestRecoverFinalizesCommittedButUnrecorded(t *testing.T) {
	root, cfgPath := sandbox(t)
	j, _, journalPath, oldRaw, newRaw := crashState(t, root, cfgPath)
	service := script(t, root, "service", `echo "$@" >> "$0.log"`)
	if err := os.WriteFile(cfgPath, newRaw, 0640); err != nil {
		t.Fatal(err)
	}
	writePrepared(t, j, cfgPath, service, oldRaw, newRaw)

	rep, err := Recover(context.Background(), j, filepath.Join(root, "run/lock/idleleo-update.lock"))
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rep.Action != "finalized" || !rep.Converged {
		t.Fatalf("report=%+v", rep)
	}
	got, _ := os.ReadFile(cfgPath)
	if string(got) != string(newRaw) {
		t.Fatal("committed target was rolled back")
	}
	if _, err := os.Stat(service + ".log"); !os.IsNotExist(err) {
		t.Fatal("finalize must not restart the service")
	}
	if journalState(t, journalPath) != StateCommitted {
		t.Fatal("journal state")
	}
}

func TestRecoverRefusesTargetChangedOutsideTransaction(t *testing.T) {
	root, cfgPath := sandbox(t)
	j, _, journalPath, oldRaw, newRaw := crashState(t, root, cfgPath)
	writePrepared(t, j, cfgPath, "", oldRaw, newRaw)
	if err := os.WriteFile(cfgPath, []byte(`{"inbounds":[]}`), 0640); err != nil {
		t.Fatal(err)
	}

	rep, err := Recover(context.Background(), j, filepath.Join(root, "run/lock/idleleo-update.lock"))
	var re *RecoveryError
	if !errors.As(err, &re) {
		t.Fatalf("want recovery error, got %v", err)
	}
	if rep.Converged || rep.Action != "recovery-required" {
		t.Fatalf("report=%+v", rep)
	}
	if journalState(t, journalPath) != StateRecoveryRequired {
		t.Fatal("journal state")
	}
}

// A new change must converge the interrupted one first, otherwise it would
// treat the half-applied file as the known-good baseline.
func TestApplyRecoversPendingTransactionFirst(t *testing.T) {
	root, cfgPath := sandbox(t)
	service := script(t, root, "service", `echo "$@" >> "$0.log"`)
	j, dir, _, oldRaw, newRaw := crashState(t, root, cfgPath)
	if err := os.WriteFile(cfgPath, newRaw, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".idleleo-phase01-rollback"), oldRaw, 0600); err != nil {
		t.Fatal(err)
	}
	writePrepared(t, j, cfgPath, service, oldRaw, newRaw)

	req := baseReq(root, cfgPath, script(t, root, "validator", "exit 0"), service)
	req.Journal = j
	entry, err := Apply(context.Background(), req)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if entry.State != StateCommitted {
		t.Fatalf("state=%s", entry.State)
	}
	if entry.OldSHA256 != store.HashBytes(oldRaw) {
		t.Fatal("baseline was not the recovered file")
	}
	log, _ := os.ReadFile(service + ".log")
	if lines := strings.Count(strings.TrimSpace(string(log)), "apply"); lines != 2 {
		t.Fatalf("want rollback+commit restarts, got %q", string(log))
	}
}

func TestRecoverLockConflict(t *testing.T) {
	root, cfgPath := sandbox(t)
	j, _, _, _, _ := crashState(t, root, cfgPath)
	lockPath := filepath.Join(root, "run/lock/idleleo-update.lock")
	lock, err := host.AcquireUpdate(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	rep, err := Recover(context.Background(), j, lockPath)
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("want conflict, got %v", err)
	}
	if rep.Converged {
		t.Fatalf("report=%+v", rep)
	}
}
