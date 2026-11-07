package change

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// Fault names are test-only failure injectors. They require a marked sandbox.
const (
	FaultWriteFailure   = "write-fail"
	FaultServiceFailure = "service-fail"
	FaultDrift          = "drift-before-commit"
)

var allowedFaults = map[string]bool{
	"": true, FaultWriteFailure: true, FaultServiceFailure: true, FaultDrift: true,
}

// Request describes one controlled file change.
type Request struct {
	Target    string
	Mutate    func([]byte) ([]byte, error)
	Validator runtime.XrayValidator
	Service   runtime.CommandService
	Journal   Journal
	LockPath  string
	Fault     string
	ID        string
}

// UsageError is a malformed request (exit 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// ConflictError means the target changed under us (exit 7).
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

// IOError is a staged/write failure before commit (exit 13).
type IOError struct{ Msg string }

func (e *IOError) Error() string { return e.Msg }

// RecoveryError means the rollback itself failed (exit 10).
type RecoveryError struct{ Msg string }

func (e *RecoveryError) Error() string { return e.Msg }

// Apply runs PREPARE -> VALIDATE -> COMMIT -> SERVICE with rollback.
func Apply(ctx context.Context, req Request) (Entry, error) {
	if !allowedFaults[req.Fault] {
		return Entry{}, &UsageError{Msg: "unknown fault injector"}
	}
	if req.Target == "" || req.Mutate == nil || req.Validator.Path == "" {
		return Entry{}, &UsageError{Msg: "target, mutator and validator are required"}
	}
	entry := Entry{ID: req.ID, State: StatePrepared, Target: req.Target, StartedAt: now()}
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	lock, err := host.AcquireUpdate(req.LockPath)
	if err != nil {
		if errors.Is(err, host.ErrLocked) {
			// No transaction started, so nothing may be written: the journal
			// belongs to the process that actually holds the lock.
			entry.State = StateFailed
			entry.Reason = "update lock is held by another process"
			entry.UpdatedAt = now()
			return entry, &ConflictError{Msg: entry.Reason}
		}
		return entry, &IOError{Msg: "acquire lock: " + err.Error()}
	}
	defer lock.Release()

	before, err := store.ReadRuntimeSnapshot(req.Target)
	if err != nil {
		entry.State = StateFailed
		entry.Reason = err.Error()
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &IOError{Msg: err.Error()}
	}
	entry.OldSHA256 = before.SHA
	entry.UpdatedAt = now()
	if err := req.Journal.Record(entry); err != nil {
		return entry, &IOError{Msg: "journal: " + err.Error()}
	}

	candidate, err := req.Mutate(before.Raw)
	if err != nil {
		return reject(req, entry, 0, err.Error())
	}
	entry.NewSHA256 = store.HashBytes(candidate)
	tempPath, err := stageCandidate(req.Target, candidate, before)
	if err != nil {
		entry.State = StateFailed
		entry.Reason = err.Error()
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &IOError{Msg: err.Error()}
	}
	defer os.Remove(tempPath)

	if req.Fault == FaultWriteFailure {
		entry.State = StateFailed
		entry.Reason = "injected write failure"
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &IOError{Msg: entry.Reason}
	}

	if err := req.Validator.Validate(ctx, tempPath); err != nil {
		var ve *runtime.ValidationError
		code := -1
		if errors.As(err, &ve) {
			code = ve.ExitCode
		}
		return reject(req, entry, code, err.Error())
	}

	if req.Fault == FaultDrift {
		f, err := os.OpenFile(req.Target, os.O_APPEND|os.O_WRONLY, 0)
		if err == nil {
			_, _ = f.WriteString("\n")
			_ = f.Close()
		}
	}
	after, err := store.ReadRuntimeSnapshot(req.Target)
	if err != nil {
		entry.State = StateConflict
		entry.Reason = "target disappeared before commit"
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &ConflictError{Msg: entry.Reason}
	}
	if after.SHA != before.SHA {
		entry.State = StateConflict
		entry.Reason = "target changed externally before commit"
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &ConflictError{Msg: entry.Reason}
	}

	rollbackPath := filepath.Join(filepath.Dir(req.Target), ".idleleo-phase01-rollback")
	if err := writeAtomic(rollbackPath, before.Raw, 0600, before.UID, before.GID); err != nil {
		entry.State = StateFailed
		entry.Reason = "rollback snapshot failed: " + err.Error()
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &IOError{Msg: entry.Reason}
	}
	if err := os.Rename(tempPath, req.Target); err != nil {
		_ = os.Remove(rollbackPath)
		entry.State = StateFailed
		entry.Reason = "commit rename failed: " + err.Error()
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &IOError{Msg: entry.Reason}
	}
	syncDir(filepath.Dir(req.Target))

	if req.Fault == FaultServiceFailure {
		return rollback(req, entry, before, rollbackPath, 1, "injected service failure")
	}
	if err := req.Service.Apply(ctx); err != nil {
		var se *runtime.ServiceError
		code := -1
		if errors.As(err, &se) {
			code = se.ExitCode
		}
		return rollback(req, entry, before, rollbackPath, code, err.Error())
	}

	_ = os.Remove(rollbackPath)
	entry.State = StateCommitted
	entry.UpdatedAt = now()
	if err := req.Journal.Record(entry); err != nil {
		return entry, &IOError{Msg: "journal: " + err.Error()}
	}
	return entry, nil
}

func reject(req Request, entry Entry, code int, reason string) (Entry, error) {
	entry.State = StateRejected
	entry.ValidatorExit = code
	entry.Reason = reason
	entry.UpdatedAt = now()
	_ = req.Journal.Record(entry)
	return entry, &runtime.ValidationError{ExitCode: code, Output: reason}
}

func rollback(req Request, entry Entry, before store.RuntimeSnapshot, rollbackPath string, code int, reason string) (Entry, error) {
	entry.ServiceExit = code
	entry.Reason = reason
	if err := writeAtomic(req.Target, before.Raw, before.Mode, before.UID, before.GID); err != nil {
		entry.State = StateRecoveryRequired
		entry.Reason += "; rollback failed: " + err.Error()
		entry.UpdatedAt = now()
		_ = req.Journal.Record(entry)
		return entry, &RecoveryError{Msg: entry.Reason}
	}
	syncDir(filepath.Dir(req.Target))
	_ = os.Remove(rollbackPath)
	entry.State = StateRolledBack
	entry.UpdatedAt = now()
	_ = req.Journal.Record(entry)
	return entry, &runtime.ServiceError{ExitCode: code, Output: reason}
}

func stageCandidate(target string, data []byte, before store.RuntimeSnapshot) (string, error) {
	dir := filepath.Dir(target)
	// Keep the target extension: real validators such as `xray -test` infer the
	// config format from the suffix.
	f, err := os.CreateTemp(dir, ".idleleo-phase01-candidate-*"+filepath.Ext(target))
	if err != nil {
		return "", fmt.Errorf("stage candidate: %w", err)
	}
	path := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(before.Mode); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Chown(before.UID, before.GID); err != nil && !errors.Is(err, os.ErrPermission) {
		f.Close()
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return path, nil
}

// writeAtomic writes data to a sibling temp file and renames it into place.
func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".idleleo-phase01-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if uid != os.Getuid() || gid != os.Getgid() {
		if err := f.Chown(uid, gid); err != nil {
			f.Close()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// SetInboundPort changes exactly one port and refuses any other semantic diff.
func SetInboundPort(raw []byte, index int, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, &UsageError{Msg: "port must be between 1 and 65535"}
	}
	root, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	originalRoot, err := decodeObject(raw)
	if err != nil {
		return nil, err
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok || index < 0 || index >= len(inbounds) {
		return nil, &UsageError{Msg: "inbound index out of range"}
	}
	in, ok := inbounds[index].(map[string]any)
	if !ok {
		return nil, &UsageError{Msg: "inbound is not an object"}
	}
	in["port"] = port
	out, err := encodeObject(root)
	if err != nil {
		return nil, err
	}
	recheck, err := decodeObject(out)
	if err != nil {
		return nil, err
	}
	if err := assertOnlyPortChanged(originalRoot, recheck, index); err != nil {
		return nil, err
	}
	return out, nil
}

func assertOnlyPortChanged(original, candidate map[string]any, index int) error {
	inbounds, _ := candidate["inbounds"].([]any)
	in, _ := inbounds[index].(map[string]any)
	origInbounds, _ := original["inbounds"].([]any)
	origIn, _ := origInbounds[index].(map[string]any)
	in["port"] = origIn["port"]
	if !reflect.DeepEqual(original, candidate) {
		return &UsageError{Msg: "refusing mutation: fields other than inbound port would change"}
	}
	return nil
}

func decodeObject(raw []byte) (map[string]any, error) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, &UsageError{Msg: "runtime config is not valid JSON: " + err.Error()}
	}
	if root == nil {
		return nil, &UsageError{Msg: "runtime config must be an object"}
	}
	return root, nil
}

func encodeObject(root map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		return nil, &UsageError{Msg: "encode candidate: " + err.Error()}
	}
	return buf.Bytes(), nil
}

func trimReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}
