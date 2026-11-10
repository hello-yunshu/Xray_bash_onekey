package tcpcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

type fakeFile struct {
	data []byte
	mode os.FileMode
	uid  int
	gid  int
}

type fakeBackend struct {
	goos       string
	kernel     string
	sysctl     map[string]string
	available  []string
	files      map[string]*fakeFile
	symlinks   map[string]bool
	root       bool
	lockCalls  int
	sysctlWrt  map[string]int
	failSysctl map[string]int
	failWrite  map[string]error
	chownErr   error
	removeErr  error
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		goos:       "linux",
		kernel:     "6.8.0-test",
		root:       true,
		sysctl:     map[string]string{"net.core.default_qdisc": "fq_codel", "net.ipv4.tcp_congestion_control": "cubic"},
		available:  []string{"cubic", "bbr"},
		files:      map[string]*fakeFile{},
		symlinks:   map[string]bool{},
		sysctlWrt:  map[string]int{},
		failSysctl: map[string]int{},
		failWrite:  map[string]error{},
	}
}

func (f *fakeBackend) GOOS() string                   { return f.goos }
func (f *fakeBackend) KernelRelease() (string, error) { return f.kernel, nil }

func (f *fakeBackend) ReadSysctl(key string) (string, error) {
	value, ok := f.sysctl[key]
	if !ok {
		return "", fmt.Errorf("no such sysctl key %s", key)
	}
	return value, nil
}

func (f *fakeBackend) ListCongestion() ([]string, error) { return f.available, nil }

func (f *fakeBackend) WriteSysctl(key, value string) error {
	f.sysctlWrt[key]++
	if at := f.failSysctl[key]; at > 0 && f.sysctlWrt[key] == at {
		return fmt.Errorf("injected sysctl failure for %s call %d", key, at)
	}
	f.sysctl[key] = value
	return nil
}

func (f *fakeBackend) ReadFile(path string) ([]byte, error) {
	file, ok := f.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), file.data...), nil
}

func (f *fakeBackend) StatFile(path string) (FileState, error) {
	if f.symlinks[path] {
		return FileState{}, fmt.Errorf("symlink refused: %s", path)
	}
	file, ok := f.files[path]
	if !ok {
		return FileState{}, nil
	}
	return FileState{Exists: true, Mode: file.mode, UID: file.uid, GID: file.gid}, nil
}

func (f *fakeBackend) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := f.failWrite[path]; err != nil {
		return err
	}
	f.files[path] = &fakeFile{data: append([]byte(nil), data...), mode: mode}
	return nil
}

func (f *fakeBackend) Chown(path string, uid, gid int) error {
	if f.chownErr != nil {
		return f.chownErr
	}
	file, ok := f.files[path]
	if !ok {
		return os.ErrNotExist
	}
	file.uid, file.gid = uid, gid
	return nil
}

func (f *fakeBackend) RemoveFile(path string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	delete(f.files, path)
	return nil
}

func (f *fakeBackend) ListDir(dir string) ([]string, error) {
	names := []string{}
	for path := range f.files {
		if filepath.Dir(path) == dir {
			names = append(names, filepath.Base(path))
		}
	}
	sort.Strings(names)
	return names, nil
}

func (f *fakeBackend) Root() bool { return f.root }

func (f *fakeBackend) Lock(string) (func(), error) {
	f.lockCalls++
	return func() {}, nil
}

func newFakeManager(t *testing.T) (*Manager, *fakeBackend) {
	t.Helper()
	root := t.TempDir()
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatalf("NewPaths: %v", err)
	}
	// sysctl.d is resolved read-only, so the fake root still needs the real
	// directory to exist.
	if err := os.MkdirAll(filepath.Join(root, "etc/sysctl.d"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	backend := newFakeBackend()
	return &Manager{Paths: paths, Backend: backend}, backend
}

func (f *fakeBackend) put(t *testing.T, m *Manager, rel, body string, mode os.FileMode, uid, gid int) string {
	t.Helper()
	path, err := m.Paths.Join(rel, true)
	if err != nil {
		t.Fatalf("Join(%s): %v", rel, err)
	}
	f.files[path] = &fakeFile{data: []byte(body), mode: mode, uid: uid, gid: gid}
	return path
}

func mustKind(t *testing.T, err error, want store.Kind) {
	t.Helper()
	var se *store.Error
	if !errors.As(err, &se) {
		t.Fatalf("expected store error kind %d, got %v", want, err)
	}
	if se.Kind != want {
		t.Fatalf("expected store error kind %d, got %d (%v)", want, se.Kind, err)
	}
}

func managedPath(t *testing.T, m *Manager) string {
	t.Helper()
	path, err := m.managedPath()
	if err != nil {
		t.Fatalf("managedPath: %v", err)
	}
	return path
}

func statePath(t *testing.T, m *Manager) string {
	t.Helper()
	path, err := m.statePath()
	if err != nil {
		t.Fatalf("statePath: %v", err)
	}
	return path
}

func TestStatusNonLinux(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.goos = "darwin"
	status, err := m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Supported {
		t.Fatal("non-linux status must report unsupported")
	}
	if len(status.Warnings) == 0 {
		t.Fatal("non-linux status must explain the limitation")
	}
}

func TestStatusReportsSourcesAndConflicts(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.put(t, m, "etc/sysctl.d/50-dist.conf", "net.ipv4.tcp_congestion_control = cubic\n", 0o644, 0, 0)
	backend.put(t, m, "etc/sysctl.d/99-override.conf", "net.ipv4.tcp_congestion_control = reno\n", 0o644, 0, 0)
	status, err := m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Effective["net.ipv4.tcp_congestion_control"] != "reno" {
		t.Fatalf("effective value = %q, want reno", status.Effective["net.ipv4.tcp_congestion_control"])
	}
	if len(status.Conflicts) != 1 {
		t.Fatalf("conflicts = %v, want exactly the 99- file", status.Conflicts)
	}
	if status.ManagedFile.Exists {
		t.Fatal("managed file must not appear before apply")
	}
	if len(status.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(status.Sources))
	}
}

func TestPlanCreateWithoutWrites(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.put(t, m, "etc/sysctl.d/50-dist.conf", "net.core.default_qdisc = fq_codel\n", 0o644, 0, 0)
	plan, err := m.Plan(ProfileBBRFQ)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !plan.Supported || !plan.KernelSupportsBBR {
		t.Fatalf("plan must report linux+bbr support: %+v", plan)
	}
	if plan.FileAction != "create" {
		t.Fatalf("file action = %q, want create", plan.FileAction)
	}
	if plan.Noop {
		t.Fatal("plan must not be a no-op")
	}
	if len(plan.Conflicts) != 0 {
		t.Fatalf("lower-priority 50- file must not conflict: %v", plan.Conflicts)
	}
	if got := plan.Keys; len(got) != 2 || got[0].Old != "fq_codel" || got[1].Old != "cubic" {
		t.Fatalf("unexpected key plan: %+v", got)
	}
	if len(backend.files) != 1 || backend.lockCalls != 0 {
		t.Fatal("plan must not write or lock")
	}
}

func TestPlanUnknownProfile(t *testing.T) {
	m, _ := newFakeManager(t)
	if _, err := m.Plan("bbrplus"); err == nil {
		t.Fatal("unknown profile must be refused")
	}
}

func TestApplyThenIdempotent(t *testing.T) {
	m, backend := newFakeManager(t)
	result, err := m.Apply(ProfileBBRFQ)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !result.Changed || result.Noop {
		t.Fatalf("first apply must change: %+v", result)
	}
	file := backend.files[managedPath(t, m)]
	if file == nil {
		t.Fatal("managed file was not written")
	}
	if backend.sysctl["net.core.default_qdisc"] != "fq" || backend.sysctl["net.ipv4.tcp_congestion_control"] != "bbr" {
		t.Fatalf("runtime values not applied: %v", backend.sysctl)
	}
	var state State
	if err := json.Unmarshal(backend.files[statePath(t, m)].data, &state); err != nil {
		t.Fatalf("state json: %v", err)
	}
	if state.Pending || state.AppliedHash == "" || len(state.AppliedKeys) != 2 {
		t.Fatalf("unexpected state: %+v", state)
	}
	qdiscWrites := backend.sysctlWrt["net.core.default_qdisc"]
	ccWrites := backend.sysctlWrt["net.ipv4.tcp_congestion_control"]
	second, err := m.Apply(ProfileBBRFQ)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if !second.Noop || second.Changed {
		t.Fatalf("second apply must be a no-op: %+v", second)
	}
	if backend.sysctlWrt["net.core.default_qdisc"] != qdiscWrites || backend.sysctlWrt["net.ipv4.tcp_congestion_control"] != ccWrites {
		t.Fatal("idempotent apply must not rewrite sysctl values")
	}
}

func TestApplyRefusesForeignFile(t *testing.T) {
	m, backend := newFakeManager(t)
	path := backend.put(t, m, ManagedFileRel, "net.core.default_qdisc = fq\n", 0o644, 0, 0)
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindDrift)
	if string(backend.files[path].data) != "net.core.default_qdisc = fq\n" {
		t.Fatal("foreign file must stay byte-identical")
	}
	if len(backend.sysctlWrt) != 0 {
		t.Fatal("foreign file refusal must happen before any runtime write")
	}
}

func TestApplyRefusesUnsupportedKernel(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.available = []string{"cubic"}
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindUnsupported)
	if len(backend.files) != 0 {
		t.Fatal("unsupported kernel must not create a file")
	}
}

func TestApplyNonLinux(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.goos = "darwin"
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindUnsupported)
}

func TestApplyRequiresRootOnRealRoot(t *testing.T) {
	backend := newFakeBackend()
	backend.root = false
	m := &Manager{Paths: host.Paths{Root: "/"}, Backend: backend}
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindPermission)
}

func TestApplyReadOnlyFileLeavesKernelAlone(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.failWrite[managedPath(t, m)] = os.ErrPermission
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindPermission)
	if backend.sysctl["net.core.default_qdisc"] != "fq_codel" || backend.sysctl["net.ipv4.tcp_congestion_control"] != "cubic" {
		t.Fatal("read-only file failure must not touch runtime keys")
	}
	if _, ok := backend.files[statePath(t, m)]; ok {
		t.Fatal("failed apply must clean up its journal")
	}
}

func TestApplyPartialFailureRollsBack(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.failSysctl["net.ipv4.tcp_congestion_control"] = 1
	_, err := m.Apply(ProfileBBRFQ)
	if err == nil {
		t.Fatal("injected partial failure must be reported")
	}
	if backend.sysctl["net.core.default_qdisc"] != "fq_codel" {
		t.Fatalf("qdisc was not restored: %v", backend.sysctl)
	}
	if _, ok := backend.files[managedPath(t, m)]; ok {
		t.Fatal("managed file must be removed after a failed apply")
	}
	if _, ok := backend.files[statePath(t, m)]; ok {
		t.Fatal("journal must be removed after a successful rollback")
	}
}

func TestApplyRollbackFailureKeepsJournal(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.failSysctl["net.ipv4.tcp_congestion_control"] = 1
	backend.failSysctl["net.core.default_qdisc"] = 2
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindCorrupt)
	raw, ok := backend.files[statePath(t, m)]
	if !ok {
		t.Fatal("journal must be kept when runtime restore fails")
	}
	var state State
	if err := json.Unmarshal(raw.data, &state); err != nil {
		t.Fatalf("state json: %v", err)
	}
	if !state.Pending || len(state.AppliedKeys) != 1 {
		t.Fatalf("unexpected recovery state: %+v", state)
	}
}

func TestRollbackRestoresKernelAndFile(t *testing.T) {
	m, backend := newFakeManager(t)
	if _, err := m.Apply(ProfileBBRFQ); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	result, err := m.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !result.Changed {
		t.Fatalf("rollback must report a change: %+v", result)
	}
	if backend.sysctl["net.core.default_qdisc"] != "fq_codel" || backend.sysctl["net.ipv4.tcp_congestion_control"] != "cubic" {
		t.Fatalf("runtime not restored: %v", backend.sysctl)
	}
	if _, ok := backend.files[managedPath(t, m)]; ok {
		t.Fatal("file created by apply must be removed")
	}
	if _, ok := backend.files[statePath(t, m)]; ok {
		t.Fatal("journal must be removed after rollback")
	}
}

func TestRollbackRestoresExistingFileBytesAndOwner(t *testing.T) {
	m, backend := newFakeManager(t)
	original := "# Managed by Xray_bash_onekey (Go): idleleo tcp\nnet.core.default_qdisc = fq_codel\n"
	path := backend.put(t, m, ManagedFileRel, original, 0o640, 1000, 1000)
	if _, err := m.Apply(ProfileBBRFQ); err != nil {
		t.Fatalf("Apply over an owned file: %v", err)
	}
	applied := backend.files[path]
	if applied.mode != 0o640 || applied.uid != 1000 || applied.gid != 1000 {
		t.Fatalf("apply must preserve mode/owner: %+v", applied)
	}
	if _, err := m.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	restored := backend.files[path]
	if restored == nil || string(restored.data) != original {
		t.Fatalf("previous file bytes were not restored: %+v", restored)
	}
	if restored.mode != 0o640 || restored.uid != 1000 || restored.gid != 1000 {
		t.Fatalf("previous mode/owner were not restored: %+v", restored)
	}
}

func TestRollbackRefusesFileDrift(t *testing.T) {
	m, backend := newFakeManager(t)
	if _, err := m.Apply(ProfileBBRFQ); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	path := managedPath(t, m)
	file := backend.files[path]
	file.data = append(file.data, []byte("# edited by someone else\n")...)
	_, err := m.Rollback()
	mustKind(t, err, store.KindDrift)
	if backend.sysctl["net.ipv4.tcp_congestion_control"] != "bbr" {
		t.Fatal("drifted rollback must leave runtime untouched")
	}
}

func TestRollbackRefusesRuntimeDrift(t *testing.T) {
	m, backend := newFakeManager(t)
	if _, err := m.Apply(ProfileBBRFQ); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	backend.sysctl["net.ipv4.tcp_congestion_control"] = "reno"
	_, err := m.Rollback()
	mustKind(t, err, store.KindDrift)
	if _, ok := backend.files[managedPath(t, m)]; !ok {
		t.Fatal("drifted rollback must keep the managed file")
	}
}

func TestRollbackWithoutJournalIsNoop(t *testing.T) {
	m, backend := newFakeManager(t)
	result, err := m.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if result.Changed || !result.Noop {
		t.Fatalf("missing journal must be a no-op: %+v", result)
	}
	if len(backend.sysctlWrt) != 0 {
		t.Fatal("no-op rollback must not write sysctl")
	}
}

func TestApplyRefusesPendingJournal(t *testing.T) {
	m, backend := newFakeManager(t)
	pending := State{Version: stateVersion, Profile: ProfileBBRFQ, Pending: true}
	raw, _ := json.Marshal(pending)
	backend.put(t, m, StateFileRel, string(raw), 0o600, 0, 0)
	_, err := m.Apply(ProfileBBRFQ)
	mustKind(t, err, store.KindDrift)
}

func TestStatusCorruptJournal(t *testing.T) {
	m, backend := newFakeManager(t)
	backend.put(t, m, StateFileRel, "{not json", 0o600, 0, 0)
	_, err := m.Status()
	mustKind(t, err, store.KindCorrupt)
}

func TestApplyRefusesSymlinkedManagedFile(t *testing.T) {
	m, backend := newFakeManager(t)
	path := managedPath(t, m)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Symlink(filepath.Join(m.Paths.Root, "outside"), path); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	_, err := m.Apply(ProfileBBRFQ)
	if err == nil {
		t.Fatal("symlinked managed file must be refused")
	}
	if len(backend.sysctlWrt) != 0 || len(backend.files) != 0 {
		t.Fatal("symlink refusal must not write anything")
	}
}
