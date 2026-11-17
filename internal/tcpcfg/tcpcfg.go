// Package tcpcfg manages the project-owned TCP sysctl profile.
//
// Scope is deliberately small: it toggles kernel features the running kernel
// already exposes (BBR congestion control and the fq qdisc) through one file
// the project owns. It never downloads third-party scripts, never replaces the
// kernel, never rewrites /etc/sysctl.conf and never replays `sysctl --system`.
package tcpcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

const (
	// ProfileBBRFQ is the only profile this round implements: BBR + fq.
	ProfileBBRFQ = "bbr-fq"

	// ManagedFileRel is the one file the project owns. It sits in
	// /etc/sysctl.d with a higher prefix than distribution defaults but lower
	// than 99-* operator overrides, so explicit operator files still win.
	ManagedFileRel = "etc/sysctl.d/90-idleleo-tcp.conf"
	StateFileRel   = "var/lib/idleleo/tcp/state.json"
	LockFileRel    = "run/lock/idleleo-tcp.lock"

	sysctlConfRel = "etc/sysctl.conf"
	sysctlDRel    = "etc/sysctl.d"

	managedMarker = "Managed by Xray_bash_onekey"
	stateVersion  = 1

	// confPriority models procps `sysctl --system`, which reads /etc/sysctl.d
	// first and /etc/sysctl.conf last. A key set there always wins.
	confPriority = 1000
)

var profileValues = map[string]map[string]string{
	ProfileBBRFQ: {
		"net.core.default_qdisc":          "fq",
		"net.ipv4.tcp_congestion_control": "bbr",
	},
}

// orderedKeys keeps the write order deterministic: qdisc first, then the
// congestion-control algorithm that relies on it.
var orderedKeys = map[string][]string{
	ProfileBBRFQ: {"net.core.default_qdisc", "net.ipv4.tcp_congestion_control"},
}

// Profiles returns the supported profile names, sorted.
func Profiles() []string {
	out := make([]string, 0, len(profileValues))
	for name := range profileValues {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ProfileKeys validates a profile and returns its sysctl keys.
func ProfileKeys(profile string) ([]string, error) {
	keys, ok := orderedKeys[profile]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (supported: %s)", profile, strings.Join(Profiles(), ", "))
	}
	return keys, nil
}

// FileState is the snapshot metadata needed to restore a file byte-for-byte.
type FileState struct {
	Exists bool
	Mode   os.FileMode
	UID    int
	GID    int
}

// Backend abstracts the kernel and filesystem so tests never touch a host.
type Backend interface {
	GOOS() string
	KernelRelease() (string, error)
	ReadSysctl(key string) (string, error)
	ListCongestion() ([]string, error)
	WriteSysctl(key, value string) error
	ReadFile(path string) ([]byte, error)
	StatFile(path string) (FileState, error)
	WriteFile(path string, data []byte, mode os.FileMode) error
	Chown(path string, uid, gid int) error
	RemoveFile(path string) error
	ListDir(dir string) ([]string, error)
	Root() bool
	Lock(path string) (release func(), err error)
}

// Manager owns the TCP transaction for one root.
type Manager struct {
	Paths   host.Paths
	Backend Backend
}

// New wires the real host backend. root="/" is the real system; any other root
// is a disposable sandbox used by the Docker mock-apply tests.
func New(root string) (*Manager, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return nil, err
	}
	return &Manager{Paths: paths, Backend: OSBackend{Paths: paths}}, nil
}

// FileStatus describes the managed file without mutating anything.
type FileStatus struct {
	Path   string            `json:"path"`
	Exists bool              `json:"exists"`
	Owned  bool              `json:"owned"`
	Mode   uint32            `json:"mode"`
	UID    int               `json:"uid"`
	GID    int               `json:"gid"`
	SHA256 string            `json:"sha256,omitempty"`
	Values map[string]string `json:"values"`
}

// SysctlSource is one scanned sysctl configuration file.
type SysctlSource struct {
	Path     string            `json:"path"`
	Name     string            `json:"name"`
	Ours     bool              `json:"ours"`
	Values   map[string]string `json:"values"`
	Priority int               `json:"priority"`
}

// State is the rollback journal for exactly one apply transaction.
type State struct {
	Version      int               `json:"version"`
	Profile      string            `json:"profile"`
	FilePath     string            `json:"filePath"`
	StatePath    string            `json:"statePath"`
	FileExisted  bool              `json:"fileExisted"`
	FileContent  string            `json:"fileContent,omitempty"`
	FileMode     uint32            `json:"fileMode"`
	FileUID      int               `json:"fileUid"`
	FileGID      int               `json:"fileGid"`
	TargetHash   string            `json:"targetHash"`
	AppliedHash  string            `json:"appliedHash"`
	OldValues    map[string]string `json:"oldValues"`
	NewValues    map[string]string `json:"newValues"`
	AppliedKeys  []string          `json:"appliedKeys,omitempty"`
	Pending      bool              `json:"pending"`
	CreatedAtUTC string            `json:"createdAtUtc"`
}

// Status is the read-only host view.
type Status struct {
	Supported           bool              `json:"supported"`
	GOOS                string            `json:"goos"`
	KernelRelease       string            `json:"kernelRelease"`
	AvailableCongestion []string          `json:"availableCongestion"`
	Current             map[string]string `json:"current"`
	ManagedFile         FileStatus        `json:"managedFile"`
	StatePath           string            `json:"statePath"`
	State               *State            `json:"state,omitempty"`
	Sources             []SysctlSource    `json:"sources"`
	Effective           map[string]string `json:"effective"`
	Conflicts           []string          `json:"conflicts"`
	Warnings            []string          `json:"warnings"`
}

// KeyChange is one planned sysctl transition.
type KeyChange struct {
	Key string `json:"key"`
	Old string `json:"old"`
	New string `json:"new"`
}

// Plan is the exact preview produced by `tcp plan`; nothing is written.
type Plan struct {
	Profile           string      `json:"profile"`
	Supported         bool        `json:"supported"`
	KernelSupportsBBR bool        `json:"kernelSupportsBbr"`
	Keys              []KeyChange `json:"keys"`
	FilePath          string      `json:"filePath"`
	FileAction        string      `json:"fileAction"`
	FileExisted       bool        `json:"fileExisted"`
	FileOwned         bool        `json:"fileOwned"`
	FileMode          uint32      `json:"fileMode"`
	FileContent       string      `json:"fileContent"`
	StatePath         string      `json:"statePath"`
	Conflicts         []string    `json:"conflicts"`
	RestartRequired   bool        `json:"restartRequired"`
	Noop              bool        `json:"noop"`
	Impact            []string    `json:"impact"`
}

// Result is the outcome of an apply or rollback.
type Result struct {
	Changed   bool        `json:"changed"`
	Noop      bool        `json:"noop"`
	Profile   string      `json:"profile,omitempty"`
	FilePath  string      `json:"filePath,omitempty"`
	StatePath string      `json:"statePath,omitempty"`
	Applied   []KeyChange `json:"applied"`
	Message   string      `json:"message,omitempty"`
}

func (m *Manager) managedPath() (string, error) { return m.Paths.Join(ManagedFileRel, true) }
func (m *Manager) statePath() (string, error)   { return m.Paths.Join(StateFileRel, true) }
func (m *Manager) lockPath() (string, error)    { return m.Paths.Join(LockFileRel, true) }

// Status is read-only on every host, including non-Linux (where it reports
// Supported=false instead of pretending the keys exist).
func (m *Manager) Status() (Status, error) {
	st := Status{
		GOOS:      m.Backend.GOOS(),
		Current:   map[string]string{},
		Effective: map[string]string{},
		Sources:   []SysctlSource{},
		Conflicts: []string{},
		Warnings:  []string{},
	}
	st.Supported = st.GOOS == "linux"
	if !st.Supported {
		st.Warnings = append(st.Warnings, "TCP management is linux-only; status is informational")
		return st, nil
	}
	if rel, err := m.Backend.KernelRelease(); err == nil {
		st.KernelRelease = rel
	} else {
		st.Warnings = append(st.Warnings, "kernel release unavailable: "+err.Error())
	}
	if list, err := m.Backend.ListCongestion(); err == nil {
		st.AvailableCongestion = list
	} else {
		st.Warnings = append(st.Warnings, "available congestion algorithms unavailable: "+err.Error())
	}
	keys := allProfileKeys()
	for _, key := range keys {
		value, err := m.Backend.ReadSysctl(key)
		if err != nil {
			st.Warnings = append(st.Warnings, fmt.Sprintf("read %s: %v", key, err))
			continue
		}
		st.Current[key] = value
	}
	if !contains(st.AvailableCongestion, "bbr") {
		st.Warnings = append(st.Warnings, "kernel does not list bbr in tcp_available_congestion_control")
	}
	sources, ours, managedPriority, err := m.scanSources()
	if err != nil {
		return st, err
	}
	st.Sources = sources
	st.ManagedFile = ours
	sp, err := m.statePath()
	if err != nil {
		return st, err
	}
	st.StatePath = sp
	state, err := m.loadState(sp)
	if err != nil {
		return st, err
	}
	st.State = state
	st.Effective, st.Conflicts = assessSources(sources, keys, managedPriority)
	for key, effective := range st.Effective {
		if effective == "" {
			continue
		}
		if current, ok := st.Current[key]; ok && current != effective {
			st.Warnings = append(st.Warnings, fmt.Sprintf("runtime %s=%s differs from persisted %s (reboot or explicit live apply needed)", key, current, effective))
		}
	}
	if state != nil && state.Pending {
		st.Warnings = append(st.Warnings, "a previous TCP transaction is pending; run `idleleo tcp rollback`")
	}
	return st, nil
}

// Plan previews the profile transition. It never writes.
func (m *Manager) Plan(profile string) (Plan, error) {
	keys, err := ProfileKeys(profile)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		Profile:   profile,
		Supported: m.Backend.GOOS() == "linux",
		Keys:      []KeyChange{},
		Conflicts: []string{},
		Impact:    []string{},
	}
	mp, err := m.managedPath()
	if err != nil {
		return Plan{}, err
	}
	plan.FilePath = mp
	sp, err := m.statePath()
	if err != nil {
		return Plan{}, err
	}
	plan.StatePath = sp
	if !plan.Supported {
		plan.Impact = append(plan.Impact, "linux-only: no kernel keys are written on this host")
		return plan, nil
	}
	list, err := m.Backend.ListCongestion()
	if err == nil {
		plan.KernelSupportsBBR = contains(list, "bbr")
	}
	if !plan.KernelSupportsBBR {
		plan.Conflicts = append(plan.Conflicts, "running kernel does not list bbr; apply is refused (no kernel replacement is attempted)")
	}
	sources, ours, managedPriority, err := m.scanSources()
	if err != nil {
		return Plan{}, err
	}
	_, conflicts := assessSources(sources, keys, managedPriority)
	plan.Conflicts = append(plan.Conflicts, conflicts...)
	plan.FileExisted = ours.Exists
	plan.FileOwned = ours.Owned
	plan.FileMode = ours.Mode
	content := renderManagedFile(profile)
	plan.FileContent = content
	switch {
	case !ours.Exists:
		plan.FileAction = "create"
	case !ours.Owned:
		plan.FileAction = "refuse"
		plan.Conflicts = append(plan.Conflicts, fmt.Sprintf("%s exists without the idleleo marker; refusing to overwrite", mp))
	case sha256Hex([]byte(content)) == ours.SHA256:
		plan.FileAction = "noop"
	default:
		plan.FileAction = "update"
	}
	noop := true
	for _, key := range keys {
		old, err := m.Backend.ReadSysctl(key)
		if err != nil {
			return Plan{}, store.New(store.KindUnsupported, "read current "+key, err)
		}
		want := profileValues[profile][key]
		plan.Keys = append(plan.Keys, KeyChange{Key: key, Old: old, New: want})
		if old != want {
			noop = false
		}
	}
	if plan.FileAction != "noop" && plan.FileAction != "refuse" {
		noop = false
	}
	plan.Noop = noop
	plan.RestartRequired = false
	plan.Impact = append(plan.Impact,
		"writes only "+mp,
		"applies only "+strings.Join(keys, ", ")+" through /proc/sys; no sysctl --system replay",
		"runtime change is immediate; after reboot the persisted file re-applies the profile",
		"does not install a kernel, BBRPlus, SharpSpeed or a third-party script",
	)
	return plan, nil
}

// Apply performs the confirmed transition. It is idempotent: a second run with
// the same file and runtime values returns Changed=false without writing.
func (m *Manager) Apply(profile string) (Result, error) {
	keys, err := ProfileKeys(profile)
	if err != nil {
		return Result{}, err
	}
	if m.Backend.GOOS() != "linux" {
		return Result{}, store.New(store.KindUnsupported, "TCP management is linux-only", nil)
	}
	if !m.Paths.IsSandbox() && !m.Backend.Root() {
		return Result{}, store.New(store.KindPermission, "tcp apply requires root", nil)
	}
	lockPath, err := m.lockPath()
	if err != nil {
		return Result{}, err
	}
	release, err := m.Backend.Lock(lockPath)
	if err != nil {
		return Result{}, err
	}
	defer release()

	res := Result{Profile: profile, Applied: []KeyChange{}}
	mp, err := m.managedPath()
	if err != nil {
		return res, err
	}
	res.FilePath = mp
	sp, err := m.statePath()
	if err != nil {
		return res, err
	}
	res.StatePath = sp

	sources, ours, managedPriority, err := m.scanSources()
	if err != nil {
		return res, err
	}
	if _, conflicts := assessSources(sources, keys, managedPriority); len(conflicts) > 0 {
		return res, store.New(store.KindDrift, "conflicting sysctl configuration: "+strings.Join(conflicts, "; "), nil)
	}
	if ours.Exists && !ours.Owned {
		return res, store.New(store.KindDrift, "refusing to overwrite "+mp+" because it is not owned by idleleo", nil)
	}
	state, err := m.loadState(sp)
	if err != nil {
		return res, err
	}
	if state != nil && state.Pending {
		return res, store.New(store.KindDrift, "a previous TCP transaction is pending; run `idleleo tcp rollback` first", nil)
	}
	if state != nil && state.AppliedHash != "" && ours.SHA256 != state.AppliedHash {
		return res, store.New(store.KindDrift, "managed sysctl file changed outside idleleo; refusing to overwrite (manual review required)", nil)
	}
	list, err := m.Backend.ListCongestion()
	if err != nil {
		return res, store.New(store.KindUnsupported, "cannot read available congestion algorithms", err)
	}
	if !contains(list, "bbr") {
		return res, store.New(store.KindUnsupported, "running kernel does not list bbr; apply refused (no kernel replacement)", nil)
	}

	content := renderManagedFile(profile)
	targetHash := sha256Hex([]byte(content))
	oldValues := map[string]string{}
	newValues := map[string]string{}
	changes := []KeyChange{}
	for _, key := range keys {
		old, err := m.Backend.ReadSysctl(key)
		if err != nil {
			return res, store.New(store.KindUnsupported, "read current "+key, err)
		}
		want := profileValues[profile][key]
		oldValues[key] = old
		newValues[key] = want
		changes = append(changes, KeyChange{Key: key, Old: old, New: want})
	}
	if ours.Exists && ours.SHA256 == targetHash {
		sameRuntime := true
		for _, change := range changes {
			if change.Old != change.New {
				sameRuntime = false
				break
			}
		}
		if sameRuntime {
			res.Noop = true
			res.Message = "profile already applied; nothing changed"
			res.Applied = changes
			return res, nil
		}
	}

	recoveredState := &State{
		Version:      stateVersion,
		Profile:      profile,
		FilePath:     mp,
		StatePath:    sp,
		FileExisted:  ours.Exists,
		FileMode:     ours.Mode,
		FileUID:      ours.UID,
		FileGID:      ours.GID,
		TargetHash:   targetHash,
		OldValues:    oldValues,
		NewValues:    newValues,
		Pending:      true,
		CreatedAtUTC: time.Now().UTC().Format(time.RFC3339),
	}
	if ours.Exists {
		raw, err := m.Backend.ReadFile(mp)
		if err != nil {
			return res, classifyIO("read "+mp, err)
		}
		recoveredState.FileContent = string(raw)
	}
	// Journal first: if the process dies after this write, rollback can still
	// restore the snapshot even though the transaction never completed.
	if err := m.saveState(sp, recoveredState); err != nil {
		return res, err
	}

	mode := os.FileMode(0o644)
	if ours.Exists {
		mode = os.FileMode(ours.Mode)
	}
	if err := m.Backend.WriteFile(mp, []byte(content), mode); err != nil {
		_ = m.Backend.RemoveFile(sp)
		return res, classifyIO("write "+mp, err)
	}
	ownerUID, ownerGID := 0, 0
	if ours.Exists {
		ownerUID, ownerGID = ours.UID, ours.GID
	}
	if err := m.Backend.Chown(mp, ownerUID, ownerGID); err != nil {
		_ = m.Backend.RemoveFile(sp)
		_ = m.restoreFile(recoveredState)
		return res, classifyIO("chown "+mp, err)
	}

	applied := []string{}
	for _, key := range keys {
		want := newValues[key]
		old := oldValues[key]
		if old == want {
			continue
		}
		if err := m.Backend.WriteSysctl(key, want); err != nil {
			rbErr := m.rollbackRuntime(applied, oldValues)
			_ = m.restoreFile(recoveredState)
			if rbErr != nil {
				recoveredState.AppliedKeys = applied
				_ = m.saveState(sp, recoveredState)
				return res, store.New(store.KindCorrupt, "apply failed and runtime restore failed; run `idleleo tcp rollback` manually: "+rbErr.Error(), err)
			}
			_ = m.Backend.RemoveFile(sp)
			return res, classifyIO("apply "+key, err)
		}
		applied = append(applied, key)
	}
	for _, key := range applied {
		got, err := m.Backend.ReadSysctl(key)
		if err != nil || got != newValues[key] {
			rbErr := m.rollbackRuntime(applied, oldValues)
			_ = m.restoreFile(recoveredState)
			if rbErr != nil {
				recoveredState.AppliedKeys = applied
				_ = m.saveState(sp, recoveredState)
				return res, store.New(store.KindCorrupt, "verification and runtime restore both failed; run `idleleo tcp rollback` manually", err)
			}
			_ = m.Backend.RemoveFile(sp)
			if err != nil {
				return res, classifyIO("verify "+key, err)
			}
			return res, store.New(store.KindCorrupt, fmt.Sprintf("verification failed for %s: read back %q, expected %q", key, got, newValues[key]), nil)
		}
	}
	recoveredState.AppliedKeys = applied
	recoveredState.AppliedHash = targetHash
	recoveredState.Pending = false
	if err := m.saveState(sp, recoveredState); err != nil {
		rbErr := m.rollbackRuntime(applied, oldValues)
		if rbErr != nil {
			return res, store.New(store.KindCorrupt, "state write failed and runtime restore failed; run `idleleo tcp rollback` manually", err)
		}
		_ = m.restoreFile(recoveredState)
		_ = m.Backend.RemoveFile(sp)
		return res, classifyIO("write state "+sp, err)
	}
	res.Changed = true
	res.Applied = changes
	res.Message = "profile applied"
	return res, nil
}

// Rollback retracts only the changes recorded in this transaction's journal.
// Third-party drift on the same key or file is refused, never overwritten.
func (m *Manager) Rollback() (Result, error) {
	res := Result{Applied: []KeyChange{}}
	if m.Backend.GOOS() != "linux" {
		return res, store.New(store.KindUnsupported, "TCP management is linux-only", nil)
	}
	if !m.Paths.IsSandbox() && !m.Backend.Root() {
		return res, store.New(store.KindPermission, "tcp rollback requires root", nil)
	}
	lockPath, err := m.lockPath()
	if err != nil {
		return res, err
	}
	release, err := m.Backend.Lock(lockPath)
	if err != nil {
		return res, err
	}
	defer release()
	sp, err := m.statePath()
	if err != nil {
		return res, err
	}
	res.StatePath = sp
	state, err := m.loadState(sp)
	if err != nil {
		return res, err
	}
	if state == nil {
		res.Noop = true
		res.Message = "no project-owned TCP transaction to roll back"
		return res, nil
	}
	res.Profile = state.Profile
	res.FilePath = state.FilePath

	expectedHash := state.AppliedHash
	if expectedHash == "" {
		expectedHash = state.TargetHash
	}
	ours, err := m.inspectFile(state.FilePath)
	if err != nil {
		return res, err
	}
	if ours.Exists {
		if expectedHash != "" && ours.SHA256 != expectedHash {
			return res, store.New(store.KindDrift, "managed sysctl file changed outside idleleo; refusing to roll back (manual review required)", nil)
		}
	} else if state.FileExisted {
		return res, store.New(store.KindDrift, "managed sysctl file is missing but the journal recorded an earlier file; refusing to guess", nil)
	}

	keys, err := ProfileKeys(state.Profile)
	if err != nil {
		return res, err
	}
	changes := []KeyChange{}
	for _, key := range keys {
		old, ok := state.OldValues[key]
		if !ok {
			continue
		}
		want, ok := state.NewValues[key]
		if !ok {
			continue
		}
		got, err := m.Backend.ReadSysctl(key)
		if err != nil {
			return res, classifyIO("read current "+key, err)
		}
		switch {
		case got == want:
			changes = append(changes, KeyChange{Key: key, Old: got, New: old})
		case got == old:
			// Someone already restored it; leave it alone.
		default:
			return res, store.New(store.KindDrift, fmt.Sprintf("%s was changed outside idleleo (now %q); refusing to overwrite", key, got), nil)
		}
	}
	if err := m.restoreFile(state); err != nil {
		return res, classifyIO("restore "+state.FilePath, err)
	}
	for _, change := range changes {
		if err := m.Backend.WriteSysctl(change.Key, change.New); err != nil {
			return res, store.New(store.KindCorrupt, "rollback stopped after restoring the file; journal kept for retry at "+sp, err)
		}
	}
	if err := m.Backend.RemoveFile(sp); err != nil {
		return res, classifyIO("remove state "+sp, err)
	}
	res.Changed = true
	res.Applied = changes
	res.Message = "rollback complete"
	return res, nil
}

func (m *Manager) restoreFile(state *State) error {
	if state.FileExisted {
		if err := m.Backend.WriteFile(state.FilePath, []byte(state.FileContent), os.FileMode(state.FileMode)); err != nil {
			return err
		}
		return m.Backend.Chown(state.FilePath, state.FileUID, state.FileGID)
	}
	return m.Backend.RemoveFile(state.FilePath)
}

func (m *Manager) rollbackRuntime(applied []string, oldValues map[string]string) error {
	var failures []string
	for i := len(applied) - 1; i >= 0; i-- {
		key := applied[i]
		if err := m.Backend.WriteSysctl(key, oldValues[key]); err != nil {
			failures = append(failures, key+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (m *Manager) inspectFile(path string) (FileStatus, error) {
	fs := FileStatus{Path: path, Values: map[string]string{}}
	if path == "" {
		return fs, nil
	}
	info, err := m.Backend.StatFile(path)
	if err != nil {
		return fs, classifyIO("stat "+path, err)
	}
	fs.Exists = info.Exists
	fs.Mode = uint32(info.Mode.Perm())
	fs.UID = info.UID
	fs.GID = info.GID
	if !info.Exists {
		return fs, nil
	}
	raw, err := m.Backend.ReadFile(path)
	if err != nil {
		return fs, classifyIO("read "+path, err)
	}
	fs.SHA256 = sha256Hex(raw)
	fs.Owned = strings.Contains(string(raw), managedMarker)
	fs.Values = parseSysctl(string(raw))
	return fs, nil
}

func (m *Manager) scanSources() ([]SysctlSource, FileStatus, int, error) {
	mp, err := m.managedPath()
	if err != nil {
		return nil, FileStatus{}, 0, err
	}
	ours, err := m.inspectFile(mp)
	if err != nil {
		return nil, FileStatus{}, 0, err
	}
	sources := []SysctlSource{}
	confPath, err := m.Paths.Join(sysctlConfRel, true)
	if err != nil {
		return nil, FileStatus{}, 0, err
	}
	if src, ok, err := m.readSource(confPath, confPriority, false); err != nil {
		return nil, FileStatus{}, 0, err
	} else if ok {
		sources = append(sources, src)
	}
	// The directory itself is resolved read-only: Join(forWrite) refuses an
	// existing directory as a final component. A host without /etc/sysctl.d
	// simply has no extra sources.
	dir, err := m.Paths.Join(sysctlDRel, false)
	if err != nil {
		if os.IsNotExist(err) {
			return sources, ours, 0, nil
		}
		return nil, FileStatus{}, 0, err
	}
	names, err := m.Backend.ListDir(dir)
	if err != nil {
		return nil, FileStatus{}, 0, classifyIO("list "+dir, err)
	}
	sort.Strings(names)
	managedName := filepath.Base(ManagedFileRel)
	managedPriority := 0
	for _, name := range names {
		if strings.HasSuffix(name, ".conf") && name < managedName {
			managedPriority++
		}
	}
	index := 0
	for _, name := range names {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		path := filepath.Join(dir, name)
		src, ok, err := m.readSource(path, index, name == managedName)
		if err != nil {
			return nil, FileStatus{}, 0, err
		}
		index++
		if ok {
			sources = append(sources, src)
		}
	}
	return sources, ours, managedPriority, nil
}

func (m *Manager) readSource(path string, priority int, ours bool) (SysctlSource, bool, error) {
	info, err := m.Backend.StatFile(path)
	if err != nil {
		return SysctlSource{}, false, classifyIO("stat "+path, err)
	}
	if !info.Exists {
		return SysctlSource{}, false, nil
	}
	raw, err := m.Backend.ReadFile(path)
	if err != nil {
		return SysctlSource{}, false, classifyIO("read "+path, err)
	}
	return SysctlSource{
		Path:     path,
		Name:     filepath.Base(path),
		Ours:     ours,
		Values:   parseSysctl(string(raw)),
		Priority: priority,
	}, true, nil
}

func (m *Manager) loadState(path string) (*State, error) {
	info, err := m.Backend.StatFile(path)
	if err != nil {
		return nil, classifyIO("stat "+path, err)
	}
	if !info.Exists {
		return nil, nil
	}
	raw, err := m.Backend.ReadFile(path)
	if err != nil {
		return nil, classifyIO("read "+path, err)
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, store.New(store.KindCorrupt, "tcp state is not valid json: "+path, err)
	}
	if state.Version != stateVersion {
		return nil, store.New(store.KindSchemaHigh, fmt.Sprintf("tcp state version %d is not supported", state.Version), nil)
	}
	return &state, nil
}

func (m *Manager) saveState(path string, state *State) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := m.Backend.WriteFile(path, raw, 0o600); err != nil {
		return classifyIO("write state "+path, err)
	}
	return nil
}

// assessSources computes the persisted effective value per key (later files
// win; /etc/sysctl.conf is applied last) and reports files that sort after the
// project file and would override it with a different value. Files with a
// lower numeric prefix are intentionally not conflicts: our 90- file wins on
// the next boot.
func assessSources(sources []SysctlSource, keys []string, managedPriority int) (map[string]string, []string) {
	last := map[string]SysctlSource{}
	for _, src := range sources {
		for key := range src.Values {
			prev, seen := last[key]
			if !seen || src.Priority >= prev.Priority {
				last[key] = src
			}
		}
	}
	effective := map[string]string{}
	conflicts := []string{}
	for _, key := range keys {
		src, ok := last[key]
		if !ok {
			effective[key] = ""
			continue
		}
		effective[key] = src.Values[key]
		if !src.Ours && src.Priority >= managedPriority {
			conflicts = append(conflicts, fmt.Sprintf("%s sets %s=%s after %s; that file wins", src.Path, key, src.Values[key], ManagedFileRel))
		}
	}
	return effective, conflicts
}

func parseSysctl(body string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func renderManagedFile(profile string) string {
	var b strings.Builder
	b.WriteString("# " + managedMarker + " (Go): idleleo tcp\n")
	b.WriteString("# Profile: " + profile + "\n")
	b.WriteString("# Rollback: idleleo tcp rollback\n")
	b.WriteString("# Do not edit; use the idleleo CLI so rollback stays accurate.\n")
	for _, key := range orderedKeys[profile] {
		b.WriteString(key + " = " + profileValues[profile][key] + "\n")
	}
	return b.String()
}

func allProfileKeys() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, keys := range orderedKeys {
		for _, key := range keys {
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func classifyIO(op string, err error) error {
	if err == nil {
		return nil
	}
	if os.IsPermission(err) {
		return store.New(store.KindPermission, op, err)
	}
	return store.New(store.KindCorrupt, op, err)
}
