// Package bridge implements a SANDBOX-ONLY Bash-to-Go management handoff probe.
// It never touches host services, crontab, real network config, or package managers.
// Marker and root constraints are intentionally not suitable for production.
package bridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	legacyConfig  = "etc/idleleo/conf/install_config.json"
	nativeXray    = "etc/idleleo/conf/xray/config.json"
	relayConfig   = "etc/idleleo/conf/nginx/relay-stream.conf"
	managerConfig = "etc/idleleo/manager/config.json"
	journalFile   = "var/lib/idleleo/transactions/bridge-v2.json"
	lockFile      = "var/lib/idleleo/transactions/bridge-v2.lock"
	backupEntry   = "var/lib/idleleo/transactions/legacy-entrypoint.backup"
	entryFile     = "usr/bin/idleleo"
	candidateFile = "opt/idleleo/bin/idleleo"
	candidateLink = "../../opt/idleleo/bin/idleleo"
	sandboxMarker = ".idleleo-probe-sandbox"
	markerValue   = "I_ACCEPT_DISPOSABLE_SANDBOX"
	Protocol      = "idleleo-bridge-probe-v2"
)

var shaHex = regexp.MustCompile(`^[0-9a-f]{64}$`)
var ErrUnsupported = errors.New("unsupported or ambiguous legacy profile")
var ErrInterrupted = errors.New("injected interruption")
var ErrRecoveryRequired = errors.New("manual recovery required: entrypoint or staged artifacts changed")

type Plan struct {
	SchemaVersion int      `json:"schemaVersion"`
	Role          string   `json:"role"`
	TLS           string   `json:"tls,omitempty"`
	Transport     string   `json:"transport,omitempty"`
	LegacySource  string   `json:"legacySource"`
	RuntimeSource string   `json:"runtimeSource"`
	LegacySHA256  string   `json:"legacySha256"`
	RuntimeSHA256 string   `json:"runtimeSha256"`
	SecretPolicy  string   `json:"secretPolicy"`
	Notes         []string `json:"notes"`
}
type Journal struct {
	SchemaVersion           int    `json:"schemaVersion"`
	State                   string `json:"state"`
	Plan                    Plan   `json:"plan"`
	OldEntrypointWasSymlink bool   `json:"oldEntrypointWasSymlink"`
	OldEntrypointTarget     string `json:"oldEntrypointTarget,omitempty"`
	OldEntrypointSHA256     string `json:"oldEntrypointSHA256,omitempty"`
	OldEntrypointMode       uint32 `json:"oldEntrypointMode,omitempty"`
	CandidateSHA256         string `json:"candidateSha256"`
	ManagerSHA256           string `json:"managerSha256"`
	CreatedAt               string `json:"createdAt"`
}

type Health struct {
	State            string `json:"state"`
	Role             string `json:"role"`
	RuntimeUntouched bool   `json:"runtimeUntouched"`
	EntryIsGo        bool   `json:"entryIsGo"`
	EntryIsLegacy    bool   `json:"entryIsLegacy"`
	ManagerPresent   bool   `json:"managerPresent"`
}

func Root(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("sandbox root required")
	}
	abs, e := filepath.Abs(root)
	if e != nil {
		return "", e
	}
	abs, e = filepath.EvalSymlinks(abs)
	if e != nil {
		return "", e
	}
	if abs == "/" {
		return "", errors.New("refuse / as sandbox")
	}
	p := filepath.Join(abs, sandboxMarker)
	fi, e := os.Lstat(p)
	if e != nil {
		return "", e
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("marker must be regular")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	if strings.TrimSpace(string(b)) != markerValue {
		return "", errors.New("sandbox marker mismatch")
	}
	return abs, nil
}
func path(root, rel string) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(rel) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("unsafe relative path")
	}
	current := root
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, component := range parts[:len(parts)-1] {
		current = filepath.Join(current, component)
		fi, e := os.Lstat(current)
		if e != nil {
			if os.IsNotExist(e) {
				continue
			}
			return "", e
		}
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("unsafe parent: %s", current)
		}
	}
	return filepath.Join(root, clean), nil
}
func file(root, rel string) ([]byte, error) {
	p, e := path(root, rel)
	if e != nil {
		return nil, e
	}
	fi, e := os.Lstat(p)
	if e != nil {
		return nil, e
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", rel)
	}
	return os.ReadFile(p)
}
func digest(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func JSON(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
func writeAtomic(root, rel string, b []byte, mode os.FileMode) error {
	p, e := path(root, rel)
	if e != nil {
		return e
	}
	d := filepath.Dir(p)
	if e = os.MkdirAll(d, 0700); e != nil {
		return e
	}
	// Recheck path after mkdir, preventing accidental symlink parents.
	if _, e = path(root, rel); e != nil {
		return e
	}
	f, e := os.CreateTemp(d, ".idleleo-v2-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, p); e != nil {
		return e
	}
	return syncDir(d)
}
func syncDir(d string) error {
	f, e := os.Open(d)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func getString(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}
func asMap(b []byte) (map[string]any, error) {
	var m map[string]any
	e := json.Unmarshal(b, &m)
	if e != nil {
		return nil, e
	}
	if m == nil {
		return nil, errors.New("expected JSON object")
	}
	return m, nil
}

// Inspect is read-only. No service health, client connectivity or cert checks.
func Inspect(root string) (Plan, error) {
	root, e := Root(root)
	if e != nil {
		return Plan{}, e
	}
	old, e := file(root, legacyConfig)
	if e != nil {
		return Plan{}, e
	}
	m, e := asMap(old)
	if e != nil {
		return Plan{}, e
	}
	role := getString(m, "role")
	if role == "" {
		role = "node"
	}
	if role != "node" && role != "relay" {
		return Plan{}, fmt.Errorf("%w: role", ErrUnsupported)
	}
	mode := strings.ToLower(getString(m, "shell_mode"))
	if strings.Contains(mode, "xtls only") || strings.Contains(mode, "xtls-only") {
		return Plan{}, fmt.Errorf("%w: retired XTLS ONLY", ErrUnsupported)
	}
	tls := getString(m, "tls")
	p := Plan{SchemaVersion: 2, Role: role, TLS: tls, Transport: getString(m, "transport_mode"), LegacySource: "/" + legacyConfig, LegacySHA256: digest(old), SecretPolicy: "reference original native config; never copy UUID/privateKey/shortId to manager metadata", Notes: []string{"sandbox-only", "no systemd/ACME/client health checks"}}
	var runtimeBytes []byte
	if role == "relay" {
		xrayPath, _ := path(root, nativeXray)
		if _, e = os.Lstat(xrayPath); e == nil {
			return Plan{}, fmt.Errorf("%w: mixed relay and Xray", ErrUnsupported)
		}
		if getString(m, "relay_backend_host") == "" || getString(m, "relay_backend_port") == "" || getString(m, "relay_listen_port") == "" {
			return Plan{}, fmt.Errorf("%w: relay fields", ErrUnsupported)
		}
		p.RuntimeSource = "/" + relayConfig
		runtimeBytes, e = file(root, relayConfig)
		if e != nil {
			return Plan{}, e
		}
	} else {
		if tls != "Reality" && tls != "TLS" && tls != "None" {
			return Plan{}, fmt.Errorf("%w: tls", ErrUnsupported)
		}
		p.RuntimeSource = "/" + nativeXray
		runtimeBytes, e = file(root, nativeXray)
		if e != nil {
			return Plan{}, e
		}
		native, e := asMap(runtimeBytes)
		if e != nil {
			return Plan{}, e
		}
		inbounds, ok := native["inbounds"].([]any)
		if !ok || len(inbounds) == 0 {
			return Plan{}, fmt.Errorf("%w: no inbounds", ErrUnsupported)
		}
		foundReality, foundPrimary := false, getString(m, "id") == ""
		for _, v := range inbounds {
			inbound, ok := v.(map[string]any)
			if !ok {
				continue
			}
			ss, _ := inbound["streamSettings"].(map[string]any)
			if getString(ss, "security") == "reality" {
				foundReality = true
				rs, _ := ss["realitySettings"].(map[string]any)
				if a, b := getString(m, "privateKey"), getString(rs, "privateKey"); a != "" && b != "" && a != b {
					return Plan{}, fmt.Errorf("%w: REALITY private key mismatch", ErrUnsupported)
				}
			}
			settings, _ := inbound["settings"].(map[string]any)
			clients, _ := settings["clients"].([]any)
			for _, c := range clients {
				cm, _ := c.(map[string]any)
				if x := getString(m, "id"); x != "" && x == getString(cm, "id") {
					foundPrimary = true
				}
			}
		}
		if tls == "Reality" && !foundReality {
			return Plan{}, fmt.Errorf("%w: Reality metadata/runtime mismatch", ErrUnsupported)
		}
		if !foundPrimary {
			return Plan{}, fmt.Errorf("%w: primary UUID mismatch", ErrUnsupported)
		}
	}
	p.RuntimeSHA256 = digest(runtimeBytes)
	return p, nil
}

func getEntry(root string) (symlink bool, target, sha string, mode uint32, e error) {
	p, err := path(root, entryFile)
	if err != nil {
		e = err
		return
	}
	fi, err := os.Lstat(p)
	if err != nil {
		e = err
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		symlink = true
		target, e = os.Readlink(p)
		return
	}
	if !fi.Mode().IsRegular() {
		e = errors.New("entrypoint not symlink/regular")
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		e = err
		return
	}
	sha = digest(b)
	mode = uint32(fi.Mode().Perm())
	return
}
func entryOriginal(root string, j Journal) bool {
	symlink, target, sha, mode, e := getEntry(root)
	if e != nil || symlink != j.OldEntrypointWasSymlink {
		return false
	}
	if symlink {
		return target == j.OldEntrypointTarget
	}
	return sha == j.OldEntrypointSHA256 && mode == j.OldEntrypointMode
}
func entryCandidate(root string) bool {
	s, t, _, _, e := getEntry(root)
	return e == nil && s && t == candidateLink
}
func pinnedCandidate(root, expected string) error {
	if !shaHex.MatchString(expected) {
		return errors.New("trusted candidate SHA256 pin required")
	}
	b, e := file(root, candidateFile)
	if e != nil {
		return e
	}
	if digest(b) != expected {
		return errors.New("candidate SHA256 does not match pin")
	}
	p, _ := path(root, candidateFile)
	fi, e := os.Stat(p)
	if e != nil {
		return e
	}
	if fi.Mode().Perm()&0111 == 0 {
		return errors.New("candidate not executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, p, "--bridge-self-check").Output()
	if e != nil {
		return fmt.Errorf("candidate self-check failed: %w", e)
	}
	var response struct {
		Protocol string `json:"protocol"`
		Schema   int    `json:"schema"`
		GOOS     string `json:"goos"`
		GOARCH   string `json:"goarch"`
	}
	if json.Unmarshal(out, &response) != nil || response.Protocol != Protocol || response.Schema != 2 || response.GOOS != runtime.GOOS || response.GOARCH != runtime.GOARCH {
		return errors.New("candidate self-check unexpected protocol/schema/OS/architecture")
	}
	return nil
}
func readJournal(root string) (Journal, error) {
	b, e := file(root, journalFile)
	if e != nil {
		return Journal{}, e
	}
	var j Journal
	if e = json.Unmarshal(b, &j); e != nil {
		return j, e
	}
	if j.SchemaVersion != 2 || !shaHex.MatchString(j.CandidateSHA256) || !shaHex.MatchString(j.ManagerSHA256) || j.Plan.SchemaVersion != 2 {
		return j, errors.New("unsupported/corrupt journal")
	}
	switch j.State {
	case "PREPARING", "PREPARED", "ACTIVATING", "COMMITTED", "ROLLED_BACK", "RECOVERY_REQUIRED":
	default:
		return j, errors.New("unknown state")
	}
	return j, nil
}
func saveJournal(root string, j Journal) error {
	b, e := JSON(j)
	if e != nil {
		return e
	}
	return writeAtomic(root, journalFile, b, 0600)
}
func takeLock(root string) (func(), error) {
	p, e := path(root, lockFile)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return nil, e
	}
	if _, e = path(root, lockFile); e != nil {
		return nil, e
	}
	fi, e := os.Lstat(p)
	if e == nil && !fi.Mode().IsRegular() {
		return nil, errors.New("unsafe lock path")
	}
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("bridge already locked")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func sourceUnchanged(root string, p Plan) bool {
	old, e := file(root, legacyConfig)
	if e != nil || digest(old) != p.LegacySHA256 {
		return false
	}
	rt, e := file(root, strings.TrimPrefix(p.RuntimeSource, "/"))
	return e == nil && digest(rt) == p.RuntimeSHA256
}
func managerUnchanged(root string, j Journal) bool {
	b, e := file(root, managerConfig)
	return e == nil && digest(b) == j.ManagerSHA256
}

func Prepare(root, pin, fault string) (Journal, error) {
	root, e := Root(root)
	if e != nil {
		return Journal{}, e
	}
	unlock, e := takeLock(root)
	if e != nil {
		return Journal{}, e
	}
	defer unlock()
	jp, _ := path(root, journalFile)
	if _, e = os.Lstat(jp); e == nil {
		return Journal{}, errors.New("journal already exists; recover explicitly")
	}
	if e != nil && !os.IsNotExist(e) {
		return Journal{}, e
	}
	mp, _ := path(root, managerConfig)
	if _, e = os.Lstat(mp); e == nil {
		return Journal{}, errors.New("manager config already exists")
	}
	if e != nil && !os.IsNotExist(e) {
		return Journal{}, e
	}
	bp, _ := path(root, backupEntry)
	if _, e = os.Lstat(bp); e == nil {
		return Journal{}, errors.New("legacy entry backup exists")
	}
	if e != nil && !os.IsNotExist(e) {
		return Journal{}, e
	}
	p, e := Inspect(root)
	if e != nil {
		return Journal{}, e
	}
	if e = pinnedCandidate(root, pin); e != nil {
		return Journal{}, e
	}
	oldLink, target, sha, mode, e := getEntry(root)
	if e != nil {
		return Journal{}, e
	}
	cfg, e := JSON(p)
	if e != nil {
		return Journal{}, e
	}
	j := Journal{SchemaVersion: 2, State: "PREPARING", Plan: p, OldEntrypointWasSymlink: oldLink, OldEntrypointTarget: target, OldEntrypointSHA256: sha, OldEntrypointMode: mode, CandidateSHA256: pin, ManagerSHA256: digest(cfg), CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if e = saveJournal(root, j); e != nil {
		return j, e
	}
	if fault == "after-journal" {
		return j, ErrInterrupted
	}
	if !oldLink {
		oldBytes, e := file(root, entryFile)
		if e != nil {
			return j, e
		}
		if digest(oldBytes) != j.OldEntrypointSHA256 {
			return j, errors.New("entry drift during prepare")
		}
		if e = writeAtomic(root, backupEntry, oldBytes, 0600); e != nil {
			return j, e
		}
	}
	if !entryOriginal(root, j) {
		return j, errors.New("entry drift during prepare")
	}
	if e = writeAtomic(root, managerConfig, cfg, 0600); e != nil {
		return j, e
	}
	if fault == "after-config" {
		return j, ErrInterrupted
	}
	j.State = "PREPARED"
	if e = saveJournal(root, j); e != nil {
		return j, e
	}
	return j, nil
}
func linkEntry(root, target string) error {
	p, e := path(root, entryFile)
	if e != nil {
		return e
	}
	d := filepath.Dir(p)
	tmp, e := os.CreateTemp(d, ".idleleo-link-")
	if e != nil {
		return e
	}
	name := tmp.Name()
	tmp.Close()
	os.Remove(name)
	if e = os.Symlink(target, name); e != nil {
		return e
	}
	defer os.Remove(name)
	if e = os.Rename(name, p); e != nil {
		return e
	}
	return syncDir(d)
}
func Activate(root, fault string) (Journal, error) {
	root, e := Root(root)
	if e != nil {
		return Journal{}, e
	}
	unlock, e := takeLock(root)
	if e != nil {
		return Journal{}, e
	}
	defer unlock()
	j, e := readJournal(root)
	if e != nil {
		return j, e
	}
	if j.State != "PREPARED" {
		return j, fmt.Errorf("not PREPARED: %s", j.State)
	}
	if !entryOriginal(root, j) {
		return j, errors.New("old entry drift: refusing activation")
	}
	if !sourceUnchanged(root, j.Plan) {
		return j, errors.New("runtime or legacy config drift")
	}
	if !managerUnchanged(root, j) {
		return j, errors.New("manager candidate changed")
	}
	if e = pinnedCandidate(root, j.CandidateSHA256); e != nil {
		return j, e
	}
	if !j.OldEntrypointWasSymlink {
		backup, e := file(root, backupEntry)
		if e != nil {
			return j, e
		}
		if digest(backup) != j.OldEntrypointSHA256 {
			return j, errors.New("entry backup drift")
		}
	}
	j.State = "ACTIVATING"
	if e = saveJournal(root, j); e != nil {
		return j, e
	}
	if fault == "after-activating" {
		return j, ErrInterrupted
	}
	if e = linkEntry(root, candidateLink); e != nil {
		return j, e
	}
	if fault == "after-swap" {
		return j, ErrInterrupted
	}
	if !entryCandidate(root) {
		return j, errors.New("entry check failed")
	}
	if e = pinnedCandidate(root, j.CandidateSHA256); e != nil {
		return j, e
	}
	j.State = "COMMITTED"
	if e = saveJournal(root, j); e != nil {
		return j, e
	}
	return j, nil
}
func recoveryNeeded(root string, j Journal, why string) (Journal, error) {
	j.State = "RECOVERY_REQUIRED"
	// Do not report recovery success when journal itself cannot be persisted.
	if e := saveJournal(root, j); e != nil {
		return j, fmt.Errorf("%s; journal write failed: %w", why, e)
	}
	return j, fmt.Errorf("%w: %s", ErrRecoveryRequired, why)
}
func removeStagedManager(root string, j Journal) error {
	mp, e := path(root, managerConfig)
	if e != nil {
		return e
	}
	_, e = os.Lstat(mp)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !managerUnchanged(root, j) {
		return errors.New("staged manager modified; refusing cleanup")
	}
	if e = os.Remove(mp); e != nil {
		return e
	}
	return syncDir(filepath.Dir(mp))
}
func Recover(root string) (Journal, error) {
	root, e := Root(root)
	if e != nil {
		return Journal{}, e
	}
	unlock, e := takeLock(root)
	if e != nil {
		return Journal{}, e
	}
	defer unlock()
	j, e := readJournal(root)
	if e != nil {
		return j, e
	}
	if j.State == "ROLLED_BACK" {
		return j, nil
	}
	if j.State == "COMMITTED" {
		return j, errors.New("COMMITTED requires separate authorized rollback procedure")
	}
	if j.State == "RECOVERY_REQUIRED" {
		return j, ErrRecoveryRequired
	}
	old := entryOriginal(root, j)
	switched := entryCandidate(root)
	if !old && !switched {
		return recoveryNeeded(root, j, "entry is neither recorded legacy nor recorded Go candidate")
	}
	if switched {
		if j.State != "ACTIVATING" {
			return recoveryNeeded(root, j, "entry switched outside ACTIVATING state")
		}
		if j.OldEntrypointWasSymlink {
			if e = linkEntry(root, j.OldEntrypointTarget); e != nil {
				return recoveryNeeded(root, j, "cannot restore legacy symlink")
			}
		} else {
			oldBytes, er := file(root, backupEntry)
			if er != nil || digest(oldBytes) != j.OldEntrypointSHA256 {
				return recoveryNeeded(root, j, "entry backup absent or wrong hash")
			}
			if e = writeAtomic(root, entryFile, oldBytes, os.FileMode(j.OldEntrypointMode)); e != nil {
				return recoveryNeeded(root, j, "cannot restore legacy entry")
			}
		}
		if !entryOriginal(root, j) {
			return recoveryNeeded(root, j, "restored entry does not match old entry")
		}
	}
	// Only remove the exact manager file that Prepare created.
	if e = removeStagedManager(root, j); e != nil {
		return recoveryNeeded(root, j, "manager config drift or removal failure")
	}
	j.State = "ROLLED_BACK"
	if e = saveJournal(root, j); e != nil {
		return j, e
	}
	return j, nil
}
func Status(root string) (Health, error) {
	root, e := Root(root)
	if e != nil {
		return Health{}, e
	}
	j, e := readJournal(root)
	if e != nil {
		return Health{}, e
	}
	rt, e := file(root, strings.TrimPrefix(j.Plan.RuntimeSource, "/"))
	if e != nil {
		return Health{}, e
	}
	mp, _ := path(root, managerConfig)
	fi, e := os.Lstat(mp)
	present := e == nil && fi.Mode().IsRegular()
	return Health{State: j.State, Role: j.Plan.Role, RuntimeUntouched: digest(rt) == j.Plan.RuntimeSHA256, EntryIsGo: entryCandidate(root), EntryIsLegacy: entryOriginal(root, j), ManagerPresent: present}, nil
}

// Test-only primitive: independent recovery is performed by a separate executable
// invoking the same Recover API, never through the replaced entrypoint.
var _ io.Reader
