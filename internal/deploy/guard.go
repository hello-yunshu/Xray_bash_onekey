package deploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// Unknown-SNI policies, matching the Bash SNI Guard menu.
const (
	SNIPolicyIsolate = "isolate"
	SNIPolicyReject  = "reject"
	SNIPolicyDecoy   = "decoy"
)

// Reserved loopback ports used by the deny upstream of each policy.
const (
	GuardIsolatePort = 9403
	GuardRejectPort  = 9404
	GuardDecoyPort   = 9444
)

const (
	guardCertRel     = "etc/idleleo/cert"
	guardDecoyRel    = "etc/idleleo/decoy"
	guardIsolateFrag = "03-isolate.conf"
	guardDecoyFrag   = "03-decoy.conf"
)

var guardDomain = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// guardDenyServer rewrites the loopback port of the deny upstream without
// regenerating the whole stream block, so the install's public port is kept.
var guardDenyServer = regexp.MustCompile(`(?s)(upstream\s+deny\s*\{[^}]*?server\s+127\.0\.0\.1:)(\d+)(\s*;)`)

// guardInclude matches the only main-config lines a policy change owns.
var guardInclude = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+/etc/idleleo/conf/nginx/03-(?:isolate|decoy)\.conf;[ \t]*\r?\n?`)

// guardResolveHost is a seam: tests must not depend on public DNS.
var guardResolveHost = net.LookupHost

// SNIGuardSpec is one policy change request.
type SNIGuardSpec struct {
	Root                 string
	AllowContainerWrites bool
	Policy               string
	DecoyDomain          string
	// DecoyCert/DecoyKey optionally import an existing certificate pair. When
	// empty a self-signed certificate is generated, matching the Bash flow.
	DecoyCert string
	DecoyKey  string
	// DecoyIPs declares extra addresses the decoy domain may resolve to, for
	// hosts behind NAT where the public address is not on an interface.
	DecoyIPs []string
	DryRun   bool
}

// SNIGuardReport is the machine-readable result.
type SNIGuardReport struct {
	Mode        string   `json:"mode"`
	Policy      string   `json:"policy"`
	DecoyDomain string   `json:"decoyDomain,omitempty"`
	DenyPort    int      `json:"denyPort"`
	Changed     bool     `json:"changed"`
	DryRun      bool     `json:"dryRun"`
	Files       []string `json:"files"`
	Reloaded    bool     `json:"reloaded"`
	SelfSigned  bool     `json:"selfSigned,omitempty"`
	Warnings    []string `json:"warnings"`
}

type guardChange struct {
	path   string
	data   []byte
	delete bool
}

// SetSNIGuard changes the Reality+Nginx unknown-SNI policy with the same
// artifacts Bash writes: an isolate site, a decoy site, or a dead deny port.
func SetSNIGuard(ctx context.Context, spec SNIGuardSpec) (SNIGuardReport, error) {
	rep := SNIGuardReport{Policy: spec.Policy, DryRun: spec.DryRun, Files: []string{}, Warnings: []string{}}
	policy, err := normalizeSNIPolicy(spec.Policy)
	if err != nil {
		return rep, err
	}
	rep.Policy = policy

	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return rep, err
	}
	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return rep, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return rep, err
		}
		defer lock.Release()
		// The first read of metadata, artifacts and the plan must happen under
		// the same lock a concurrent install/edit/certificate change takes.
		if rec, recErr := recoverPendingLocked(ctx, paths); recErr != nil {
			return rep, recErr
		} else if rec.Action != "none" {
			rep.Warnings = append(rep.Warnings, "converged a pending deploy transaction: "+rec.Action)
			if serviceManaged(paths.Root) {
				if testErr := balanceNginxTest(ctx, paths.Root); testErr == nil {
					_ = balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings)
				}
			}
		}
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return rep, err
	}
	rep.Mode = meta.TLS
	if meta.TLS != "Reality" {
		return rep, fmt.Errorf("the current install mode %q has no Reality SNI front", meta.TLS)
	}

	nginxDir, err := paths.Join(nginxDirRel, false)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Nginx front: %w", err)
	}
	mainConf, err := paths.Join(filepath.Join(nginx.InstallDirRel, "conf/nginx.conf"), false)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Nginx front: %w", err)
	}
	xrayConf := filepath.Join(nginxDir, nginx.MainConf)
	xrayBody, err := os.ReadFile(xrayConf)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Reality+Nginx front: %w", err)
	}
	if !strings.Contains(string(xrayBody), "$ssl_preread_server_name") || !guardDenyServer.Match(xrayBody) {
		return rep, errors.New("this install is not a managed Reality+Nginx front: deny upstream not found")
	}
	mainBody, err := os.ReadFile(mainConf)
	if err != nil {
		return rep, err
	}

	denyPort := sniguardPort(policy)
	rep.DenyPort = denyPort
	if err := guardPortConflict(paths, meta, denyPort); err != nil {
		return rep, err
	}

	isolatePath := filepath.Join(nginxDir, guardIsolateFrag)
	decoyPath := filepath.Join(nginxDir, guardDecoyFrag)

	changes := make([]guardChange, 0, 8)
	if updated, changed := rewriteDenyPort(string(xrayBody), denyPort); changed {
		changes = append(changes, guardChange{path: xrayConf, data: []byte(updated)})
	}

	switch policy {
	case SNIPolicyIsolate:
		changes = append(changes,
			guardChange{path: isolatePath, data: []byte(isolateFragment())},
			guardChange{path: decoyPath, delete: true},
		)
	case SNIPolicyReject:
		changes = append(changes,
			guardChange{path: isolatePath, delete: true},
			guardChange{path: decoyPath, delete: true},
		)
	case SNIPolicyDecoy:
		domain := strings.TrimSpace(spec.DecoyDomain)
		if err := validateDecoyDomain(domain); err != nil {
			return rep, err
		}
		rep.DecoyDomain = domain
		if err := verifyDecoyDomain(domain, spec.DecoyIPs); err != nil {
			return rep, err
		}
		certPath, keyPath, certPEM, keyPEM, generated, err := prepareDecoyCert(paths, spec, domain)
		if err != nil {
			return rep, err
		}
		rep.SelfSigned = generated
		webroot, err := paths.Join(guardDecoyRel, true)
		if err != nil {
			return rep, err
		}
		changes = append(changes,
			guardChange{path: certPath, data: certPEM},
			guardChange{path: keyPath, data: keyPEM},
			guardChange{path: filepath.Join(webroot, "index.html"), data: []byte(decoyIndex(domain, decoyToken()))},
			guardChange{path: decoyPath, data: []byte(decoyFragment(domain, certPath, keyPath, webroot))},
			guardChange{path: isolatePath, delete: true},
		)
	}

	updatedMain, mainChanged, err := rewriteGuardInclude(string(mainBody), policy)
	if err != nil {
		return rep, err
	}
	if mainChanged {
		changes = append(changes, guardChange{path: mainConf, data: []byte(updatedMain)})
	}

	meta.SNIGuard = &store.SNIGuardState{
		Enabled:     true,
		Policy:      policy,
		DecoyDomain: rep.DecoyDomain,
	}
	meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaBytes = append(metaBytes, '\n')
	metaPath, err := paths.Join(paths.ManagerMetadata(), false)
	if err != nil {
		return rep, err
	}
	changes = append(changes, guardChange{path: metaPath, data: metaBytes})

	for _, ch := range changes {
		rep.Files = append(rep.Files, ch.path)
	}
	if spec.DryRun {
		rep.Changed = len(changes) > 0
		return rep, nil
	}

	backups, err := captureGuardFiles(changes)
	if err != nil {
		return rep, err
	}
	// Persist the snapshot before mutating: a SIGKILL between two file writes is
	// then converged by the next lock holder instead of leaving a half-applied
	// policy on disk.
	journal, err := newJournal(paths, backups, serviceState{}, nil, meta.TLS, meta.Transport)
	if err != nil {
		return rep, err
	}
	if err := applyGuardChanges(changes); err != nil {
		return rep, guardRollback(paths, &journal, backups, err, "apply")
	}
	if err := balanceNginxTest(ctx, paths.Root); err != nil {
		return rep, guardRollback(paths, &journal, backups, err, "nginx -t")
	}
	rep.Changed = true
	var workerMasterPID int
	var workerMasterTicks uint64
	var workersBefore map[nginxWorkerIdentity]struct{}
	if serviceManaged(paths.Root) {
		pid, ticks, identityErr := currentNginxIdentity(paths)
		if identityErr != nil {
			rep.Warnings = append(rep.Warnings, "cannot verify the Nginx worker generation before reload: "+identityErr.Error())
		} else if workers, workersErr := nginxWorkerIdentities(pid); workersErr != nil {
			rep.Warnings = append(rep.Warnings, "cannot verify the Nginx worker generation before reload: "+workersErr.Error())
		} else {
			workerMasterPID, workerMasterTicks, workersBefore = pid, ticks, workers
		}
	}
	if err := balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings); err != nil {
		rbErr := guardRollback(paths, &journal, backups, err, "reload")
		if rbErr == nil {
			// The files are back; bring the running master in sync with them.
			if testErr := balanceNginxTest(ctx, paths.Root); testErr == nil {
				_ = balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings)
			}
		}
		return rep, rbErr
	}
	if rep.Reloaded {
		if workersBefore == nil {
			rep.Warnings = append(rep.Warnings, "the reload command completed, but the Nginx worker generation could not be confirmed; runtime status remains unverified")
		} else if err := waitNginxWorkerGeneration(ctx, workerMasterPID, workerMasterTicks, workersBefore, 2*time.Second); err != nil {
			rbErr := guardRollback(paths, &journal, backups, err, "reload confirmation")
			if rbErr == nil {
				// Restore the prior on-disk policy and ask the master to converge to
				// it. The old runtime record remains valid only if that content and
				// process instance still match.
				if testErr := balanceNginxTest(ctx, paths.Root); testErr == nil {
					_ = balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings)
				}
			}
			return rep, rbErr
		} else if pid, ticks, pidErr := currentNginxIdentity(paths); pidErr != nil {
			rep.Warnings = append(rep.Warnings, "the reload was applied but the running Nginx instance could not be identified: "+pidErr.Error())
		} else if err := writeGuardRuntimeRecord(paths, rep.Policy, guardRuntimeEvidence(paths), pid, ticks); err != nil {
			rep.Warnings = append(rep.Warnings, "the reload was applied but the runtime verification record could not be written: "+err.Error())
		}
	}
	if err := journalMarkCommitted(paths, &journal); err != nil {
		return rep, err
	}
	return rep, nil
}

// guardRollback restores every guard file and records a terminal journal state.
// It distinguishes a completed rollback from RECOVERY_NEEDED; a failed restore
// is never reported as "the previous policy was restored".
func guardRollback(paths host.Paths, j *deployJournal, backups []fileState, cause error, stage string) error {
	if err := restoreGuardFiles(backups); err != nil {
		journalMarkRecoveryRequired(paths, j, err)
		return fmt.Errorf("%w; %s failed and the rollback did not complete: %v (RECOVERY_NEEDED, run 'idleleo recover')",
			cause, stage, err)
	}
	_ = journalMarkRolledBack(paths, j, cause)
	return fmt.Errorf("%w; the previous SNI Guard policy was restored", cause)
}

// SNIGuardStatus is the read-only view of the unknown-SNI policy. It is derived
// from the deployed Nginx artifacts and reconciled with metadata; it never
// invents "enabled/isolate" for a node that has no managed Reality front.
type SNIGuardStatus struct {
	Applicable     bool     `json:"applicable"`
	TLS            string   `json:"tls,omitempty"`
	ManagedFront   bool     `json:"managedFront"`
	Enabled        bool     `json:"enabled"`
	Policy         string   `json:"policy,omitempty"`
	DecoyDomain    string   `json:"decoyDomain,omitempty"`
	Status         string   `json:"status"`
	MetadataSynced bool     `json:"metadataSynced"`
	DenyPort       int      `json:"denyPort,omitempty"`
	Evidence       []string `json:"evidence"`
	Warnings       []string `json:"warnings"`
}

var (
	guardDecoyServerName = regexp.MustCompile(`(?m)^[ \t]*server_name[ \t]+([^;]+);`)
	guardIncludePolicy   = regexp.MustCompile(`\binclude[ \t]+/etc/idleleo/conf/nginx/(03-(?:isolate|decoy)\.conf)\s*;`)
	guardIncludeGlob     = regexp.MustCompile(`\binclude[ \t]+/etc/idleleo/conf/nginx/\*\.conf\s*;`)
)

// InspectSNIGuard reports the actual policy and any disagreement between the
// deployed files and the ownership metadata. It is strictly read-only.
func InspectSNIGuard(root string) (SNIGuardStatus, error) {
	st := SNIGuardStatus{Evidence: []string{}, Warnings: []string{}, Status: "not-applicable"}
	paths, err := host.NewPaths(root)
	if err != nil {
		return st, err
	}
	meta, _, metaErr := store.LoadMetadata(paths)
	if metaErr == nil {
		st.TLS = meta.TLS
	} else {
		st.Warnings = append(st.Warnings, "manager metadata is unavailable; runtime artifacts only")
	}
	if st.TLS != "" && st.TLS != "Reality" {
		return st, nil
	}
	nginxDir, err := paths.Join(nginxDirRel, false)
	if err != nil {
		return st, nil
	}
	xrayConf := filepath.Join(nginxDir, nginx.MainConf)
	body, err := os.ReadFile(xrayConf)
	if err != nil {
		return st, nil
	}
	text := string(body)
	if !strings.Contains(text, "$ssl_preread_server_name") {
		return st, nil
	}
	loc := guardDenyServer.FindStringSubmatchIndex(text)
	if loc == nil {
		return st, nil
	}
	st.Applicable = true
	st.ManagedFront = true
	port, _ := strconv.Atoi(text[loc[4]:loc[5]])
	st.DenyPort = port
	st.Evidence = append(st.Evidence, xrayConf)

	mainConf, err := paths.Join(filepath.Join(nginx.InstallDirRel, "conf/nginx.conf"), false)
	if err != nil {
		return st, err
	}

	inconsistent := func(reason string) (SNIGuardStatus, error) {
		st.Status = "inconsistent"
		st.Warnings = append(st.Warnings, reason)
		return st, nil
	}

	mainBody, readErr := os.ReadFile(mainConf)
	if readErr != nil {
		// Without the main config the include chain is unknown. Inferring a
		// policy from the fragment directory would report a protection that may
		// not be loaded at all.
		return inconsistent("cannot read the managed Nginx main configuration " + mainConf + ": " + readErr.Error())
	}
	st.Evidence = append(st.Evidence, mainConf)
	includes := map[string]bool{}
	for _, m := range guardIncludePolicy.FindAllStringSubmatch(string(mainBody), -1) {
		includes[m[1]] = true
	}
	globInclude := guardIncludeGlob.Match(mainBody)

	decoyFrag := filepath.Join(nginxDir, guardDecoyFrag)
	isolateFrag := filepath.Join(nginxDir, guardIsolateFrag)
	hasDecoy := fileExists(decoyFrag)
	hasIsolate := fileExists(isolateFrag)
	if hasDecoy {
		st.Evidence = append(st.Evidence, decoyFrag)
		if raw, err := os.ReadFile(decoyFrag); err == nil {
			if m := guardDecoyServerName.FindStringSubmatch(string(raw)); m != nil {
				st.DecoyDomain = strings.TrimSpace(m[1])
			}
		}
	}
	if hasIsolate {
		st.Evidence = append(st.Evidence, isolateFrag)
	}
	if hasDecoy && hasIsolate {
		return inconsistent("both 03-isolate.conf and 03-decoy.conf exist")
	}
	if includes[guardIsolateFrag] && includes[guardDecoyFrag] {
		return inconsistent("nginx.conf includes both isolate and decoy fragments")
	}
	if hasDecoy && !includes[guardDecoyFrag] && !globInclude {
		return inconsistent("03-decoy.conf exists but nginx.conf does not include it")
	}
	if hasIsolate && !includes[guardIsolateFrag] && !globInclude {
		return inconsistent("03-isolate.conf exists but nginx.conf does not include it")
	}

	switch {
	case hasDecoy:
		st.Policy = SNIPolicyDecoy
		if port != GuardDecoyPort {
			return inconsistent(fmt.Sprintf("decoy fragment present but the deny upstream is port %d", port))
		}
	case hasIsolate:
		st.Policy = SNIPolicyIsolate
		if port != GuardIsolatePort {
			return inconsistent(fmt.Sprintf("isolate fragment present but the deny upstream is port %d", port))
		}
	case port == GuardDecoyPort:
		return inconsistent("the deny upstream targets the decoy port but 03-decoy.conf is missing")
	case port == GuardIsolatePort && !hasIsolate:
		return inconsistent("the deny upstream targets the isolate port but 03-isolate.conf is missing")
	case port == GuardIsolatePort:
		st.Policy = SNIPolicyIsolate
	default:
		st.Policy = SNIPolicyReject
	}
	st.Enabled = true
	// "active" is a runtime claim: it needs a live managed Nginx whose identity
	// and load state can be proven. Anything less is reported truthfully as
	// configured or runtime-unverified instead of pretending the policy applies.
	if verified, alive, reason := nginxPolicyRuntimeVerified(paths, st.Evidence, st.Policy); verified {
		st.Status = "active"
	} else {
		if alive {
			st.Status = "runtime-unverified"
		} else {
			st.Status = "configured"
		}
		if reason != "" {
			st.Warnings = append(st.Warnings, reason)
		}
	}

	if metaErr != nil {
		st.MetadataSynced = false
		return st, nil
	}
	if meta.SNIGuard == nil {
		st.MetadataSynced = false
		st.Warnings = append(st.Warnings, "metadata has no sniGuard record; showing deployed artifacts, nothing was rewritten")
		return st, nil
	}
	if !meta.SNIGuard.Enabled {
		st.MetadataSynced = false
		if st.Enabled {
			st.Status = "drift"
			st.Warnings = append(st.Warnings, "metadata says sniGuard is disabled but the deployed front still applies a policy")
			return st, nil
		}
		st.Enabled = false
		return st, nil
	}
	if meta.SNIGuard.Policy != st.Policy {
		st.MetadataSynced = false
		st.Status = "drift"
		st.Warnings = append(st.Warnings, fmt.Sprintf("metadata policy %q does not match deployed policy %q", meta.SNIGuard.Policy, st.Policy))
		return st, nil
	}
	if st.DecoyDomain == "" {
		st.DecoyDomain = meta.SNIGuard.DecoyDomain
	} else if meta.SNIGuard.DecoyDomain != "" && st.DecoyDomain != meta.SNIGuard.DecoyDomain {
		st.MetadataSynced = false
		st.Status = "drift"
		st.Warnings = append(st.Warnings, fmt.Sprintf("metadata decoy domain %q does not match the deployed domain %q", meta.SNIGuard.DecoyDomain, st.DecoyDomain))
		return st, nil
	}
	// Only now is every artifact/metadata comparison known to agree.
	st.MetadataSynced = true
	return st, nil
}

// nginxProcess is the verifiable identity of the managed Nginx master.
//
// StartTicks is the kernel's per-process start time in clock ticks since boot
// (field 22 of /proc/<pid>/stat). Together with PID it identifies one process
// instance, so a reload record cannot be reused after a restart or pid reuse.
type nginxProcess struct {
	Alive      bool
	Exe        string
	Started    time.Time
	PID        int
	StartTicks uint64
}

// inspectNginxProcess is a variable so tests can simulate a managed master
// without starting Nginx; production always reads the real /proc entry.
var inspectNginxProcess = readNginxProcess

// nginxPolicyRuntimeVerified proves three things before "active" is claimed:
// the pid belongs to the managed Nginx binary, that process is alive, and a
// successful reload recorded exactly these file hashes for this process
// instance. Process start time and file mtimes cannot prove loaded contents.
func nginxPolicyRuntimeVerified(paths host.Paths, evidence []string, policy string) (verified, alive bool, reason string) {
	bin := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel), "sbin", "nginx")
	if fi, err := os.Stat(bin); err != nil || !fi.Mode().IsRegular() {
		return false, false, "the managed Nginx binary is missing; reporting configured, not active"
	}
	pidFile := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel), "logs", "nginx.pid")
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		return false, false, "the managed Nginx pid file is missing; reporting configured, not active"
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return false, false, "the managed Nginx pid file is invalid; reporting configured, not active"
	}
	proc, err := inspectNginxProcess(bin, pid)
	if err != nil || !proc.Alive {
		return false, false, "the managed Nginx is not running; reporting configured, not active"
	}
	if proc.Exe != "" && !samePath(proc.Exe, bin) {
		return false, true, fmt.Sprintf("pid %d runs %s, not the managed Nginx; reporting runtime-unverified", pid, proc.Exe)
	}
	record, err := readGuardRuntimeRecord(paths)
	if err == nil && record.Policy == policy && record.Digest == guardEvidenceDigest(evidence) &&
		record.PID == pid && record.StartTicks != 0 && record.StartTicks == proc.StartTicks {
		return true, true, ""
	}
	return false, true, "no verified reload record matches the current policy content and Nginx process instance; reporting runtime-unverified"
}

func samePath(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}

// readNginxProcess reads /proc to verify the pid belongs to the managed binary
// and to learn when it started. Without /proc (non-Linux) identity and load
// state cannot be proven, which the caller reports as unverified.
//
// The start time must come from /proc/<pid>/stat field 22 plus /proc/stat btime.
// The /proc/<pid> directory mtime is not a process start time: it changes when
// entries are created or removed and produced false "active" claims.
func readNginxProcess(bin string, pid int) (nginxProcess, error) {
	proc := nginxProcess{PID: pid}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return proc, fmt.Errorf("cannot read /proc/%d/exe: %w", pid, err)
	}
	proc.Exe = exe
	proc.Alive = processAlive(pid)
	if !proc.Alive {
		return proc, nil
	}
	ticks, started, err := processStartTime(pid)
	if err != nil {
		return proc, err
	}
	proc.StartTicks = ticks
	proc.Started = started
	return proc, nil
}

// clockTicksPerSecond is USER_HZ. Linux exposes it as 100 on every supported
// architecture; the value only scales the start timestamp, never a security
// decision on its own.
const clockTicksPerSecond = 100

// processStartTime returns the kernel start ticks of pid and the wall-clock
// time derived from the boot time recorded in /proc/stat.
func processStartTime(pid int) (uint64, time.Time, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("cannot read /proc/%d/stat: %w", pid, err)
	}
	// The comm field is parenthesised and may contain spaces and parentheses;
	// the remaining fields start after the last ')'.
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 || end+2 >= len(raw) {
		return 0, time.Time{}, fmt.Errorf("/proc/%d/stat has no field list", pid)
	}
	fields := strings.Fields(string(raw[end+2:]))
	// fields[0] is field 3 (state); starttime is field 22, i.e. index 19.
	if len(fields) < 20 {
		return 0, time.Time{}, fmt.Errorf("/proc/%d/stat is truncated", pid)
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("/proc/%d/stat starttime: %w", pid, err)
	}
	boot, err := bootTime()
	if err != nil {
		return ticks, time.Time{}, err
	}
	return ticks, boot.Add(time.Duration(ticks) * time.Second / clockTicksPerSecond), nil
}

func bootTime() (time.Time, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot read /proc/stat: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("/proc/stat btime: %w", err)
		}
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, errors.New("/proc/stat has no btime line")
}

// currentNginxIdentity returns the pid and start ticks of the managed master.
// It deliberately bypasses the inspectNginxProcess seam: the reload record must
// describe the real process, never a test double.
func currentNginxIdentity(paths host.Paths) (int, uint64, error) {
	pidFile := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel), "logs", "nginx.pid")
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return 0, 0, fmt.Errorf("invalid pid file %s", pidFile)
	}
	ticks, _, err := processStartTime(pid)
	if err != nil {
		return 0, 0, err
	}
	return pid, ticks, nil
}

type nginxWorkerIdentity struct {
	PID        int
	StartTicks uint64
}

// nginxWorkerIdentities returns the direct worker process identities under a
// managed Nginx master. A new worker generation is the cheapest local signal
// that the master consumed an asynchronous reload; the reload command's zero
// exit status alone only proves that a signal was sent.
func nginxWorkerIdentities(masterPID int) (map[nginxWorkerIdentity]struct{}, error) {
	path := fmt.Sprintf("/proc/%d/task/%d/children", masterPID, masterPID)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	workers := make(map[nginxWorkerIdentity]struct{})
	for _, field := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			return nil, fmt.Errorf("invalid child pid %q in %s", field, path)
		}
		ticks, _, err := processStartTime(pid)
		if err != nil {
			// A worker can exit while the child list is being read. Ignore that
			// race; the next poll will observe the stable generation.
			continue
		}
		workers[nginxWorkerIdentity{PID: pid, StartTicks: ticks}] = struct{}{}
	}
	if len(workers) == 0 {
		return nil, fmt.Errorf("managed Nginx master %d has no readable worker processes", masterPID)
	}
	return workers, nil
}

func waitNginxWorkerGeneration(ctx context.Context, masterPID int, masterTicks uint64,
	previous map[nginxWorkerIdentity]struct{}, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		ticks, _, err := processStartTime(masterPID)
		if err != nil || ticks != masterTicks {
			return fmt.Errorf("managed Nginx master changed during reload confirmation")
		}
		if workers, err := nginxWorkerIdentities(masterPID); err == nil {
			for worker := range workers {
				if _, existed := previous[worker]; !existed {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("reload confirmation canceled before a new Nginx worker generation appeared: %w", ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("Nginx reload command succeeded but no new worker generation appeared within %s", timeout)
		case <-ticker.C:
		}
	}
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	return err == nil && proc.Signal(syscall.Signal(0)) == nil
}

type guardRuntimeRecord struct {
	SchemaVersion int    `json:"schemaVersion"`
	Policy        string `json:"policy"`
	Digest        string `json:"digest"`
	PID           int    `json:"pid"`
	StartTicks    uint64 `json:"startTicks"`
	VerifiedAt    string `json:"verifiedAt"`
}

// Schema 2 binds the record to a process instance. A schema-1 record only named
// content, so a restart or pid reuse could keep claiming "active"; those records
// are deliberately ignored.
const guardRuntimeRecordSchema = 2

func guardRuntimeRecordPath(paths host.Paths) string {
	return filepath.Join(paths.Root, "var/lib/idleleo/state/guard-runtime.json")
}

func guardRuntimeEvidence(paths host.Paths) []string {
	evidence := []string{
		filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel), "conf", "nginx.conf"),
		filepath.Join(paths.Root, filepath.FromSlash(nginxDirRel), nginx.MainConf),
	}
	for _, frag := range []string{guardDecoyFrag, guardIsolateFrag} {
		path := filepath.Join(paths.Root, filepath.FromSlash(nginxDirRel), frag)
		if fileExists(path) {
			evidence = append(evidence, path)
		}
	}
	return evidence
}

func guardEvidenceDigest(evidence []string) string {
	// The inspection and apply paths discover the same files in different
	// orders; the digest must describe the content, not the discovery order.
	files := append([]string(nil), evidence...)
	sort.Strings(files)
	h := sha256.New()
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		h.Write([]byte(filepath.Clean(path)))
		h.Write([]byte{0})
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeGuardRuntimeRecord(paths host.Paths, policy string, evidence []string, pid int, startTicks uint64) error {
	path := guardRuntimeRecordPath(paths)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	record := guardRuntimeRecord{
		SchemaVersion: guardRuntimeRecordSchema,
		Policy:        policy,
		Digest:        guardEvidenceDigest(evidence),
		PID:           pid,
		StartTicks:    startTicks,
		VerifiedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readGuardRuntimeRecord(paths host.Paths) (guardRuntimeRecord, error) {
	var record guardRuntimeRecord
	raw, err := os.ReadFile(guardRuntimeRecordPath(paths))
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, err
	}
	if record.SchemaVersion != guardRuntimeRecordSchema {
		return record, fmt.Errorf("unsupported guard runtime record schema %d", record.SchemaVersion)
	}
	return record, nil
}

func normalizeSNIPolicy(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", SNIPolicyIsolate:
		return SNIPolicyIsolate, nil
	case SNIPolicyReject:
		return SNIPolicyReject, nil
	case SNIPolicyDecoy:
		return SNIPolicyDecoy, nil
	}
	return "", fmt.Errorf("unknown SNI policy %q; use isolate, reject or decoy", policy)
}

func sniguardPort(policy string) int {
	switch policy {
	case SNIPolicyReject:
		return GuardRejectPort
	case SNIPolicyDecoy:
		return GuardDecoyPort
	}
	return GuardIsolatePort
}

// guardPortConflict refuses a guard port already used by an inbound, matching
// Bash's sni_guard_port_conflicts.
func guardPortConflict(paths host.Paths, meta store.Metadata, port int) error {
	ports := map[int]bool{}
	if meta.Install != nil {
		ports[meta.Install.Port] = true
	}
	if runtimePath, err := paths.Join(meta.RuntimeConfigPath, false); err == nil {
		if raw, readErr := os.ReadFile(runtimePath); readErr == nil {
			portPattern := regexp.MustCompile(`"port"\s*:\s*(\d+)`)
			for _, m := range portPattern.FindAllSubmatch(raw, -1) {
				if n, convErr := strconv.Atoi(string(m[1])); convErr == nil {
					ports[n] = true
				}
			}
		}
	}
	if ports[port] {
		return fmt.Errorf("port %d is already used by an inbound; choose another SNI policy or move the inbound", port)
	}
	return nil
}

func rewriteDenyPort(body string, port int) (string, bool) {
	loc := guardDenyServer.FindStringSubmatchIndex(body)
	if loc == nil {
		return body, false
	}
	current, err := strconv.Atoi(body[loc[4]:loc[5]])
	if err == nil && current == port {
		return body, false
	}
	replacement := body[loc[2]:loc[3]] + strconv.Itoa(port) + body[loc[6]:loc[7]]
	return body[:loc[0]] + replacement + body[loc[1]:], true
}

// rewriteGuardInclude keeps exactly the http-level include the policy needs.
// A *.conf glob already picks fragments up, so only explicit includes change.
func rewriteGuardInclude(body, policy string) (string, bool, error) {
	wanted := ""
	switch policy {
	case SNIPolicyIsolate:
		wanted = guardIsolateFrag
	case SNIPolicyDecoy:
		wanted = guardDecoyFrag
	}
	hasGlob := regexp.MustCompile(`(?m)^[ \t]*include[ \t]+/etc/idleleo/conf/nginx/\*\.conf;[ \t]*$`).MatchString(body)
	cleaned := guardInclude.ReplaceAllString(body, "")
	if hasGlob {
		return cleaned, cleaned != body, nil
	}
	if wanted == "" {
		return cleaned, cleaned != body, nil
	}
	line := "    include /etc/idleleo/conf/nginx/" + wanted + ";"
	lines := strings.Split(cleaned, "\n")
	httpOpen := regexp.MustCompile(`^\s*http\s*\{`)
	for i, text := range lines {
		if httpOpen.MatchString(text) {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, line)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n"), true, nil
		}
	}
	return cleaned, cleaned != body, errors.New("nginx main config has no http { block; the SNI Guard site cannot be included")
}

func isolateFragment() string {
	return "# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert\n" +
		"server {\n" +
		"    listen 127.0.0.1:9403 ssl;\n" +
		"    ssl_reject_handshake on;\n" +
		"    access_log off;\n" +
		"    error_log /dev/null;\n" +
		"}\n"
}

func decoyFragment(domain, cert, key, webroot string) string {
	return "# decoy 回落站点 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 HTTPS 站点\n" +
		"server {\n" +
		"    listen 127.0.0.1:9444 ssl;\n" +
		"    server_name " + domain + ";\n" +
		"    ssl_certificate " + cert + ";\n" +
		"    ssl_certificate_key " + key + ";\n" +
		"    ssl_protocols TLSv1.2 TLSv1.3;\n" +
		"    ssl_ciphers HIGH:!aNULL:!MD5;\n" +
		"    root " + webroot + ";\n" +
		"    index index.html;\n" +
		"    location / {\n" +
		"        try_files $uri $uri/ =404;\n" +
		"    }\n" +
		"}\n"
}

func validateDecoyDomain(domain string) error {
	if !guardDomain.MatchString(domain) || !strings.Contains(domain, ".") {
		return errors.New("decoy domain must be a DNS name containing a dot")
	}
	return nil
}

// verifyDecoyDomain requires the domain's A/AAAA set to overlap this host's
// addresses, matching the Bash safety check before serving a decoy site.
func verifyDecoyDomain(domain string, extra []string) error {
	resolved, err := guardResolveHost(domain)
	if err != nil || len(resolved) == 0 {
		return fmt.Errorf("cannot resolve decoy domain %s: %v", domain, err)
	}
	local := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				local[ipNet.IP.String()] = true
			}
		}
	}
	for _, raw := range extra {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			local[ip.String()] = true
		}
	}
	for _, raw := range resolved {
		if ip := net.ParseIP(raw); ip != nil && local[ip.String()] {
			return nil
		}
	}
	return fmt.Errorf("decoy domain %s resolves to %s, which does not include this host; point DNS at this server first",
		domain, strings.Join(resolved, ","))
}

func prepareDecoyCert(paths host.Paths, spec SNIGuardSpec, domain string) (certPath, keyPath string, certPEM, keyPEM []byte, generated bool, err error) {
	certPath, err = paths.Join(filepath.Join(guardCertRel, "decoy.crt"), true)
	if err != nil {
		return "", "", nil, nil, false, err
	}
	keyPath, err = paths.Join(filepath.Join(guardCertRel, "decoy.key"), true)
	if err != nil {
		return "", "", nil, nil, false, err
	}
	if spec.DecoyCert == "" && spec.DecoyKey == "" {
		certPEM, keyPEM, err = selfSignedDecoyCert(domain)
		if err != nil {
			return "", "", nil, nil, false, err
		}
		return certPath, keyPath, certPEM, keyPEM, true, nil
	}
	if spec.DecoyCert == "" || spec.DecoyKey == "" {
		return "", "", nil, nil, false, errors.New("--decoy-cert and --decoy-key must be provided together")
	}
	certPEM, err = os.ReadFile(spec.DecoyCert)
	if err != nil {
		return "", "", nil, nil, false, fmt.Errorf("read decoy certificate: %w", err)
	}
	keyPEM, err = os.ReadFile(spec.DecoyKey)
	if err != nil {
		return "", "", nil, nil, false, fmt.Errorf("read decoy key: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return "", "", nil, nil, false, fmt.Errorf("decoy certificate and key do not match: %w", err)
	}
	return certPath, keyPath, certPEM, keyPEM, false, nil
}

func selfSignedDecoyCert(domain string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func decoyToken() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "ok" + strconv.FormatInt(time.Now().Unix()%100000, 10)
	}
	return hex.EncodeToString(buf)[:6]
}

func decoyIndex(domain, token string) string {
	return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
		"<title>" + domain + "</title>\n</head>\n<body>\n<h1>It works</h1>\n" +
		"<p>Service status: OK (" + token + ")</p>\n</body>\n</html>\n"
}

func captureGuardFiles(changes []guardChange) ([]fileState, error) {
	paths := make([]string, 0, len(changes))
	for _, ch := range changes {
		paths = append(paths, ch.path)
	}
	return captureFiles(paths)
}

func applyGuardChanges(changes []guardChange) error {
	for _, ch := range changes {
		if ch.delete {
			if err := os.Remove(ch.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(ch.path), 0o755); err != nil {
			return err
		}
		if err := writeFileAtomic(ch.path, ch.data, guardFileMode(ch.path)); err != nil {
			return err
		}
		if isGuardSensitive(ch.path) {
			applyNginxGroup(ch.path)
		}
	}
	return nil
}

func restoreGuardFiles(backups []fileState) error {
	var errs []string
	for i := len(backups) - 1; i >= 0; i-- {
		if err := backups[i].restore(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", backups[i].path, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func guardFileMode(path string) os.FileMode {
	if isGuardSensitive(path) {
		return 0o600
	}
	return 0o644
}

func isGuardSensitive(path string) bool {
	return strings.HasSuffix(path, ".key") || strings.HasSuffix(path, ".crt")
}

// applyNginxGroup lets the managed worker read the certificate without making
// it world-readable. It is best-effort: a missing group leaves root-only 0600.
func applyNginxGroup(path string) {
	group, err := user.LookupGroup("idleleo-nginx")
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return
	}
	_ = os.Chmod(path, 0o640)
}
