package deploy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

const (
	managedCertRel    = "etc/idleleo/cert"
	certClearStateRel = "var/lib/idleleo/certclear"

	certOwnerProject = "project"
	certOwnerUser    = "third-party"
	certOwnerUnknown = "unknown"

	certActionDelete = "delete"
	certActionKeep   = "keep"
)

// managedPairNames are the default pairs the Bash installer and the Go manager
// create inside the managed directory. A file with one of these names is
// project-owned even without a marker.
var managedPairNames = map[string]bool{
	"xray.crt": true, "xray.key": true,
	"decoy.crt": true, "decoy.key": true,
}

var certDirective = regexp.MustCompile(`(?m)^[ \t]*(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate|ssl_client_certificate)[ \t]+([^;]+);`)
var jsonCertField = regexp.MustCompile(`"(certificateFile|keyFile|certFile|certKeyFile)"\s*:\s*"([^"]+)"`)

// ClearCertsSpec is one "clear every managed certificate" request.
//
// DryRun always wins over any confirmation flag: it performs zero writes, takes
// no lock and lists the exact plan. HomeDir is a test seam; production resolves
// the operator's home directory only on the real root.
type ClearCertsSpec struct {
	Root                 string
	AllowContainerWrites bool
	DryRun               bool
	HomeDir              string
}

// CertPlanEntry is one reviewed path in the dry-run/execution plan.
type CertPlanEntry struct {
	Path         string   `json:"path"`
	Kind         string   `json:"kind"`
	Owner        string   `json:"owner"`
	InUse        bool     `json:"inUse"`
	ReferencedBy []string `json:"referencedBy,omitempty"`
	Action       string   `json:"action"`
	Reason       string   `json:"reason,omitempty"`
}

// ClearCertsReport is the machine-readable result. Planned is populated for
// dry-runs and for real runs (the plan that was executed or refused).
type ClearCertsReport struct {
	Dir       string          `json:"dir"`
	Removed   []string        `json:"removed"`
	Skipped   []string        `json:"skipped,omitempty"`
	Planned   []CertPlanEntry `json:"planned"`
	Missing   bool            `json:"missing"`
	DryRun    bool            `json:"dryRun"`
	Recovered bool            `json:"recovered,omitempty"`
	Warnings  []string        `json:"warnings"`
}

// ClearCertificates deletes only material it can prove is owned by this
// project and is not referenced by an effective Nginx/Xray/schedule config.
// Unclear ownership, third-party certificates, ACME account material and every
// file that a live configuration still references are kept with a warning.
//
// A real change takes the shared update lock before it reads any state, stages
// every removal inside the same filesystem and records a journal first, so an
// interruption restores the original tree instead of leaving a half-deleted
// certificate store.
func ClearCertificates(ctx context.Context, spec ClearCertsSpec) (ClearCertsReport, error) {
	rep := ClearCertsReport{DryRun: spec.DryRun, Removed: []string{}, Warnings: []string{}, Planned: []CertPlanEntry{}}
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return rep, err
	}
	dir, err := paths.Join(managedCertRel, false)
	if err != nil && !os.IsNotExist(err) {
		return rep, err
	}
	rep.Dir = dir

	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return rep, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return rep, err
		}
		defer lock.Release()

		// Converge any interrupted deploy transaction before touching the same
		// tree, then undo a half-finished certificate clear from a previous run.
		if rec, recErr := recoverPendingLocked(ctx, paths); recErr != nil {
			return rep, recErr
		} else if rec.Action != "none" {
			rep.Warnings = append(rep.Warnings, "converged a pending deploy transaction: "+rec.Action)
		}
		recovered, err := recoverCertClearLocked(paths)
		if err != nil {
			return rep, err
		}
		rep.Recovered = recovered
	}

	meta, _ := loadCertMetadata(paths)
	refs := collectCertReferences(paths, meta)

	var moves []certMove
	local, err := planManagedDir(paths, dir, refs, meta, &rep)
	if err != nil {
		return rep, err
	}
	moves = append(moves, local...)

	home := spec.HomeDir
	if home == "" && paths.Root == "/" {
		home, _ = os.UserHomeDir()
	}
	if home != "" {
		acmeMoves, err := planACMEState(home, &rep)
		if err != nil {
			return rep, err
		}
		moves = append(moves, acmeMoves...)
	}

	if len(rep.Planned) == 0 {
		return rep, nil
	}
	if spec.DryRun {
		return rep, nil
	}
	if len(moves) == 0 {
		return rep, nil
	}
	removed, warnings, err := executeCertClear(paths, moves)
	rep.Warnings = append(rep.Warnings, warnings...)
	rep.Removed = append(rep.Removed, removed...)
	if err != nil {
		return rep, err
	}
	return rep, nil
}

type certMove struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type certClearJournal struct {
	SchemaVersion int        `json:"schemaVersion"`
	State         string     `json:"state"`
	ID            string     `json:"id"`
	Root          string     `json:"root"`
	CreatedAt     string     `json:"createdAt"`
	UpdatedAt     string     `json:"updatedAt"`
	Moves         []certMove `json:"moves"`
	LastError     string     `json:"lastError,omitempty"`
}

const (
	certJournalPrepared         = "PREPARED"
	certJournalCommitted        = "COMMITTED"
	certJournalRolledBack       = "ROLLED_BACK"
	certJournalRecoveryRequired = "RECOVERY_REQUIRED"
	certJournalSchema           = 1
)

func certStateDir(paths host.Paths) string {
	return filepath.Join(paths.Root, filepath.FromSlash(certClearStateRel))
}

func certJournalPath(paths host.Paths) string {
	return filepath.Join(certStateDir(paths), "journal.json")
}

func loadCertMetadata(paths host.Paths) (store.Metadata, bool) {
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return store.Metadata{}, false
	}
	return meta, true
}

func planManagedDir(paths host.Paths, dir string, refs map[string][]string, meta store.Metadata, rep *ClearCertsReport) ([]certMove, error) {
	if dir == "" {
		rep.Missing = true
		return nil, nil
	}
	if info, statErr := os.Lstat(dir); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to clear %s: the managed certificate directory is a symlink", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			rep.Missing = true
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read the managed certificate directory %s: %w", dir, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	userManaged := fileExists(filepath.Join(dir, ".user-managed"))
	managerOwned := fileExists(filepath.Join(dir, ".managed-by-idleleo"))
	scheduleCerts := configuredScheduleCerts(paths)
	ownedResources := map[string]bool{}
	for _, rel := range meta.OwnedResources {
		if p, err := paths.Join(rel, false); err == nil {
			ownedResources[filepath.Clean(p)] = true
		}
	}

	var moves []certMove
	for _, entry := range entries {
		target := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(target)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			keepEntry(rep, target, "symlink", certOwnerUnknown, false, nil, "symlink left untouched")
			continue
		}
		if info.IsDir() {
			if userManaged {
				keepEntry(rep, target, "directory", certOwnerUser, false, nil, "the .user-managed marker forbids automatic removal")
				continue
			}
			files, used, unknown, hasLink := scanCertDir(target, refs, managerOwned, scheduleCerts, ownedResources)
			inUse := len(used) > 0 || refsContainDir(refs, target)
			if hasLink || unknown {
				reason := "directory holds a symlink or a file whose ownership is not proven; refusing to remove it"
				keepEntry(rep, target, "directory", certOwnerUnknown, inUse, used, reason)
				continue
			}
			if inUse {
				keepEntry(rep, target, "directory", certOwnerProject, true, used, "referenced by an effective configuration")
				continue
			}
			if managerOwned || files > 0 {
				addPlan(rep, target, "directory", certOwnerProject, false, nil, certActionDelete, "")
				moves = append(moves, certMove{From: target, Kind: "dir"})
				continue
			}
			keepEntry(rep, target, "directory", certOwnerUnknown, false, nil, "ownership is not proven")
			continue
		}
		if !info.Mode().IsRegular() {
			keepEntry(rep, target, "special", certOwnerUnknown, false, nil, "special file left untouched")
			continue
		}
		used := refs[filepath.Clean(target)]
		inUse := len(used) > 0
		owner := classifyManagedFile(target, userManaged, managerOwned, scheduleCerts, ownedResources)
		switch {
		case inUse:
			keepEntry(rep, target, "file", certOwnerProject, true, used, "referenced by an effective configuration")
		case userManaged:
			keepEntry(rep, target, "file", certOwnerUser, false, nil, "the .user-managed marker forbids automatic removal")
		case owner != certOwnerProject:
			keepEntry(rep, target, "file", owner, false, nil, "ownership is not proven; not removed")
		default:
			addPlan(rep, target, "file", owner, false, nil, certActionDelete, "")
			moves = append(moves, certMove{From: target, Kind: "file"})
		}
	}
	return moves, nil
}

// scanCertDir reports whether a directory contains project-owned files, an
// unknown file, or a symlink. It never follows links.
func scanCertDir(dir string, refs map[string][]string, managerOwned bool, scheduleCerts, ownedResources map[string]bool) (files int, used []string, unknown, hasLink bool) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if path == dir {
				unknown = true
			}
			return nil
		}
		if path == dir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			hasLink = true
			return nil
		}
		if d.IsDir() {
			return nil
		}
		files++
		if refs[filepath.Clean(path)] != nil {
			used = append(used, filepath.Clean(path))
		}
		if !d.Type().IsRegular() {
			unknown = true
			return nil
		}
		if classifyManagedFile(path, false, managerOwned, scheduleCerts, ownedResources) != certOwnerProject {
			unknown = true
		}
		return nil
	})
	return files, used, unknown, hasLink
}

func refsContainDir(refs map[string][]string, dir string) bool {
	prefix := dir + string(os.PathSeparator)
	for p := range refs {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func classifyManagedFile(path string, userManaged, managerOwned bool, scheduleCerts, ownedResources map[string]bool) string {
	if userManaged {
		return certOwnerUser
	}
	if managerOwned {
		return certOwnerProject
	}
	if managedPairNames[filepath.Base(path)] {
		return certOwnerProject
	}
	if scheduleCerts[filepath.Clean(path)] {
		return certOwnerProject
	}
	if ownedResources[filepath.Clean(path)] {
		return certOwnerProject
	}
	if strings.HasPrefix(filepath.Base(path), ".") {
		// Project markers and sidecar files live in the managed directory.
		return certOwnerProject
	}
	return certOwnerUnknown
}

func configuredScheduleCerts(paths host.Paths) map[string]bool {
	out := map[string]bool{}
	cfgPath, err := paths.Join(schedule.ConfigRel, false)
	if err != nil {
		return out
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return out
	}
	var cfg struct {
		CertFile    string `json:"certFile"`
		CertKeyFile string `json:"certKeyFile"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return out
	}
	for _, rel := range []string{cfg.CertFile, cfg.CertKeyFile} {
		if rel == "" {
			continue
		}
		if p, err := paths.Join(rel, false); err == nil {
			out[filepath.Clean(p)] = true
		}
	}
	return out
}

// collectCertReferences gathers every absolute certificate path referenced by
// an effective managed configuration. Relative paths are resolved against the
// root; an unresolvable directive is ignored here and surfaced as a warning by
// the caller only when it could change a decision.
func collectCertReferences(paths host.Paths, meta store.Metadata) map[string][]string {
	refs := map[string][]string{}
	add := func(raw, source string) {
		raw = strings.TrimSpace(strings.Trim(raw, `"'`))
		if raw == "" {
			return
		}
		p := raw
		if filepath.IsAbs(p) {
			// Managed configs name /etc/idleleo/... ; a sandbox root relocates
			// that absolute tree under the disposable directory.
			if paths.Root != "/" {
				p = filepath.Join(paths.Root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
			}
		} else {
			p = filepath.Join(paths.Root, filepath.FromSlash(p))
		}
		refs[filepath.Clean(p)] = append(refs[filepath.Clean(p)], source)
	}

	// Managed Nginx fragments and the managed main configuration.
	for _, rel := range []string{nginx.ConfDirRel, filepath.Join(nginx.InstallDirRel, "conf")} {
		dir, err := paths.Join(rel, false)
		if err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".conf") {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			for _, m := range certDirective.FindAllStringSubmatch(string(raw), -1) {
				add(m[2], path)
			}
			return nil
		})
	}

	// Xray runtime config (TLS certificates; Reality has no certificate files).
	runtimeRel := meta.RuntimeConfigPath
	if err := store.ValidateManagerPath(runtimeRel); err != nil {
		runtimeRel = paths.RuntimeConfig()
	}
	if runtimePath, err := paths.Join(runtimeRel, false); err == nil {
		if raw, readErr := os.ReadFile(runtimePath); readErr == nil {
			for _, m := range jsonCertField.FindAllStringSubmatch(string(raw), -1) {
				add(m[2], runtimePath)
			}
		}
	}

	// Go scheduled renewal targets.
	if cfgPath, err := paths.Join(schedule.ConfigRel, false); err == nil {
		if raw, readErr := os.ReadFile(cfgPath); readErr == nil {
			for _, m := range jsonCertField.FindAllStringSubmatch(string(raw), -1) {
				add(m[2], cfgPath)
			}
		}
	}
	return refs
}

// planACMEState removes only acme.sh domain directories whose certificate is
// already proven project-owned. Account keys, CA state and unknown domains are
// always preserved.
func planACMEState(home string, rep *ClearCertsReport) ([]certMove, error) {
	root := filepath.Join(home, ".acme.sh")
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			rep.Warnings = append(rep.Warnings, "acme.sh state not scanned: "+err.Error())
		}
		return nil, nil
	}
	domains := projectCertDomains(rep.Dir)
	if len(domains) == 0 {
		rep.Warnings = append(rep.Warnings, "no project certificate domain could be identified; acme.sh state left untouched")
		return nil, nil
	}
	var moves []certMove
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasSuffix(entry.Name(), "_ecc") {
			continue
		}
		target := filepath.Join(root, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			keepEntry(rep, target, "acme-directory", certOwnerUnknown, false, nil, "symlink left untouched")
			continue
		}
		domain := strings.TrimSuffix(entry.Name(), "_ecc")
		if !domains[domain] {
			keepEntry(rep, target, "acme-directory", certOwnerUser, false, nil,
				"ACME domain is not one of this project's certificates; preserving it")
			continue
		}
		addPlan(rep, target, "acme-directory", certOwnerProject, false, nil, certActionDelete, "")
		moves = append(moves, certMove{From: target, Kind: "acme"})
	}
	return moves, nil
}

// projectCertDomains extracts the DNS names of project-owned certificates in
// the managed directory. It is the ownership proof used for acme.sh state.
func projectCertDomains(dir string) map[string]bool {
	out := map[string]bool{}
	if dir == "" {
		return out
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		for _, name := range cert.DNSNames {
			out[strings.ToLower(name)] = true
		}
		if cert.Subject.CommonName != "" {
			out[strings.ToLower(cert.Subject.CommonName)] = true
		}
	}
	return out
}

func addPlan(rep *ClearCertsReport, path, kind, owner string, inUse bool, used []string, action, reason string) {
	rep.Planned = append(rep.Planned, CertPlanEntry{
		Path: path, Kind: kind, Owner: owner, InUse: inUse,
		ReferencedBy: used, Action: action, Reason: reason,
	})
}

func keepEntry(rep *ClearCertsReport, path, kind, owner string, inUse bool, used []string, reason string) {
	addPlan(rep, path, kind, owner, inUse, used, certActionKeep, reason)
	rep.Skipped = append(rep.Skipped, path)
	rep.Warnings = append(rep.Warnings, reason+": "+path)
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// renameCertFile is a fault-injection seam. Production always renames inside
// the same filesystem, so a rollback is an atomic metadata operation.
var renameCertFile = os.Rename

func executeCertClear(paths host.Paths, moves []certMove) ([]string, []string, error) {
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	stage := filepath.Join(certStateDir(paths), "staging", id)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return nil, nil, err
	}
	home, _ := os.UserHomeDir()
	for i := range moves {
		name := fmt.Sprintf("%03d", i)
		if moves[i].Kind == "acme" {
			// Keep the staged directory on the same filesystem as ~/.acme.sh.
			moves[i].To = filepath.Join(filepath.Dir(moves[i].From), ".idleleo-clear-"+id+"-"+filepath.Base(moves[i].From))
			continue
		}
		moves[i].To = filepath.Join(stage, name+"-"+filepath.Base(moves[i].From))
	}

	j := certClearJournal{
		SchemaVersion: certJournalSchema, State: certJournalPrepared, ID: id,
		Root: paths.Root, CreatedAt: time.Now().UTC().Format(time.RFC3339), Moves: moves,
	}
	if err := writeCertJournal(paths, &j); err != nil {
		_ = os.RemoveAll(stage)
		return nil, nil, err
	}

	var removed, warnings []string
	for _, mv := range moves {
		if err := renameCertFile(mv.From, mv.To); err != nil {
			rbErr := rollbackCertMoves(moves)
			j.LastError = err.Error()
			if rbErr != nil {
				j.State = certJournalRecoveryRequired
				j.LastError += "; rollback failed: " + rbErr.Error()
				_ = writeCertJournal(paths, &j)
				return nil, warnings, fmt.Errorf("%w (rollback failed: %v; run `idleleo xray cert clear` again to recover)", err, rbErr)
			}
			j.State = certJournalRolledBack
			_ = writeCertJournal(paths, &j)
			cleanupCertJournal(paths, stage, home)
			return nil, warnings, fmt.Errorf("%w; the previous certificate tree was restored", err)
		}
		removed = append(removed, mv.From)
	}

	j.State = certJournalCommitted
	if err := writeCertJournal(paths, &j); err != nil {
		// The moves already happened; the journal stays PREPARED, so the next run
		// restores them. Report the actual state instead of claiming success.
		return removed, warnings, fmt.Errorf("certificate removal completed but the journal could not be committed: %w", err)
	}
	if err := cleanupCertJournal(paths, stage, home); err != nil {
		warnings = append(warnings, "staging cleanup failed: "+err.Error())
	}
	return removed, warnings, nil
}

func rollbackCertMoves(moves []certMove) error {
	var errs []string
	for i := len(moves) - 1; i >= 0; i-- {
		mv := moves[i]
		if _, err := os.Lstat(mv.To); err != nil {
			continue
		}
		if err := renameCertFile(mv.To, mv.From); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", mv.From, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func cleanupCertJournal(paths host.Paths, stage, home string) error {
	var errs []string
	if err := os.RemoveAll(stage); err != nil {
		errs = append(errs, err.Error())
	}
	if home != "" {
		root := filepath.Join(home, ".acme.sh")
		if entries, err := os.ReadDir(root); err == nil {
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".idleleo-clear-") {
					if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
						errs = append(errs, err.Error())
					}
				}
			}
		}
	}
	_ = os.Remove(certJournalPath(paths))
	_ = os.Remove(filepath.Dir(stage))
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func writeCertJournal(paths host.Paths, j *certClearJournal) error {
	j.SchemaVersion = certJournalSchema
	j.Root = paths.Root
	j.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(certStateDir(paths), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(certJournalPath(paths), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	syncDir(certStateDir(paths))
	return nil
}

// recoverCertClearLocked restores an interrupted certificate deletion. The
// caller holds the shared update lock. Safety comes first: a PREPARED journal is
// always rolled back, never continued.
func recoverCertClearLocked(paths host.Paths) (bool, error) {
	raw, err := os.ReadFile(certJournalPath(paths))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var j certClearJournal
	if err := json.Unmarshal(raw, &j); err != nil {
		return false, fmt.Errorf("corrupt certificate-clear journal: %w", err)
	}
	if j.SchemaVersion != certJournalSchema || j.Root != paths.Root {
		return false, fmt.Errorf("certificate-clear journal does not belong to this root")
	}
	home, _ := os.UserHomeDir()
	switch j.State {
	case certJournalCommitted, certJournalRolledBack:
		_ = cleanupCertJournal(paths, filepath.Join(certStateDir(paths), "staging", j.ID), home)
		return true, nil
	case certJournalPrepared, certJournalRecoveryRequired:
		if err := validateCertMoves(paths, home, j.Moves); err != nil {
			return false, err
		}
		if err := rollbackCertMoves(j.Moves); err != nil {
			j.State = certJournalRecoveryRequired
			j.LastError = err.Error()
			_ = writeCertJournal(paths, &j)
			return false, fmt.Errorf("certificate-clear recovery failed, journal kept as %s: %w", certJournalRecoveryRequired, err)
		}
		j.State = certJournalRolledBack
		_ = writeCertJournal(paths, &j)
		_ = cleanupCertJournal(paths, filepath.Join(certStateDir(paths), "staging", j.ID), home)
		return true, nil
	default:
		return false, fmt.Errorf("unknown certificate-clear journal state %q", j.State)
	}
}

func validateCertMoves(paths host.Paths, home string, moves []certMove) error {
	managedDir := filepath.Join(paths.Root, filepath.FromSlash(managedCertRel))
	acmeRoot := ""
	if home != "" {
		acmeRoot = filepath.Join(home, ".acme.sh")
	}
	for _, mv := range moves {
		if !within(mv.From, managedDir) && !(acmeRoot != "" && within(mv.From, acmeRoot) && strings.HasSuffix(mv.From, "_ecc")) {
			return fmt.Errorf("journal path escapes the certificate tree: %s", mv.From)
		}
		if !within(mv.To, filepath.Join(certStateDir(paths), "staging")) &&
			!(acmeRoot != "" && within(mv.To, acmeRoot) && strings.HasPrefix(filepath.Base(mv.To), ".idleleo-clear-")) {
			return fmt.Errorf("journal staging path escapes the allowed tree: %s", mv.To)
		}
	}
	return nil
}

func within(path, base string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}
