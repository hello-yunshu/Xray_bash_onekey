package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
	"unicode"

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

	// certMarkerName is the manager's ownership record. The record is only
	// trusted together with the content hashes it lists: a marker file, a
	// certificate file name or the managed path alone proves nothing.
	certMarkerName  = ".managed-by-idleleo"
	certUserMarker  = ".user-managed"
	maxScanDepth    = 16
	maxDirWalkDepth = 8
)

// certDirective captures the whole argument up to the terminating semicolon,
// including ${...} expansions and directives that span physical lines. The
// body is validated separately: anything the parser cannot prove is a literal,
// non-variable path fails closed.
var certDirective = regexp.MustCompile(`(ssl_certificate_key|ssl_certificate|ssl_trusted_certificate|ssl_client_certificate)[ \t\r\n]+([^;]*);`)
var jsonCertField = regexp.MustCompile(`"(certificateFile|keyFile|certFile|certKeyFile)"\s*:\s*"([^"]+)"`)
var nginxIncludeDirective = regexp.MustCompile(`\binclude[ \t\r\n]+([^;]*);`)
var managedHashLine = regexp.MustCompile(`(?m)^sha256=([0-9a-f]{64})$`)

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
	scan := collectCertReferences(paths, meta)
	rep.Warnings = append(rep.Warnings, scan.warnings...)

	var moves []certMove
	local, err := planManagedDir(dir, scan, &rep)
	if err != nil {
		return rep, err
	}
	moves = append(moves, local...)

	home := spec.HomeDir
	if home == "" && paths.Root == "/" {
		home, _ = os.UserHomeDir()
	}
	if home != "" {
		acmeMoves, err := planACMEState(home, scan, &rep)
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
	// Validate the live configuration before deleting anything. A tree that is
	// already broken must not lose certificates on top of the breakage.
	if managedNginxInstalled(paths) {
		if testErr := balanceNginxTest(ctx, paths.Root); testErr != nil {
			return rep, fmt.Errorf("refusing to clear certificates: the managed Nginx configuration is invalid before the change: %w", testErr)
		}
	}
	removed, warnings, err := executeCertClear(ctx, paths, moves)
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

func planManagedDir(dir string, scan certReferenceScan, rep *ClearCertsReport) ([]certMove, error) {
	refs := scan.refs
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

	userManaged := fileExists(filepath.Join(dir, certUserMarker))
	proofCache := map[string]map[string]bool{}
	proofFor := func(d string) map[string]bool {
		if proof, ok := proofCache[d]; ok {
			return proof
		}
		proof := readCertOwnershipProof(d, rep)
		proofCache[d] = proof
		return proof
	}

	var moves []certMove
	for _, entry := range entries {
		name := entry.Name()
		if name == certMarkerName || name == certUserMarker {
			// Ownership records are never deletion candidates; a fully owned
			// directory takes them along as one transaction unit.
			continue
		}
		target := filepath.Join(dir, name)
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
			files, used, badReason := examineCertDir(target, refs, proofFor, 0)
			inUse := len(used) > 0 || refsContainDir(refs, target)
			switch {
			case inUse:
				keepEntry(rep, target, "directory", certOwnerProject, true, used, "referenced by an effective configuration")
			case badReason != "":
				keepEntry(rep, target, "directory", certOwnerUnknown, false, used, badReason)
			case scan.failClosed:
				keepEntry(rep, target, "directory", certOwnerProject, false, used,
					"the effective configuration could not be fully scanned; refusing to remove a project directory")
			case files == 0:
				keepEntry(rep, target, "directory", certOwnerUnknown, false, nil, "empty directory has no ownership record")
			default:
				addPlan(rep, target, "directory", certOwnerProject, false, nil, certActionDelete, "every file is bound to this project by its ownership record and no configuration references it")
				moves = append(moves, certMove{From: target, Kind: "dir"})
			}
			continue
		}
		if !info.Mode().IsRegular() {
			keepEntry(rep, target, "special", certOwnerUnknown, false, nil, "special file left untouched")
			continue
		}
		used := refs[filepath.Clean(target)]
		inUse := len(used) > 0
		owned := proofFor(dir)[filepath.Clean(target)]
		owner := certOwnerUnknown
		if owned {
			owner = certOwnerProject
		}
		switch {
		case inUse:
			keepEntry(rep, target, "file", certOwnerProject, true, used, "referenced by an effective configuration")
		case userManaged:
			keepEntry(rep, target, "file", certOwnerUser, false, nil, "the .user-managed marker forbids automatic removal")
		case !owned:
			keepEntry(rep, target, "file", owner, false, nil, "ownership is not proven by the manager's ownership record; not removed")
		case scan.failClosed:
			keepEntry(rep, target, "file", owner, false, nil,
				"the effective configuration could not be fully scanned; cannot prove this certificate is unused")
		default:
			addPlan(rep, target, "file", owner, false, nil, certActionDelete, "")
			moves = append(moves, certMove{From: target, Kind: "file"})
		}
	}
	return moves, nil
}

// readCertOwnershipProof returns the files in dir whose current content hash is
// listed in the manager's ownership record. A marker alone (including a legacy
// marker without hashes) proves nothing, and neither does a file name or the
// directory it happens to live in.
func readCertOwnershipProof(dir string, rep *ClearCertsReport) map[string]bool {
	owned := map[string]bool{}
	marker := filepath.Join(dir, certMarkerName)
	raw, err := os.ReadFile(marker)
	if err != nil {
		if !os.IsNotExist(err) {
			rep.Warnings = append(rep.Warnings, "cannot read the ownership record "+marker+": "+err.Error())
		}
		return owned
	}
	hashes := map[string]bool{}
	for _, m := range managedHashLine.FindAllStringSubmatch(string(raw), -1) {
		hashes[m[1]] = true
	}
	if len(hashes) == 0 {
		rep.Warnings = append(rep.Warnings,
			"the ownership record "+marker+" has no content hashes; files in that directory are preserved")
		return owned
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "cannot read "+dir+" while checking ownership: "+err.Error())
		return owned
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == certMarkerName || name == certUserMarker || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, name)
		sum, err := certFileSHA256(path)
		if err != nil {
			rep.Warnings = append(rep.Warnings, "cannot hash "+path+" while checking ownership: "+err.Error())
			continue
		}
		if hashes[sum] {
			owned[filepath.Clean(path)] = true
		}
	}
	return owned
}

// examineCertDir proves that every regular file in a directory tree is bound to
// this project by its own content hash and that none of them is referenced by
// an effective configuration. Any doubt keeps the directory.
func examineCertDir(dir string, refs map[string][]string, proofFor func(string) map[string]bool, depth int) (files int, used []string, reason string) {
	if depth > maxDirWalkDepth {
		return files, used, "the certificate directory tree is deeper than the supported limit; refusing to remove it"
	}
	proof := proofFor(dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return files, used, "cannot read " + dir + " while proving ownership: " + err.Error()
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == certMarkerName || name == certUserMarker {
			continue
		}
		path := filepath.Join(dir, name)
		if entry.Type()&os.ModeSymlink != 0 {
			return files, used, "the certificate directory holds a symlink; refusing to remove it"
		}
		if entry.IsDir() {
			childFiles, childUsed, childReason := examineCertDir(path, refs, proofFor, depth+1)
			files += childFiles
			used = append(used, childUsed...)
			if childReason != "" {
				return files, used, childReason
			}
			continue
		}
		if !entry.Type().IsRegular() {
			return files, used, "the certificate directory holds a special file; refusing to remove it"
		}
		files++
		if refs[filepath.Clean(path)] != nil {
			used = append(used, filepath.Clean(path))
		}
		if !proof[filepath.Clean(path)] {
			return files, used, "ownership of " + path + " is not proven by the manager's ownership record; refusing to remove the directory"
		}
	}
	return files, used, ""
}

func certFileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
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

// certReferenceScan is the result of following the effective configuration.
// failClosed means at least one reference could not be proven: a variable path,
// an unreadable file or a missing include. In that state every project-owned
// certificate is kept, because deleting an unproven file could break a live
// server on the next reload.
type certReferenceScan struct {
	refs       map[string][]string
	warnings   []string
	incompleteSeen map[string]bool
	failClosed bool
}

// collectCertReferences gathers every certificate path referenced by the
// effective managed configuration: the managed Nginx main config and its real
// include chain (including paths outside the managed directory), every managed
// fragment, every Xray configuration under the managed tree and the renewal
// schedule. Symlink aliases are resolved so a reference through a link still
// protects the real managed file.
func collectCertReferences(paths host.Paths, meta store.Metadata) certReferenceScan {
	scan := certReferenceScan{refs: map[string][]string{}}
	prefix := nginxPrefixDir(paths)
	visited := map[string]bool{}

	var scanFile func(path string, depth int)
	scanFile = func(path string, depth int) {
		clean := filepath.Clean(path)
		if visited[clean] {
			return
		}
		if depth > maxScanDepth {
			scan.incomplete("the include chain at " + clean + " exceeds the supported nesting depth")
			return
		}
		visited[clean] = true
		raw, err := os.ReadFile(clean)
		if err != nil {
			scan.incomplete("cannot read configuration " + clean)
			return
		}
		text := stripNginxComments(string(raw))

		for _, m := range nginxIncludeDirective.FindAllStringSubmatch(text, -1) {
			target := strings.TrimSpace(strings.Trim(m[1], `"'`))
			if target == "" {
				continue
			}
			if strings.ContainsAny(target, "$}{") {
				scan.incomplete("the include path in " + clean + " uses a variable or brace expression")
				continue
			}
			resolved := resolveNginxPath(paths, prefix, target)
			if resolved == "" {
				scan.incomplete("the include path in " + clean + " cannot be resolved")
				continue
			}
			globbed := strings.ContainsAny(target, "*?[")
			matches := []string{resolved}
			if globbed {
				found, globErr := filepath.Glob(resolved)
				if globErr != nil {
					scan.incomplete("the include glob in " + clean + " is invalid")
					continue
				}
				if len(found) == 0 {
					scan.incomplete("the include glob in " + clean + " matches no configuration")
					continue
				}
				matches = found
			}
			for _, included := range matches {
				fi, statErr := os.Stat(included)
				if statErr != nil || fi.IsDir() {
					if !globbed {
						scan.incomplete("the included configuration " + included + " cannot be read")
					}
					continue
				}
				scanFile(included, depth+1)
			}
		}
		for _, m := range certDirective.FindAllStringSubmatch(text, -1) {
			scan.add(paths, prefix, m[2], clean)
		}
	}

	// The managed main config is the entry point of the effective chain.
	if mainConf, err := paths.Join(filepath.Join(nginx.InstallDirRel, "conf", "nginx.conf"), false); err == nil {
		if _, statErr := os.Stat(mainConf); statErr == nil {
			scanFile(mainConf, 0)
		} else if managedNginxInstalled(paths) {
			scan.incomplete("the managed main configuration " + mainConf + " is missing")
		}
	}
	for _, rel := range []string{nginx.ConfDirRel, filepath.Join(nginx.InstallDirRel, "conf")} {
		dir, err := paths.Join(rel, false)
		if err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				scan.incomplete("cannot read configuration " + path)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			scanFile(path, 1)
			return nil
		})
	}

	// Xray runtime config plus any additional managed Xray configuration; a
	// second config can reference the same certificate files.
	runtimeRel := meta.RuntimeConfigPath
	if err := store.ValidateManagerPath(runtimeRel); err != nil {
		runtimeRel = paths.RuntimeConfig()
	}
	xrayPaths := map[string]bool{}
	if runtimePath, err := paths.Join(runtimeRel, false); err == nil {
		xrayPaths[filepath.Clean(runtimePath)] = true
	}
	if xrayDir, err := paths.Join("etc/idleleo/conf/xray", false); err == nil {
		_ = filepath.WalkDir(xrayDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				scan.incomplete("cannot read Xray configuration " + path)
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if strings.HasSuffix(path, ".json") {
				xrayPaths[filepath.Clean(path)] = true
			}
			return nil
		})
	}
	for xrayPath := range xrayPaths {
		raw, readErr := os.ReadFile(xrayPath)
		if readErr != nil {
			if !os.IsNotExist(readErr) {
				scan.incomplete("cannot read Xray configuration " + xrayPath)
			}
			continue
		}
		for _, m := range jsonCertField.FindAllStringSubmatch(string(raw), -1) {
			scan.add(paths, prefix, m[2], xrayPath)
		}
	}

	// Go scheduled renewal targets.
	if cfgPath, err := paths.Join(schedule.ConfigRel, false); err == nil {
		if raw, readErr := os.ReadFile(cfgPath); readErr == nil {
			for _, m := range jsonCertField.FindAllStringSubmatch(string(raw), -1) {
				scan.add(paths, prefix, m[2], cfgPath)
			}
		} else if !os.IsNotExist(readErr) {
			scan.incomplete("cannot read the renewal schedule " + cfgPath)
		}
	}
	return scan
}

func (s *certReferenceScan) incomplete(reason string) {
	s.failClosed = true
	if s.incompleteSeen == nil {
		s.incompleteSeen = map[string]bool{}
	}
	if s.incompleteSeen[reason] {
		return
	}
	s.incompleteSeen[reason] = true
	s.warnings = append(s.warnings, reason+"; certificates whose use cannot be proven will be kept")
}

func (s *certReferenceScan) add(paths host.Paths, prefix, raw, source string) {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return
	}
	if strings.ContainsAny(raw, "$}{") {
		s.incomplete("a certificate directive in " + source + " uses a variable or brace expression")
		return
	}
	if strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		s.incomplete("a certificate directive in " + source + " contains embedded whitespace and cannot be parsed safely")
		return
	}
	p := resolveNginxPath(paths, prefix, raw)
	if p == "" {
		s.incomplete("a certificate directive in " + source + " cannot be resolved")
		return
	}
	s.record(p, source)
	if real, err := filepath.EvalSymlinks(p); err == nil && filepath.Clean(real) != p {
		s.record(filepath.Clean(real), source)
	}
}

func (s *certReferenceScan) record(path, source string) {
	for _, existing := range s.refs[path] {
		if existing == source {
			return
		}
	}
	s.refs[path] = append(s.refs[path], source)
}

// nginxPrefixDir is the prefix Nginx resolves relative include and certificate
// paths against. The managed install wins; a sandbox without one falls back to
// its root, which keeps relative fixtures working.
func nginxPrefixDir(paths host.Paths) string {
	install := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel))
	if fi, err := os.Stat(filepath.Join(install, "conf")); err == nil && fi.IsDir() {
		return install
	}
	return paths.Root
}

func resolveNginxPath(paths host.Paths, prefix, raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"'`))
	if raw == "" {
		return ""
	}
	p := raw
	if filepath.IsAbs(p) {
		// Managed configs name /etc/idleleo/... ; a sandbox root relocates that
		// absolute tree under the disposable directory.
		if paths.Root != "/" {
			p = filepath.Join(paths.Root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
		}
	} else {
		p = filepath.Join(prefix, filepath.FromSlash(p))
	}
	return filepath.Clean(p)
}

// stripNginxComments removes unquoted '#' comments so a commented-out directive
// can never protect or delete a certificate.
func stripNginxComments(text string) string {
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			b.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			b.WriteByte(c)
		case c == '#' && !inSingle && !inDouble:
			for i < len(text) && text[i] != '\n' {
				i++
			}
			if i < len(text) {
				b.WriteByte('\n')
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// managedNginxInstalled reports whether a real managed Nginx binary exists to
// validate the tree against. A missing install means no Nginx can be broken by
// the removal, so the check is skipped.
func managedNginxInstalled(paths host.Paths) bool {
	bin := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel), "sbin", "nginx")
	fi, err := os.Stat(bin)
	return err == nil && fi.Mode().IsRegular()
}

// planACMEState removes only acme.sh domain directories that can be matched,
// by certificate identity, to a certificate this manager has proven it owns and
// has already planned to remove. Account keys, CA state, user-managed pairs and
// domains whose acme.sh certificate does not match are always preserved.
func planACMEState(home string, scan certReferenceScan, rep *ClearCertsReport) ([]certMove, error) {
	preserveAll := ""
	if scan.failClosed {
		preserveAll = "the effective configuration could not be fully scanned"
	} else if rep.Dir != "" && fileExists(filepath.Join(rep.Dir, certUserMarker)) {
		preserveAll = "the certificate directory is marked .user-managed"
	}
	deletable := map[string]bool{}
	for _, entry := range rep.Planned {
		if entry.Action != certActionDelete || entry.Kind != "file" {
			continue
		}
		if !strings.HasSuffix(entry.Path, ".crt") && !strings.HasSuffix(entry.Path, ".pem") {
			continue
		}
		fp, err := certFingerprint(entry.Path)
		if err != nil {
			continue
		}
		deletable[fp] = true
	}
	root := filepath.Join(home, ".acme.sh")
	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			rep.Warnings = append(rep.Warnings, "acme.sh state not scanned: "+err.Error())
		}
		return nil, nil
	}
	if preserveAll != "" {
		rep.Warnings = append(rep.Warnings, "acme.sh state is preserved because "+preserveAll)
		for _, entry := range entries {
			if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && strings.HasSuffix(entry.Name(), "_ecc") {
				keepEntry(rep, filepath.Join(root, entry.Name()), "acme-directory", certOwnerUnknown, false, nil,
					"preserved because "+preserveAll)
			}
		}
		return nil, nil
	}
	if len(deletable) == 0 {
		rep.Warnings = append(rep.Warnings,
			"no removable project certificate identity is available; acme.sh state left untouched")
		for _, entry := range entries {
			if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && strings.HasSuffix(entry.Name(), "_ecc") {
				keepEntry(rep, filepath.Join(root, entry.Name()), "acme-directory", certOwnerUser, false, nil,
					"no project ownership record binds this ACME state to a certificate being removed; preserving it")
			}
		}
		return nil, nil
	}
	var moves []certMove
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), "_ecc") {
			continue
		}
		target := filepath.Join(root, entry.Name())
		domain := strings.TrimSuffix(entry.Name(), "_ecc")
		cerPath := filepath.Join(target, domain+".cer")
		fp, err := certFingerprint(cerPath)
		if err != nil || !deletable[fp] {
			keepEntry(rep, target, "acme-directory", certOwnerUser, false, nil,
				"no project ownership record binds this ACME state to a certificate being removed; preserving it")
			continue
		}
		addPlan(rep, target, "acme-directory", certOwnerProject, false, nil, certActionDelete,
			"ACME state holds the identical certificate that this project issued and is removing")
		moves = append(moves, certMove{From: target, Kind: "acme"})
	}
	return moves, nil
}

// certFingerprint returns the SHA-256 digest of the DER certificate. It accepts
// PEM (including chains) and raw DER, so it can compare the managed certificate
// with acme.sh's own copy.
func certFingerprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
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

func executeCertClear(ctx context.Context, paths host.Paths, moves []certMove) ([]string, []string, error) {
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

	// Prove the moved tree still runs before committing the transaction. The
	// staged files are reversible, so a failed check restores everything.
	if err := verifyCertClearTree(ctx, paths); err != nil {
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

// verifyCertClearTree proves the staged removals did not break the services that
// own the certificates. It only runs real binaries that are installed; a node
// without them has nothing that could load the files.
func verifyCertClearTree(ctx context.Context, paths host.Paths) error {
	if managedNginxInstalled(paths) {
		if err := balanceNginxTest(ctx, paths.Root); err != nil {
			return fmt.Errorf("nginx -t rejected the configuration after the certificate change: %w", err)
		}
	}
	xrayBin := filepath.Join(paths.Root, "usr/local/bin/xray")
	if fi, err := os.Stat(xrayBin); err == nil && fi.Mode().IsRegular() {
		if conf, err := paths.Join(paths.RuntimeConfig(), false); err == nil {
			if _, statErr := os.Stat(conf); statErr == nil {
				res, runErr := host.Run(ctx, host.ExecSpec{
					Path: xrayBin, Args: []string{"-test", "-config", conf},
					Env: geodataEnv(paths.Root), Timeout: 60 * time.Second,
				})
				if runErr != nil {
					return runErr
				}
				if res.ExitCode != 0 {
					return fmt.Errorf("xray -test rejected the runtime configuration after the certificate change (exit %d): %s",
						res.ExitCode, strings.TrimSpace(res.Stderr))
				}
			}
		}
	}
	return nil
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
