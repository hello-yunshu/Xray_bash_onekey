package legacybridge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// importMaxBytes bounds the legacy config a caller can hand to import.
const importMaxBytes = 1 << 20

// ImportOptions is one metadata import request. The source is always the
// managed legacy config under the root; there is no way to import an arbitrary
// file and pretend it describes this host.
type ImportOptions struct {
	Root                 string
	AllowContainerWrites bool
}

// ImportReport is the machine-readable import result.
type ImportReport struct {
	SchemaVersion  int      `json:"schemaVersion"`
	State          string   `json:"state"`
	MetadataPath   string   `json:"metadataPath"`
	MetadataSHA256 string   `json:"metadataSha256"`
	Provenance     string   `json:"provenance"`
	Role           string   `json:"role"`
	TLS            string   `json:"tls"`
	Transport      string   `json:"transport"`
	RuntimeSHA256  string   `json:"runtimeSha256,omitempty"`
	SourcePath     string   `json:"sourcePath"`
	SourceSHA256   string   `json:"sourceSha256"`
	Warnings       []string `json:"warnings"`
}

// ImportMetadata writes manager metadata from the existing legacy config. It
// reads install_config.json and never writes it; provenance is fixed to
// "legacy" so a later reader can tell this record was derived, not installed.
// An existing metadata.json is never overwritten: it is the single source of
// truth, and silently replacing it is exactly the dual-write this phase bans.
func ImportMetadata(opts ImportOptions) (ImportReport, error) {
	report := ImportReport{
		SchemaVersion: 1, Provenance: "legacy", State: "IMPORTED", Warnings: []string{},
	}
	if err := requireWriteAccess(opts.Root, opts.AllowContainerWrites); err != nil {
		return report, err
	}
	lock, err := lockForWrite(opts.Root)
	if err != nil {
		return report, err
	}
	if lock != nil {
		defer lock.Release()
	}

	metaPath := mustResolve(opts.Root, metadataRel)
	if _, statErr := os.Lstat(metaPath); statErr == nil {
		return report, &Error{Code: 3, Msg: "manager metadata already exists; import never overwrites the single source of truth"}
	} else if !os.IsNotExist(statErr) {
		return report, &Error{Code: 13, Msg: "cannot inspect the metadata path", Err: statErr}
	}

	source := mustResolve(opts.Root, legacyConfigRel)
	raw, err := os.ReadFile(source)
	if err != nil {
		return report, &Error{Code: 2, Msg: "install_config.json is required for import", Err: err}
	}
	if len(raw) > importMaxBytes {
		return report, &Error{Code: 2, Msg: "install_config.json is larger than 1 MiB; refusing"}
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return report, &Error{Code: 2, Msg: "install_config.json is not valid JSON", Err: err}
	}
	report.SourcePath = source
	report.SourceSHA256 = hashBytes(raw)
	if _, ok := probe["role"]; !ok {
		report.Warnings = append(report.Warnings,
			"install_config.json 无 role 字段，按 legacy 语义视为 node")
	}

	audit, err := AuditMigration(opts.Root)
	if err != nil {
		return report, &Error{Code: 1, Msg: "audit failed", Err: err}
	}
	if audit.Verdict == VerdictBlocked {
		return report, &Error{Code: 3, Msg: "import blocked by audit"}
	}

	b, err := buildMetadata(audit)
	if err != nil {
		return report, &Error{Code: 13, Msg: "build metadata failed", Err: err}
	}
	var meta store.Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return report, &Error{Code: 13, Msg: "build metadata failed", Err: err}
	}
	meta.Provenance = "legacy"
	meta.UpdatedAt = now()
	if meta.Role == "node" && meta.RuntimeSHA256 == "" {
		return report, &Error{Code: 3, Msg: "runtime config is missing or empty; refusing to import incomplete metadata"}
	}
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return report, &Error{Code: 13, Msg: "build metadata failed", Err: err}
	}
	out = append(out, '\n')

	// The source must still be byte-identical immediately before the write.
	if current, err := os.ReadFile(source); err != nil || hashBytes(current) != report.SourceSHA256 {
		return report, &Error{Code: 13, Msg: "install_config.json changed during import; source was left untouched"}
	}
	if err := writeAtomic(metaPath, out, 0o640); err != nil {
		return report, &Error{Code: 13, Msg: "write metadata failed", Err: err}
	}

	report.MetadataPath = metaPath
	report.MetadataSHA256 = hashBytes(out)
	report.Role = meta.Role
	report.TLS = meta.TLS
	report.Transport = meta.Transport
	report.RuntimeSHA256 = meta.RuntimeSHA256
	return report, nil
}

// ExportOptions is one metadata export request. Out may be empty, in which
// case the caller prints the report as the export document.
type ExportOptions struct {
	Root string
	Out  string
}

// ExportReport is both the command output and the file that deactivate
// validates. It deliberately records the runtime digest observed at export
// time so a later deactivate can prove nothing drifted.
type ExportReport struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Provenance            string `json:"provenance,omitempty"`
	Role                  string `json:"role"`
	TLS                   string `json:"tls"`
	Transport             string `json:"transport"`
	MetadataPath          string `json:"metadataPath"`
	MetadataSHA256        string `json:"metadataSha256"`
	MetadataRuntimeSHA256 string `json:"metadataRuntimeSha256,omitempty"`
	RuntimeConfigPath     string `json:"runtimeConfigPath,omitempty"`
	RuntimeSHA256         string `json:"runtimeSha256"`
	MatchesMetadata       bool   `json:"matchesMetadata"`
	ExportedAt            string `json:"exportedAt"`
	Out                   string `json:"out,omitempty"`
}

// ExportMetadata reads the single source of truth and the runtime file it
// describes. It never writes runtime config, certificates or user data; the
// only write is the export document itself, and that target may not live under
// a managed directory.
func ExportMetadata(opts ExportOptions) (ExportReport, error) {
	report := ExportReport{SchemaVersion: 1}
	paths, err := host.NewPaths(opts.Root)
	if err != nil {
		return report, &Error{Code: 2, Msg: "invalid root", Err: err}
	}
	meta, metaSHA, err := store.LoadMetadata(paths)
	if err != nil {
		return report, &Error{Code: 3, Msg: "manager metadata is not readable", Err: err}
	}
	report.Provenance = meta.Provenance
	report.Role = meta.Role
	report.TLS = meta.TLS
	report.Transport = meta.Transport
	report.MetadataPath = mustResolve(opts.Root, metadataRel)
	report.MetadataSHA256 = metaSHA
	report.MetadataRuntimeSHA256 = meta.RuntimeSHA256
	report.RuntimeConfigPath = meta.RuntimeConfigPath
	actual, err := runtimeDigest(opts.Root, meta)
	if err != nil {
		return report, &Error{Code: 3, Msg: "cannot read the runtime config", Err: err}
	}
	report.RuntimeSHA256 = actual
	report.MatchesMetadata = actual == meta.RuntimeSHA256
	report.ExportedAt = now()

	if opts.Out != "" {
		if err := refuseManagedExportTarget(opts.Root, opts.Out); err != nil {
			return report, &Error{Code: 2, Msg: err.Error()}
		}
		report.Out = opts.Out
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return report, &Error{Code: 13, Msg: "encode export failed", Err: err}
		}
		b = append(b, '\n')
		if err := writeAtomic(opts.Out, b, 0o600); err != nil {
			return report, &Error{Code: 13, Msg: "write export failed", Err: err}
		}
	}
	return report, nil
}

// runtimeDigest fingerprints the runtime file named by metadata. Relay roots
// have no node runtime config, so an empty digest is the correct answer there.
func runtimeDigest(root string, meta store.Metadata) (string, error) {
	if meta.Role != "node" || meta.RuntimeConfigPath == "" {
		return "", nil
	}
	if err := store.ValidateManagerPath(meta.RuntimeConfigPath); err != nil {
		return "", err
	}
	p := mustResolve(root, meta.RuntimeConfigPath)
	sha, err := hashFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("runtime config is missing: %s", p)
		}
		return "", err
	}
	return sha, nil
}

// refuseManagedExportTarget keeps export from overwriting the files it only
// promised to read.
func refuseManagedExportTarget(root, out string) error {
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if abs == mustResolve(root, metadataRel) {
		return fmt.Errorf("refusing to export over manager metadata")
	}
	for _, rel := range []string{"etc/idleleo/conf", certDirRel, "etc/idleleo/info"} {
		dir := mustResolve(root, rel)
		if abs == dir || strings.HasPrefix(abs, dir+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to export into managed path %s", rel)
		}
	}
	return nil
}

// DeactivateOptions is one request to hand the root back to the Bash manager.
type DeactivateOptions struct {
	Root                 string
	Export               string
	AllowContainerWrites bool
}

// DeactivateReport is the machine-readable hand-back result.
type DeactivateReport struct {
	SchemaVersion   int      `json:"schemaVersion"`
	State           string   `json:"state"`
	Entry           string   `json:"entry"`
	Actions         []string `json:"actions"`
	ExportPath      string   `json:"exportPath"`
	RuntimeSHA256   string   `json:"runtimeSha256"`
	MetadataArchive string   `json:"metadataArchive,omitempty"`
	RillUnchanged   bool     `json:"rillUnchanged"`
}

// Deactivate reverses a committed bridge activation. It requires the export
// document written by "metadata export" and refuses when either the runtime
// file or metadata changed after that export. Runtime config, certificates and
// user data are never written; only the entry, project cron lines, permission
// modes recorded in the snapshot, and manager metadata move.
func Deactivate(opts DeactivateOptions) (DeactivateReport, error) {
	report := DeactivateReport{SchemaVersion: 1, Actions: []string{}}
	if opts.Export == "" {
		return report, &Error{Code: 2, Msg: "--export is required; run 'idleleo metadata export --out FILE' first"}
	}
	if err := requireWriteAccess(opts.Root, opts.AllowContainerWrites); err != nil {
		return report, err
	}
	lock, err := lockForWrite(opts.Root)
	if err != nil {
		return report, err
	}
	if lock != nil {
		defer lock.Release()
	}

	j, hasJournal, err := loadJournal(opts.Root)
	if err != nil {
		return report, &Error{Code: 2, Msg: "cannot read the bridge journal", Err: err}
	}
	if hasJournal && j.State != StateCommitted {
		return report, &Error{Code: 3, Msg: "deactivate requires a COMMITTED bridge transaction or no transaction at all; current state is " + j.State + "; run bridge recover first"}
	}
	if !hasJournal {
		// Import without activation only declares ownership; the entry still
		// belongs to Bash, so there is nothing to restore. Refuse a hand-back
		// when the entry already points at Go, because that state has no
		// journal and needs recovery, not metadata removal.
		if entry, err := os.Readlink(mustResolve(opts.Root, entryRel)); err == nil &&
			entry == mustResolve(opts.Root, installedRel) {
			return report, &Error{Code: 3, Msg: "entry already points at the Go manager but no bridge journal exists; run bridge recover instead of deactivate"}
		}
	}

	exp, err := readExport(opts.Export)
	if err != nil {
		return report, &Error{Code: 2, Msg: "invalid export document", Err: err}
	}
	report.ExportPath = opts.Export
	report.RuntimeSHA256 = exp.RuntimeSHA256

	paths, err := host.NewPaths(opts.Root)
	if err != nil {
		return report, &Error{Code: 2, Msg: "invalid root", Err: err}
	}
	meta, metaSHA, err := store.LoadMetadata(paths)
	if err != nil {
		return report, &Error{Code: 3, Msg: "manager metadata is not readable", Err: err}
	}
	if metaSHA != exp.MetadataSHA256 {
		return report, &Error{Code: 6, Msg: "manager metadata changed since the export; export again before deactivating"}
	}
	actual, err := runtimeDigest(opts.Root, meta)
	if err != nil {
		return report, &Error{Code: 3, Msg: "cannot read the runtime config", Err: err}
	}
	if !exp.MatchesMetadata || exp.RuntimeSHA256 != exp.MetadataRuntimeSHA256 {
		return report, &Error{Code: 6, Msg: "the export was taken while metadata and the runtime config disagreed; export again after resolving the drift"}
	}
	if actual != exp.RuntimeSHA256 {
		return report, &Error{Code: 6, Msg: "the runtime config changed since the export; export again before deactivating"}
	}
	if meta.RuntimeSHA256 != exp.RuntimeSHA256 {
		return report, &Error{Code: 6, Msg: "manager metadata no longer matches the exported runtime digest"}
	}
	if hasJournal && j.RuntimeSHA256 != "" && j.RuntimeSHA256 != exp.RuntimeSHA256 {
		return report, &Error{Code: 6, Msg: "the bridge journal records a different runtime digest; refusing to hand back a drifted config"}
	}

	if hasJournal {
		state, actions, err := rollbackWithActions(opts.Root, &j)
		report.State, report.Actions = state, actions
		report.RillUnchanged = rillUnchanged(opts.Root, currentRill(opts.Root))
		if err != nil {
			return report, &Error{Code: 5, Msg: "deactivate restore failed; keep the snapshot and inspect manually", Err: err}
		}
	} else {
		report.State = "RELEASED"
		report.RillUnchanged = true
		report.Actions = append(report.Actions,
			"no bridge transaction found; released manager metadata without touching the entry or cron")
	}
	report.Entry = mustResolve(opts.Root, entryRel)

	// Metadata is archived, not deleted: the record must stay auditable while
	// its absence is what tells the Bash manager it may write again.
	archive := filepath.Join(mustResolve(opts.Root, snapshotRel), "metadata.deactivated.json")
	if _, statErr := os.Lstat(archive); statErr == nil {
		return report, &Error{Code: 13, Msg: "deactivate archive already exists; refusing to overwrite " + archive}
	}
	if err := os.MkdirAll(filepath.Dir(archive), 0o750); err != nil {
		return report, &Error{Code: 13, Msg: "cannot create the deactivate archive directory", Err: err}
	}
	if err := os.Rename(mustResolve(opts.Root, metadataRel), archive); err != nil {
		return report, &Error{Code: 13, Msg: "hand-back completed but manager metadata could not be archived; remove it manually after verifying the entry is correct: " + mustResolve(opts.Root, metadataRel), Err: err}
	}
	report.MetadataArchive = archive
	report.Actions = append(report.Actions, "archived manager metadata to "+archive)
	if _, err := os.Lstat(mustResolve(opts.Root, installedRel)); err == nil {
		report.Actions = append(report.Actions,
			"kept the installed Go binary for a later re-activation")
	}
	return report, nil
}

// loadJournal distinguishes "no transaction yet" from a real journal. Import
// alone creates metadata without a journal, and that state must still be
// releasable.
func loadJournal(root string) (Journal, bool, error) {
	p, err := journalPath(root)
	if err != nil {
		return Journal{}, false, err
	}
	if _, err := os.Lstat(p); err != nil {
		if os.IsNotExist(err) {
			return Journal{}, false, nil
		}
		return Journal{}, false, err
	}
	j, err := readJournal(root)
	if err != nil {
		return Journal{}, true, err
	}
	return j, true, nil
}

// readExport parses and validates an export document.
func readExport(path string) (ExportReport, error) {
	var exp ExportReport
	fi, err := os.Lstat(path)
	if err != nil {
		return exp, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return exp, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > importMaxBytes {
		return exp, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return exp, err
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		return exp, err
	}
	if exp.SchemaVersion != 1 {
		return exp, fmt.Errorf("unsupported export schema %d", exp.SchemaVersion)
	}
	if !shaHexValue(exp.MetadataSHA256) {
		return exp, fmt.Errorf("export metadataSha256 is not 64 lowercase hex characters")
	}
	if exp.RuntimeSHA256 != "" && !shaHexValue(exp.RuntimeSHA256) {
		return exp, fmt.Errorf("export runtimeSha256 is not 64 lowercase hex characters")
	}
	return exp, nil
}

func shaHexValue(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
