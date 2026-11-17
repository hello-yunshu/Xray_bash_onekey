package legacybridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

func errorCode(t *testing.T, err error) int {
	t.Helper()
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("expected a bridge Error, got %v", err)
	}
	return be.Code
}

func TestImportMetadataWritesLegacyProvenanceWithoutTouchingSource(t *testing.T) {
	root := sandbox(t, "reality-direct")
	source := filepath.Join(root, "etc/idleleo/conf/install_config.json")
	sourceBefore := mustHash(t, source)
	runtime := filepath.Join(root, "etc/idleleo/conf/xray/config.json")

	rep, err := ImportMetadata(ImportOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Provenance != "legacy" {
		t.Fatalf("provenance=%s", rep.Provenance)
	}
	if rep.Role != "node" || rep.TLS == "" || rep.Transport == "" {
		t.Fatalf("incomplete report: %+v", rep)
	}
	if mustHash(t, source) != sourceBefore {
		t.Fatal("import rewrote install_config.json")
	}

	b, err := os.ReadFile(filepath.Join(root, "etc/idleleo/v1/metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta store.Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Provenance != "legacy" || meta.ActiveEngine != "xray" {
		t.Fatalf("metadata provenance=%s engine=%s", meta.Provenance, meta.ActiveEngine)
	}
	if meta.RuntimeSHA256 != mustHash(t, runtime) {
		t.Fatal("metadata runtime digest does not match the runtime config")
	}

	if _, err := ImportMetadata(ImportOptions{Root: root}); errorCode(t, err) != 3 {
		t.Fatalf("second import should refuse to overwrite metadata, got %v", err)
	}
	if mustHash(t, source) != sourceBefore {
		t.Fatal("refused import still touched install_config.json")
	}
}

func TestExportRecordsRuntimeDigestAndRefusesManagedTarget(t *testing.T) {
	root := sandbox(t, "reality-direct")
	if _, err := ImportMetadata(ImportOptions{Root: root}); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	metaBefore := mustHash(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"))

	out := filepath.Join(t.TempDir(), "idleleo-export.json")
	rep, err := ExportMetadata(ExportOptions{Root: root, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.MatchesMetadata {
		t.Fatal("fresh import should match the runtime config")
	}
	if rep.RuntimeSHA256 != mustHash(t, runtime) {
		t.Fatal("export did not record the runtime digest")
	}
	var written ExportReport
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &written); err != nil {
		t.Fatal(err)
	}
	if written.RuntimeSHA256 != rep.RuntimeSHA256 || written.MetadataSHA256 != rep.MetadataSHA256 {
		t.Fatal("export file disagrees with the command report")
	}
	if mustHash(t, filepath.Join(root, "etc/idleleo/v1/metadata.json")) != metaBefore {
		t.Fatal("export wrote manager metadata")
	}
	if mustHash(t, runtime) != rep.RuntimeSHA256 {
		t.Fatal("export wrote the runtime config")
	}

	if _, err := ExportMetadata(ExportOptions{
		Root: root, Out: filepath.Join(root, "etc/idleleo/conf/export.json"),
	}); errorCode(t, err) != 2 {
		t.Fatalf("export into the managed config dir must be refused, got %v", err)
	}
}

func TestDeactivateReleasesImportedMetadataWithoutJournal(t *testing.T) {
	root := sandbox(t, "reality-direct")
	if _, err := ImportMetadata(ImportOptions{Root: root}); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(root, "usr/bin/idleleo")
	linkBefore, err := os.Readlink(entry)
	if err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	runtimeBefore := mustHash(t, runtime)
	certBefore := mustHash(t, filepath.Join(root, "etc/idleleo/cert/fullchain.pem"))
	keyBefore := mustHash(t, filepath.Join(root, "etc/idleleo/cert/privkey.pem"))
	cron := filepath.Join(root, "var/spool/cron/crontabs/root")
	cronBefore := mustHash(t, cron)

	out := filepath.Join(t.TempDir(), "idleleo-export.json")
	if _, err := ExportMetadata(ExportOptions{Root: root, Out: out}); err != nil {
		t.Fatal(err)
	}
	rep, err := Deactivate(DeactivateOptions{Root: root, Export: out})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != "RELEASED" {
		t.Fatalf("state=%s", rep.State)
	}
	link, err := os.Readlink(entry)
	if err != nil {
		t.Fatal(err)
	}
	if link != linkBefore {
		t.Fatalf("import-only release changed the entry: %s -> %s", linkBefore, link)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/idleleo/v1/metadata.json")); !os.IsNotExist(err) {
		t.Fatal("metadata.json survived the import-only release")
	}
	if _, err := os.Stat(rep.MetadataArchive); err != nil {
		t.Fatalf("archived metadata missing: %v", err)
	}
	// The import-only release may archive metadata and nothing else.
	if mustHash(t, runtime) != runtimeBefore {
		t.Fatal("import-only release rewrote the runtime config")
	}
	if mustHash(t, filepath.Join(root, "etc/idleleo/cert/fullchain.pem")) != certBefore {
		t.Fatal("import-only release rewrote the certificate")
	}
	if mustHash(t, filepath.Join(root, "etc/idleleo/cert/privkey.pem")) != keyBefore {
		t.Fatal("import-only release rewrote the private key")
	}
	if mustHash(t, cron) != cronBefore {
		t.Fatal("import-only release rewrote user cron")
	}
}

func TestDeactivateRequiresMatchingExportAndRestoresLegacyEntry(t *testing.T) {
	root := sandbox(t, "reality-direct")
	dir := t.TempDir()
	cand := elfCandidate(t)
	rec := stubBin(t, dir, "idleleo-recover")
	xray := stubBin(t, dir, "xray")
	nginx := stubBin(t, dir, "nginx")
	if _, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand, Recovery: rec}); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(context.Background(), ValidateOptions{Root: root, XrayBin: xray, NginxBin: nginx}); err != nil {
		t.Fatal(err)
	}
	if _, err := Activate(context.Background(), ActivateOptions{Root: root}); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	runtimeBytes, err := os.ReadFile(runtime)
	if err != nil {
		t.Fatal(err)
	}
	runtimeSHA := mustHash(t, runtime)

	// Deactivate without an export is refused: the order is export, then hand-back.
	if _, err := Deactivate(DeactivateOptions{Root: root}); errorCode(t, err) != 2 {
		t.Fatalf("deactivate without --export must be refused, got %v", err)
	}

	out := filepath.Join(t.TempDir(), "idleleo-export.json")
	exp, err := ExportMetadata(ExportOptions{Root: root, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	if !exp.MatchesMetadata || exp.RuntimeSHA256 != runtimeSHA {
		t.Fatalf("unexpected export: %+v", exp)
	}

	// A runtime drift after export invalidates the hand-back.
	writeFile(t, runtime, "{}\n", 0o640)
	if _, err := Deactivate(DeactivateOptions{Root: root, Export: out}); errorCode(t, err) != 6 {
		t.Fatalf("drifted runtime must be refused, got %v", err)
	}
	link, err := os.Readlink(filepath.Join(root, "usr/bin/idleleo"))
	if err != nil {
		t.Fatal(err)
	}
	if link != filepath.Join(root, "opt/idleleo/bin/idleleo") {
		t.Fatal("refused deactivate still switched the entry")
	}
	if err := os.WriteFile(runtime, runtimeBytes, 0o640); err != nil {
		t.Fatal(err)
	}

	rep, err := Deactivate(DeactivateOptions{Root: root, Export: out})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateRolledBack {
		t.Fatalf("state=%s", rep.State)
	}
	link, err = os.Readlink(filepath.Join(root, "usr/bin/idleleo"))
	if err != nil {
		t.Fatal(err)
	}
	if link != filepath.Join(root, "etc/idleleo/install.sh") {
		t.Fatalf("entry not handed back to Bash: %s", link)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/idleleo/v1/metadata.json")); !os.IsNotExist(err) {
		t.Fatal("metadata.json still marks the root as Go-owned after deactivate")
	}
	if _, err := os.Stat(rep.MetadataArchive); err != nil {
		t.Fatalf("archived metadata missing: %v", err)
	}
	if mustHash(t, runtime) != runtimeSHA {
		t.Fatal("deactivate rewrote the runtime config")
	}
}
