package legacybridge

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// sandbox creates a marked disposable root with a realistic legacy layout.
func sandbox(t *testing.T, fixture string) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".idleleo-phase01-sandbox"), "I_ACCEPT_DISPOSABLE_SANDBOX\n", 0o644)
	writeFile(t, filepath.Join(root, "etc/idleleo/install.sh"), "#!/bin/sh\necho legacy\n", 0o755)
	copyFixture(t, fixture, root)
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"), fixtureRuntime(t, fixture), 0o640)
	writeFile(t, filepath.Join(root, "etc/systemd/system/xray.service"),
		"[Service]\nUser=xray\nGroup=xray\nExecStart=/usr/local/bin/xray run -config /etc/idleleo/conf/xray/config.json\n", 0o644)
	writeFile(t, filepath.Join(root, "etc/systemd/system/nginx.service"),
		"[Service]\nUser=root\nExecStart=/usr/sbin/nginx -g daemon off;\n", 0o644)
	writeFile(t, filepath.Join(root, "etc/nginx/nginx.conf"), "events {}\nhttp {}\n", 0o644)
	writeFile(t, filepath.Join(root, "etc/idleleo/cert/fullchain.pem"), "CERT\n", 0o644)
	writeFile(t, filepath.Join(root, "etc/idleleo/cert/privkey.pem"), "KEY\n", 0o600)
	writeFile(t, filepath.Join(root, "var/spool/cron/crontabs/root"),
		"17 3 * * * /bin/true user-job\n"+
			"* * * * * /etc/idleleo/scripts/auto_update.sh >/dev/null 2>&1\n"+
			"0 4 * * * /etc/idleleo/scripts/ssl_update.sh\n"+
			"30 4 1 * * /etc/idleleo/scripts/geo_update.sh\n", 0o600)
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(root, "usr/bin/idleleo")
	legacy := filepath.Join(root, "etc/idleleo/install.sh")
	if err := os.Symlink(legacy, entry); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func copyFixture(t *testing.T, fixture, root string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "legacy", fixture, "install_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/install_config.json"), string(b), 0o640)
}

// fixtureRuntime returns a fixture-backed runtime config; reality-nginx and
// relay fixtures need their own files.
func fixtureRuntime(t *testing.T, fixture string) string {
	t.Helper()
	base := filepath.Join("..", "..", "tests", "fixtures", "legacy", fixture, "xray-config.json")
	if b, err := os.ReadFile(base); err == nil {
		return string(b)
	}
	return `{"inbounds":[{"listen":"127.0.0.1","port":9443,"protocol":"vless","settings":{"clients":[{"id":"u1"}]},"streamSettings":{"security":"reality","realitySettings":{"privateKey":"k"}}}],"outbounds":[{"protocol":"freedom"}]}`
}

func stubBin(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := `#!/bin/sh
if [ "$3" = "status" ] || [ "$2" = "status" ]; then
  echo '{"schemaVersion":1,"installed":true,"config":{"matchesMetadata":true}}'
  exit 0
fi
echo "idleleo test 0.0.0"
`
	writeFile(t, p, script, 0o755)
	return p
}

var (
	candOnce sync.Once
	candPath string
	candErr  error
	candDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if candDir != "" {
		_ = os.RemoveAll(candDir)
	}
	os.Exit(code)
}

// elfCandidate builds one real ELF manager once per test binary. Prepare now
// rejects non-ELF executables, so the old shell stub can no longer stand in
// for the candidate; recovery binaries keep using stubBin.
func elfCandidate(t *testing.T) string {
	t.Helper()
	candOnce.Do(func() {
		dir, err := os.MkdirTemp("", "idleleo-bridge-candidate-")
		if err != nil {
			candErr = err
			return
		}
		candDir = dir
		src := filepath.Join(dir, "main.go")
		prog := `package main

import (
	"fmt"
	"os"
)

func main() {
	for _, a := range os.Args[1:] {
		if a == "status" {
			fmt.Println(` + "`" + `{"schemaVersion":1,"installed":true,"config":{"matchesMetadata":true}}` + "`" + `)
			return
		}
		if a == "version" {
			fmt.Println("idleleo 0.2.0-phase04 (go)")
			return
		}
	}
	fmt.Println("idleleo 0.2.0-phase04 (go)")
}
`
		if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
			candErr = err
			return
		}
		out := filepath.Join(dir, "idleleo")
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			candErr = fmt.Errorf("build test candidate: %v: %s", err, b)
			return
		}
		candPath = out
	})
	if candErr != nil {
		t.Fatal(candErr)
	}
	return candPath
}

// fakeELFWrongArch writes a parseable ELF header for another machine so the
// architecture check is exercised without cross-compiling a real binary.
func fakeELFWrongArch(t *testing.T) string {
	t.Helper()
	machine := elf.EM_AARCH64
	if runtime.GOARCH == "arm64" {
		machine = elf.EM_X86_64
	}
	b := make([]byte, 64)
	copy(b, "\x7fELF")
	b[4] = 2                                 // ELFCLASS64
	b[5] = 1                                 // little endian
	b[6] = 1                                 // EV_CURRENT
	binary.LittleEndian.PutUint16(b[16:], 2) // ET_EXEC
	binary.LittleEndian.PutUint16(b[18:], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:], 1)  // e_version
	binary.LittleEndian.PutUint16(b[52:], 64) // e_ehsize
	p := filepath.Join(t.TempDir(), "idleleo")
	writeFile(t, p, string(b), 0o755)
	return p
}

func TestAuditRealityDirectConvertible(t *testing.T) {
	root := sandbox(t, "reality-direct")
	a, err := AuditMigration(root)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != VerdictConvertible {
		t.Fatalf("verdict=%s findings=%v", a.Verdict, a.Findings)
	}
	if a.Role != "node" || a.TLS != "Reality" || a.UserCount == 0 {
		t.Fatalf("unexpected audit %+v", a)
	}
	if a.Entry.IsGoBridge {
		t.Fatal("legacy entry must not be reported as Go")
	}
}

func TestAuditXTLSBlocked(t *testing.T) {
	root := sandbox(t, "xtls-only")
	a, err := AuditMigration(root)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != VerdictBlocked {
		t.Fatalf("verdict=%s", a.Verdict)
	}
	if !hasFinding(a, "legacy-xtls-removed") {
		t.Fatalf("missing xtls finding: %v", a.Findings)
	}
}

func TestAuditMissingMetadataBlocked(t *testing.T) {
	root := sandbox(t, "reality-direct")
	if err := os.Remove(filepath.Join(root, "etc/idleleo/conf/install_config.json")); err != nil {
		t.Fatal(err)
	}
	a, _ := AuditMigration(root)
	if a.Verdict != VerdictBlocked || !hasFinding(a, "legacy-metadata-missing") {
		t.Fatalf("verdict=%s findings=%v", a.Verdict, a.Findings)
	}
}

func TestAuditCorruptMetadataBlocked(t *testing.T) {
	root := sandbox(t, "reality-direct")
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/install_config.json"), "{broken", 0o640)
	a, _ := AuditMigration(root)
	if a.Verdict != VerdictBlocked || !hasFinding(a, "legacy-metadata-corrupt") {
		t.Fatalf("verdict=%s findings=%v", a.Verdict, a.Findings)
	}
}

func TestAuditPortConflictBlocked(t *testing.T) {
	root := sandbox(t, "reality-direct")
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/install_config.json"),
		`{"tls":"Reality","port":1,"shell_version":"3.3.4"}`, 0o640)
	a, _ := AuditMigration(root)
	if !hasFinding(a, "runtime-port-conflict") {
		t.Fatalf("expected port conflict, got %v", a.Findings)
	}
}

func TestAuditRealityKeyMissingBlocked(t *testing.T) {
	root := sandbox(t, "reality-direct")
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"),
		`{"inbounds":[{"port":9443,"settings":{"clients":[{"id":"u"}]},"streamSettings":{"security":"reality"}}]}`, 0o640)
	a, _ := AuditMigration(root)
	if !hasFinding(a, "reality-key-missing") {
		t.Fatalf("expected key missing, got %v", a.Findings)
	}
}

func TestAuditAlreadyMigratedBlocked(t *testing.T) {
	root := sandbox(t, "reality-direct")
	writeFile(t, filepath.Join(root, "opt/idleleo/bin/idleleo"), "go", 0o755)
	_ = os.Remove(filepath.Join(root, "usr/bin/idleleo"))
	if err := os.Symlink(filepath.Join(root, "opt/idleleo/bin/idleleo"), filepath.Join(root, "usr/bin/idleleo")); err != nil {
		t.Fatal(err)
	}
	a, _ := AuditMigration(root)
	if !hasFinding(a, "already-migrated") {
		t.Fatalf("expected already-migrated, got %v", a.Findings)
	}
}

func hasFinding(a Audit, code string) bool {
	for _, f := range a.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestPrepareLeavesRuntimeEntryCronUntouched(t *testing.T) {
	root := sandbox(t, "reality-direct")
	runtime := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	before := mustHash(t, runtime)
	cron := filepath.Join(root, "var/spool/cron/crontabs/root")
	cronBefore := mustHash(t, cron)
	entryBefore, _ := os.Readlink(filepath.Join(root, "usr/bin/idleleo"))

	cand := elfCandidate(t)
	rep, audit, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StatePrepared || audit.Verdict != VerdictConvertible {
		t.Fatalf("report=%+v verdict=%s", rep, audit.Verdict)
	}
	if mustHash(t, runtime) != before {
		t.Fatal("prepare rewrote the runtime config")
	}
	if mustHash(t, cron) != cronBefore {
		t.Fatal("prepare rewrote cron")
	}
	if entryAfter, _ := os.Readlink(filepath.Join(root, "usr/bin/idleleo")); entryAfter != entryBefore {
		t.Fatal("prepare changed the entry")
	}
	if rep.ProjectCronLines != 3 {
		t.Fatalf("project cron lines=%d", rep.ProjectCronLines)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/idleleo/bridge/plan.json")); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustHash(t *testing.T, p string) string {
	t.Helper()
	h, err := hashFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestActivateSwitchesEntryAndCronOnly(t *testing.T) {
	root := sandbox(t, "reality-direct")
	dir := t.TempDir()
	cand := elfCandidate(t)
	rec := stubBin(t, dir, "idleleo-recover")
	xray := stubBin(t, dir, "xray")
	nginx := stubBin(t, dir, "nginx")

	_, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand, Recovery: rec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(context.Background(), ValidateOptions{Root: root, XrayBin: xray, NginxBin: nginx}); err != nil {
		t.Fatal(err)
	}
	runtime := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
	before := mustHash(t, runtime)

	rep, err := Activate(context.Background(), ActivateOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateCommitted {
		t.Fatalf("state=%s", rep.State)
	}
	link, err := os.Readlink(filepath.Join(root, "usr/bin/idleleo"))
	if err != nil {
		t.Fatal(err)
	}
	if link != filepath.Join(root, "opt/idleleo/bin/idleleo") {
		t.Fatalf("entry link=%s", link)
	}
	if mustHash(t, runtime) != before {
		t.Fatal("activation rewrote the runtime config")
	}
	b, err := os.ReadFile(filepath.Join(root, "var/spool/cron/crontabs/root"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "/bin/true user-job") {
		t.Fatal("activation removed an unrelated user cron line")
	}
	for _, marker := range []string{"auto_update.sh", "ssl_update.sh"} {
		if strings.Count(string(b), marker) != 1 {
			t.Fatalf("retained cron line %s count=%d", marker, strings.Count(string(b), marker))
		}
	}
	if strings.Contains(string(b), "geo_update.sh") {
		t.Fatal("taken-over project cron line geo_update.sh survived")
	}
	if rep.RemovedCron != 1 {
		t.Fatalf("removed=%d", rep.RemovedCron)
	}
	if len(rep.RetainedCron) != 2 {
		t.Fatalf("retained=%v", rep.RetainedCron)
	}
	j, err := readJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != StateCommitted {
		t.Fatalf("journal=%s", j.State)
	}
}

func TestActivateRefusesWithoutRecoveryEntry(t *testing.T) {
	root := sandbox(t, "reality-direct")
	dir := t.TempDir()
	cand := elfCandidate(t)
	xray := stubBin(t, dir, "xray")
	nginx := stubBin(t, dir, "nginx")
	if _, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand}); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(context.Background(), ValidateOptions{Root: root, XrayBin: xray, NginxBin: nginx}); err != nil {
		t.Fatal(err)
	}
	entryBefore, _ := os.Readlink(filepath.Join(root, "usr/bin/idleleo"))
	if _, err := Activate(context.Background(), ActivateOptions{Root: root}); err == nil {
		t.Fatal("activation must refuse without the recovery binary")
	}
	if link, _ := os.Readlink(filepath.Join(root, "usr/bin/idleleo")); link != entryBefore {
		t.Fatal("refused activation changed the entry")
	}
}

func TestValidateRejectsDrift(t *testing.T) {
	root := sandbox(t, "reality-direct")
	dir := t.TempDir()
	cand := elfCandidate(t)
	xray := stubBin(t, dir, "xray")
	nginx := stubBin(t, dir, "nginx")
	if _, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"), mustRead(t, filepath.Join(root, "etc/idleleo/conf/xray/config.json"))+"\n", 0o640)
	_, err := Validate(context.Background(), ValidateOptions{Root: root, XrayBin: xray, NginxBin: nginx})
	if err == nil {
		t.Fatal("validate must reject runtime drift")
	}
	var be *Error
	if !asError(err, &be) || be.Code != 6 {
		t.Fatalf("expected conflict exit 6, got %v", err)
	}
}

func TestPrepareRefusesUnfinishedJournal(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := elfCandidate(t)
	j := Journal{SchemaVersion: JournalSchema, State: StateActivating}
	if err := writeJournal(root, &j); err != nil {
		t.Fatal(err)
	}
	_, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand})
	if err == nil {
		t.Fatal("prepare must refuse an unfinished transaction")
	}
}

func TestPrepareDoesNotOverwriteRecoveryEvidence(t *testing.T) {
	for _, state := range []string{StateActivating, StateRollbackRequired, StateRecoveryRequired, StateCommitted} {
		t.Run(state, func(t *testing.T) {
			root := sandbox(t, "reality-direct")
			// Evidence written by the interrupted transaction.
			evidence := map[string]string{
				"var/lib/idleleo/bridge/snapshot/entry.json":    `{"path":"/usr/bin/idleleo","exists":true}` + "\n",
				"var/lib/idleleo/bridge/snapshot/entry-idleleo": "legacy entry payload\n",
				"var/lib/idleleo/bridge/plan.json":              `{"state":"sentinel"}` + "\n",
				"opt/idleleo/bin/idleleo.candidate":             "existing candidate\n",
			}
			for rel, body := range evidence {
				writeFile(t, filepath.Join(root, rel), body, 0o640)
			}
			j := Journal{SchemaVersion: JournalSchema, State: state}
			if err := writeJournal(root, &j); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			for rel := range evidence {
				before[rel] = mustHash(t, filepath.Join(root, rel))
			}
			cand := elfCandidate(t)
			_, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand})
			if err == nil {
				t.Fatal("prepare must refuse an unfinished transaction")
			}
			var be *Error
			if !asError(err, &be) || be.Code != 3 {
				t.Fatalf("expected exit 3, got %v", err)
			}
			for rel := range evidence {
				if got := mustHash(t, filepath.Join(root, rel)); got != before[rel] {
					t.Fatalf("%s was modified by a refused prepare", rel)
				}
			}
		})
	}
}

func TestRequireWriteAccessDelegatesToHostGate(t *testing.T) {
	old := systemWriteGate
	t.Cleanup(func() { systemWriteGate = old })
	var gotRoot string
	var gotAck bool
	systemWriteGate = func(root string, ack bool) error {
		gotRoot, gotAck = root, ack
		return nil
	}
	if err := requireWriteAccess("/", false); err != nil {
		t.Fatalf("real host without container marker was refused: %v", err)
	}
	if gotRoot != "/" || gotAck {
		t.Fatalf("gate called with root=%q ack=%v", gotRoot, gotAck)
	}
	systemWriteGate = func(string, bool) error { return errors.New("audit trail unavailable") }
	var be *Error
	err := requireWriteAccess("/", false)
	if !asError(err, &be) || be.Code != 2 {
		t.Fatalf("expected exit 2, got %v", err)
	}
}

func TestActivateRefusesChangedEntry(t *testing.T) {
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
	entry := filepath.Join(root, "usr/bin/idleleo")
	_ = os.Remove(entry)
	if err := os.Symlink(filepath.Join(root, "opt/third-party/idleleo"), entry); err != nil {
		t.Fatal(err)
	}
	_, err := Activate(context.Background(), ActivateOptions{Root: root})
	if err == nil {
		t.Fatal("activation must refuse a replaced entry")
	}
	var be *Error
	if !asError(err, &be) || be.Code != 6 {
		t.Fatalf("expected exit 6, got %v", err)
	}
	if link, _ := os.Readlink(entry); link != filepath.Join(root, "opt/third-party/idleleo") {
		t.Fatalf("refused activation changed the third-party entry: %s", link)
	}
}

func TestRecoverPreservesThirdPartyEntry(t *testing.T) {
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
	entry := filepath.Join(root, "usr/bin/idleleo")
	_ = os.Remove(entry)
	if err := os.Symlink(filepath.Join(root, "opt/idleleo/bin/idleleo"), entry); err != nil {
		t.Fatal(err)
	}
	j, _ := readJournal(root)
	j.setState(StateActivating, "simulated crash")
	if err := writeJournal(root, &j); err != nil {
		t.Fatal(err)
	}
	// A third party replaces the entry after the crash.
	_ = os.Remove(entry)
	if err := os.Symlink(filepath.Join(root, "opt/third-party/idleleo"), entry); err != nil {
		t.Fatal(err)
	}
	rep, err := Recover(RecoverOptions{Root: root})
	if err == nil {
		t.Fatal("recovery must refuse to overwrite a third-party entry")
	}
	var be *Error
	if !asError(err, &be) || be.Code != 5 {
		t.Fatalf("expected exit 5, got %v", err)
	}
	if rep.State != StateRecoveryRequired || !rep.RequiresManual {
		t.Fatalf("report=%+v", rep)
	}
	if link, _ := os.Readlink(entry); link != filepath.Join(root, "opt/third-party/idleleo") {
		t.Fatalf("recovery overwrote the third-party entry: %s", link)
	}
}

func TestRecoverPreparedDiscards(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := elfCandidate(t)
	if _, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand}); err != nil {
		t.Fatal(err)
	}
	rep, err := Recover(RecoverOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateRolledBack || rep.Actions[0] != "discarded unactivated candidate" {
		t.Fatalf("report=%+v", rep)
	}
	link, _ := os.Readlink(filepath.Join(root, "usr/bin/idleleo"))
	if !strings.Contains(link, "install.sh") {
		t.Fatal("recovery changed an unactivated entry")
	}
}

func TestRecoverActivatingRestoresEntryAndCron(t *testing.T) {
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
	// Simulate a crash right after the entry switch.
	entry := filepath.Join(root, "usr/bin/idleleo")
	_ = os.Remove(entry)
	if err := os.Symlink(filepath.Join(root, "opt/idleleo/bin/idleleo"), entry); err != nil {
		t.Fatal(err)
	}
	j, _ := readJournal(root)
	j.setState(StateActivating, "simulated crash")
	if err := writeJournal(root, &j); err != nil {
		t.Fatal(err)
	}
	removed, err := rewriteCrontab(filepath.Join(root, "var/spool/cron/crontabs/root"))
	if err != nil || removed != 1 {
		t.Fatalf("cron removal=%d err=%v", removed, err)
	}
	rep, err := Recover(RecoverOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateRolledBack {
		t.Fatalf("state=%s", rep.State)
	}
	link, _ := os.Readlink(entry)
	if !strings.Contains(link, "install.sh") {
		t.Fatalf("entry was not restored: %s", link)
	}
	b, _ := os.ReadFile(filepath.Join(root, "var/spool/cron/crontabs/root"))
	for _, marker := range []string{"auto_update.sh", "ssl_update.sh", "geo_update.sh"} {
		if !strings.Contains(string(b), "/etc/idleleo/scripts/"+marker) {
			t.Fatalf("cron line %s was not restored; content=%q", marker, string(b))
		}
	}
	if !strings.Contains(string(b), "user-job") {
		t.Fatalf("unrelated user cron line lost: %s", b)
	}
}

func TestRecoverCommittedRefuses(t *testing.T) {
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
	rep, err := Recover(RecoverOptions{Root: root})
	if err == nil {
		t.Fatal("recovery must refuse a committed migration")
	}
	if rep.RequiresManual != true || rep.State != StateCommitted {
		t.Fatalf("report=%+v", rep)
	}
}

func TestRecoverCorruptJournal(t *testing.T) {
	root := sandbox(t, "reality-direct")
	writeFile(t, filepath.Join(root, "var/lib/idleleo/bridge/journal.json"), "{not-json", 0o640)
	rep, err := Recover(RecoverOptions{Root: root})
	if err == nil {
		t.Fatal("corrupt journal must not report success")
	}
	if rep.State == StateRolledBack {
		t.Fatal("corrupt journal must not be reported as rolled back")
	}
	var be *Error
	if !asError(err, &be) || be.Code != 2 {
		t.Fatalf("expected exit 2, got %v", err)
	}
}

func TestRecoverIdempotentRolledBack(t *testing.T) {
	root := sandbox(t, "reality-direct")
	j := Journal{SchemaVersion: JournalSchema, State: StateRolledBack}
	if err := writeJournal(root, &j); err != nil {
		t.Fatal(err)
	}
	rep, err := Recover(RecoverOptions{Root: root})
	if err != nil || rep.State != StateRolledBack {
		t.Fatalf("report=%+v err=%v", rep, err)
	}
}

func asError(err error, target **Error) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestStatusReadsJournal(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := elfCandidate(t)
	if _, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand}); err != nil {
		t.Fatal(err)
	}
	rep, err := Status(root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StatePrepared || rep.Verdict != VerdictConvertible {
		t.Fatalf("status=%+v", rep)
	}
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), "privateKey") || strings.Contains(string(b), "uuid") {
		t.Fatalf("status leaked secrets: %s", b)
	}
}

func bridgeCode(t *testing.T, err error) int {
	t.Helper()
	var be *Error
	if !asError(err, &be) {
		t.Fatalf("expected a bridge Error, got %v", err)
	}
	return be.Code
}

func TestPrepareRejectsTextCandidateWithExecBit(t *testing.T) {
	root := sandbox(t, "reality-direct")
	p := filepath.Join(t.TempDir(), "idleleo")
	writeFile(t, p, "#!/bin/sh\necho not-a-go-manager\n", 0o755)

	_, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: p})
	if err == nil {
		t.Fatal("a text file with the executable bit must not be accepted as the Go manager")
	}
	if code := bridgeCode(t, err); code != 2 {
		t.Fatalf("expected exit 2, got %d: %v", code, err)
	}
	if !strings.Contains(err.Error(), "not an ELF") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, journalRel)); !os.IsNotExist(statErr) {
		t.Fatal("a rejected candidate must not create a journal")
	}
}

func TestPrepareRejectsWrongArchitectureCandidate(t *testing.T) {
	root := sandbox(t, "reality-direct")
	_, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: fakeELFWrongArch(t)})
	if err == nil {
		t.Fatal("an ELF for another architecture must be rejected")
	}
	if code := bridgeCode(t, err); code != 2 {
		t.Fatalf("expected exit 2, got %d: %v", code, err)
	}
	if !strings.Contains(err.Error(), "architecture") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeCandidateManifest(t *testing.T, candidate string, mutate func(*CandidateManifest)) string {
	t.Helper()
	b, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	m := CandidateManifest{SHA256: hashBytes(b), Version: "0.2.0-phase04", GOARCH: runtime.GOARCH}
	if mutate != nil {
		mutate(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "manifest.json")
	writeFile(t, p, string(raw), 0o644)
	return p
}

func TestPrepareAcceptsTrustedManifest(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := elfCandidate(t)
	manifest := writeCandidateManifest(t, cand, nil)

	rep, _, err := Prepare(context.Background(), PrepareOptions{
		Root: root, Candidate: cand, CandidateManifest: manifest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StatePrepared || !rep.CandidatePinned {
		t.Fatalf("report=%+v", rep)
	}
	if rep.CandidateVersion != "0.2.0-phase04" {
		t.Fatalf("candidate version not recorded: %+v", rep)
	}
}

func TestPrepareRejectsManifestDigestMismatch(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := elfCandidate(t)
	manifest := writeCandidateManifest(t, cand, func(m *CandidateManifest) {
		m.SHA256 = strings.Repeat("0", 64)
	})
	_, _, err := Prepare(context.Background(), PrepareOptions{
		Root: root, Candidate: cand, CandidateManifest: manifest,
	})
	if err == nil {
		t.Fatal("a candidate that does not match the trusted digest must be rejected")
	}
	if code := bridgeCode(t, err); code != 2 {
		t.Fatalf("expected exit 2, got %d: %v", code, err)
	}
	if !strings.Contains(err.Error(), "trusted manifest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrepareRejectsManifestVersionMismatch(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := elfCandidate(t)
	manifest := writeCandidateManifest(t, cand, func(m *CandidateManifest) {
		m.Version = "9.9.9"
	})
	_, _, err := Prepare(context.Background(), PrepareOptions{
		Root: root, Candidate: cand, CandidateManifest: manifest,
	})
	if err == nil {
		t.Fatal("a candidate whose self-reported version differs from the manifest must be rejected")
	}
	if code := bridgeCode(t, err); code != 2 {
		t.Fatalf("expected exit 2, got %d: %v", code, err)
	}
	if !strings.Contains(err.Error(), "requires") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecoverAfterMetadataCrashLeavesNoHalfMigration(t *testing.T) {
	root := sandbox(t, "reality-direct")
	meta := filepath.Join(root, metadataRel)
	cand := elfCandidate(t)

	_, _, err := Prepare(context.Background(), PrepareOptions{
		Root: root, Candidate: cand, Fault: "crash-after-metadata",
	})
	if err == nil {
		t.Fatal("the crash fault must fail the prepare")
	}
	if code := bridgeCode(t, err); code != 13 {
		t.Fatalf("expected exit 13, got %d: %v", code, err)
	}
	j, err := readJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if j.State != StatePreparing {
		t.Fatalf("journal state after crash=%s, want %s", j.State, StatePreparing)
	}
	if _, err := os.Stat(meta); err != nil {
		t.Fatalf("the fault must leave the written metadata behind for recovery: %v", err)
	}
	// The journal already knew the exact metadata digest before the write, which
	// is only possible because PREPARING was committed first.
	written, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if j.MetadataNewSHA256 != hashBytes(written) {
		t.Fatalf("journal digest %q does not match the staged metadata", j.MetadataNewSHA256)
	}
	if _, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand}); err == nil {
		t.Fatal("prepare must refuse to continue a PREPARING journal")
	}

	rep, err := Recover(RecoverOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateRolledBack {
		t.Fatalf("recover state=%s", rep.State)
	}
	if _, err := os.Stat(meta); !os.IsNotExist(err) {
		t.Fatal("staged manager metadata must be removed, otherwise the root claims Go ownership while Bash still runs")
	}
	if link, _ := os.Readlink(filepath.Join(root, "usr/bin/idleleo")); link != filepath.Join(root, "etc/idleleo/install.sh") {
		t.Fatalf("entry changed during discard: %s", link)
	}

	rep2, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand})
	if err != nil {
		t.Fatalf("prepare after recovery must work again: %v", err)
	}
	if rep2.State != StatePrepared {
		t.Fatalf("second prepare state=%s", rep2.State)
	}
}

func TestRecoverAfterMetadataCrashRestoresPreviousMetadata(t *testing.T) {
	root := sandbox(t, "reality-direct")
	meta := filepath.Join(root, metadataRel)
	writeFile(t, meta, "{\"sentinel\":\"previous-manager\"}\n", 0o640)
	before := mustHash(t, meta)

	_, _, err := Prepare(context.Background(), PrepareOptions{
		Root: root, Candidate: elfCandidate(t), Fault: "crash-after-metadata",
	})
	if err == nil {
		t.Fatal("the crash fault must fail the prepare")
	}
	rep, err := Recover(RecoverOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateRolledBack {
		t.Fatalf("recover state=%s", rep.State)
	}
	if mustHash(t, meta) != before {
		t.Fatal("pre-migration manager metadata was not restored")
	}
}
