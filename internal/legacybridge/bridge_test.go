package legacybridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

	cand := stubBin(t, t.TempDir(), "idleleo")
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
	cand := stubBin(t, dir, "idleleo")
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
	for _, marker := range projectCronMarkers {
		if strings.Contains(string(b), marker) {
			t.Fatalf("project cron line %s survived", marker)
		}
	}
	if rep.RemovedCron != 3 {
		t.Fatalf("removed=%d", rep.RemovedCron)
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
	cand := stubBin(t, dir, "idleleo")
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
	cand := stubBin(t, dir, "idleleo")
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
	cand := stubBin(t, t.TempDir(), "idleleo")
	j := Journal{SchemaVersion: JournalSchema, State: StateActivating}
	if err := writeJournal(root, &j); err != nil {
		t.Fatal(err)
	}
	_, _, err := Prepare(context.Background(), PrepareOptions{Root: root, Candidate: cand})
	if err == nil {
		t.Fatal("prepare must refuse an unfinished transaction")
	}
}

func TestRecoverPreparedDiscards(t *testing.T) {
	root := sandbox(t, "reality-direct")
	cand := stubBin(t, t.TempDir(), "idleleo")
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
	cand := stubBin(t, dir, "idleleo")
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
	if err != nil || removed != 3 {
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
	cand := stubBin(t, dir, "idleleo")
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
	cand := stubBin(t, t.TempDir(), "idleleo")
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
