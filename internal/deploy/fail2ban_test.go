package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

type fail2banStub struct {
	statusOut   string
	jails       map[string]string
	calls       []string
	rejectTest  bool
	reloadFails bool
}

func stubFail2ban(t *testing.T, stub *fail2banStub, ip string) *fail2banStub {
	t.Helper()
	oldLook, oldRun, oldIP := lookPathFail2ban, runFail2ban, sshClientIP
	lookPathFail2ban = func() (string, error) { return "/usr/bin/fail2ban-client", nil }
	sshClientIP = func() string { return ip }
	runFail2ban = func(_ context.Context, _ string, args ...string) (host.ExecResult, error) {
		stub.calls = append(stub.calls, strings.Join(args, " "))
		switch {
		case len(args) > 0 && args[0] == "-c":
			if stub.rejectTest {
				return host.ExecResult{ExitCode: 1, Stderr: "ERROR invalid config"}, nil
			}
			return host.ExecResult{}, nil
		case len(args) == 1 && args[0] == "status":
			return host.ExecResult{Stdout: stub.statusOut}, nil
		case len(args) == 2 && args[0] == "status":
			out, ok := stub.jails[args[1]]
			if !ok {
				return host.ExecResult{ExitCode: 255, Stderr: "Sorry but the jail '" + args[1] + "' does not exist"}, nil
			}
			return host.ExecResult{Stdout: out}, nil
		case len(args) == 4 && args[0] == "set" && args[2] == "unbanip":
			jail, ip := args[1], args[3]
			out := stub.jails[jail]
			lines := []string{}
			for _, line := range strings.Split(out, "\n") {
				idx := strings.Index(line, "Banned IP list:")
				if idx < 0 {
					lines = append(lines, line)
					continue
				}
				kept := []string{}
				for _, field := range strings.Fields(line[idx+len("Banned IP list:"):]) {
					if field != ip {
						kept = append(kept, field)
					}
				}
				lines = append(lines, line[:idx]+"Banned IP list:\t"+strings.Join(kept, " "))
			}
			stub.jails[jail] = strings.Join(lines, "\n")
			return host.ExecResult{}, nil
		case len(args) == 1 && args[0] == "reload":
			if stub.reloadFails {
				return host.ExecResult{ExitCode: 1, Stderr: "ERROR reload failed"}, nil
			}
			return host.ExecResult{}, nil
		}
		return host.ExecResult{}, nil
	}
	t.Cleanup(func() {
		lookPathFail2ban, runFail2ban, sshClientIP = oldLook, oldRun, oldIP
	})
	return stub
}

func seedNginxLogs(t *testing.T, root string, names ...string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(root, "usr/local/nginx/logs", name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("log\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func seedFail2banPackage(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, "etc/fail2ban/jail.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[DEFAULT]\nbantime = 10m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFail2banInstallWritesBashJailsAndSkipsMissingLogs(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	seedNginxLogs(t, root, "access.log", "sni_error.log")
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stub := stubFail2ban(t, &fail2banStub{statusOut: "Jail list:\tsshd, nginx-badbots\n"}, "203.0.113.7")

	report, err := InstallFail2ban(context.Background(), Fail2banSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}

	wantWritten := map[string]bool{"sshd": true, "nginx-badbots": true, "nginx-botsearch": true, "nginx-no-host": true}
	for _, jail := range report.Jails {
		if jail.Written != wantWritten[jail.Name] {
			t.Fatalf("jail %s written = %v, want %v (%s)", jail.Name, jail.Written, wantWritten[jail.Name], jail.Reason)
		}
	}
	tlsJail := report.Jails[4]
	if tlsJail.Name != "nginx-tls-error" || !strings.Contains(tlsJail.Reason, "log file does not exist") {
		t.Fatalf("tls-error jail = %+v, want skipped for a missing log", tlsJail)
	}

	jailDir := filepath.Join(root, "etc/fail2ban/jail.d")
	for _, name := range []string{"sshd.local", "nginx-badbots.local", "nginx-botsearch.local", "nginx-no-host.local", "zzz-idleleo-incremental.local"} {
		if _, err := os.Stat(filepath.Join(jailDir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(jailDir, "nginx-tls-error.local")); !os.IsNotExist(err) {
		t.Fatal("nginx-tls-error.local must not be written without its log file")
	}
	if body := readFile(t, filepath.Join(root, "etc/fail2ban/jail.local")); !strings.Contains(body, "bantime = 10m") {
		t.Fatalf("jail.local was not copied from jail.conf: %s", body)
	}
	if body := readFile(t, filepath.Join(jailDir, "sshd.local")); !strings.Contains(body, "bantime = 604800") {
		t.Fatalf("sshd jail lost the Bash bantime: %s", body)
	}
	if body := readFile(t, filepath.Join(jailDir, "nginx-no-host.local")); !strings.Contains(body, "findtime = 120") ||
		!strings.Contains(body, "logpath  = "+filepath.Join(root, "usr/local/nginx/logs/sni_error.log")) {
		t.Fatalf("no-host jail does not match Bash: %s", body)
	}
	if body := readFile(t, filepath.Join(root, "etc/fail2ban/filter.d/nginx-no-host.conf")); !strings.Contains(body, "datepattern = %%d/%%b/%%Y") {
		t.Fatalf("custom filter lost the doubled percent escapes: %s", body)
	}
	if body := readFile(t, filepath.Join(jailDir, "zzz-idleleo-incremental.local")); !strings.Contains(body, "bantime.maxtime = 180d") {
		t.Fatalf("incremental policy missing: %s", body)
	}

	manifest := loadFail2banManifest(mustPaths(t, root))
	if !manifest.contains("etc/fail2ban/jail.d/nginx-badbots.local") || manifest.contains("etc/fail2ban/jail.d/nginx-tls-error.local") {
		t.Fatalf("manifest = %v, want only the jails that were written", manifest.Files)
	}
	if report.SSHClientIP != "203.0.113.7" {
		t.Fatalf("SSHClientIP = %q", report.SSHClientIP)
	}
	if !strings.Contains(report.TrustHint, "fail2ban trust add --jail sshd --ip 203.0.113.7") {
		t.Fatalf("TrustHint = %q", report.TrustHint)
	}
	if len(stub.calls) == 0 || !strings.Contains(strings.Join(stub.calls, "|"), "-t") {
		t.Fatal("candidate config was never validated")
	}
}

func TestFail2banInstallRespectsDisableFlags(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	seedNginxLogs(t, root, "access.log", "sni_error.log", "tls_error.log")
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stubFail2ban(t, &fail2banStub{}, "")

	report, err := InstallFail2ban(context.Background(), Fail2banSpec{
		Root: root, DisableNoHost: true, DisableTLSError: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, jail := range report.Jails {
		if jail.Name == "nginx-no-host" || jail.Name == "nginx-tls-error" {
			if jail.Written || !strings.Contains(jail.Reason, "disabled by --no-nginx-") {
				t.Fatalf("jail %s = %+v, want an explicit opt-out", jail.Name, jail)
			}
		}
	}
	for _, name := range []string{"nginx-no-host.local", "nginx-tls-error.local"} {
		if _, err := os.Stat(filepath.Join(root, "etc/fail2ban/jail.d", name)); !os.IsNotExist(err) {
			t.Fatalf("%s must not be written when opted out", name)
		}
	}
}

func TestFail2banInstallRequiresTheBinary(t *testing.T) {
	root := sandbox(t)
	oldLook := lookPathFail2ban
	lookPathFail2ban = func() (string, error) { return "", errors.New("executable file not found") }
	t.Cleanup(func() { lookPathFail2ban = oldLook })

	_, err := InstallFail2ban(context.Background(), Fail2banSpec{Root: root})
	if err == nil || !strings.Contains(err.Error(), "apt-get install -y fail2ban") {
		t.Fatalf("err = %v, want the copy-paste install hint", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "etc/fail2ban")); !os.IsNotExist(statErr) {
		t.Fatal("nothing may be written when the binary is missing")
	}
}

func TestFail2banInstallRejectsCandidateWithoutWriting(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	seedNginxLogs(t, root, "access.log")
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stubFail2ban(t, &fail2banStub{rejectTest: true}, "")

	_, err := InstallFail2ban(context.Background(), Fail2banSpec{Root: root})
	if err == nil || !strings.Contains(err.Error(), "rejected the generated config") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "etc/fail2ban/jail.local")); !os.IsNotExist(statErr) {
		t.Fatal("a rejected candidate must not leave jail.local behind")
	}
	if _, statErr := os.Stat(filepath.Join(root, "etc/fail2ban/jail.d")); !os.IsNotExist(statErr) {
		t.Fatal("a rejected candidate must not leave any jail.d files")
	}
}

func TestFail2banInstallKeepsForeignFiles(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	seedNginxLogs(t, root, "access.log")
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stubFail2ban(t, &fail2banStub{}, "")

	foreign := filepath.Join(root, "etc/fail2ban/jail.d/nginx-badbots.local")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("[nginx-badbots]\nenabled = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := InstallFail2ban(context.Background(), Fail2banSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, foreign) != "[nginx-badbots]\nenabled = false\n" {
		t.Fatal("a pre-existing jail file was overwritten")
	}
	found := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "left "+foreign+" untouched") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v, want an explicit untouched notice", report.Warnings)
	}
	manifest := loadFail2banManifest(mustPaths(t, root))
	if manifest.contains("etc/fail2ban/jail.d/nginx-badbots.local") {
		t.Fatal("a foreign file must never enter the manifest")
	}
}

func TestFail2banUninstallRemovesOnlyManifestFiles(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	seedNginxLogs(t, root, "access.log")
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stubFail2ban(t, &fail2banStub{}, "")

	if _, err := InstallFail2ban(context.Background(), Fail2banSpec{Root: root}); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "etc/fail2ban/jail.d/my-own.local")
	if err := os.WriteFile(foreign, []byte("[my-own]\nenabled = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := UninstallFail2ban(context.Background(), UninstallFail2banSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("a file outside the manifest was deleted")
	}
	if !containsString(report.Preserved, foreign) {
		t.Fatalf("preserved = %v, want %s", report.Preserved, foreign)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/fail2ban/jail.d/sshd.local")); !os.IsNotExist(err) {
		t.Fatal("a manifest file survived the uninstall")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/fail2ban/jail.conf")); err != nil {
		t.Fatal("the package's jail.conf must never be touched")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/idleleo/v1/fail2ban.json")); !os.IsNotExist(err) {
		t.Fatal("the manifest should be gone after a clean uninstall")
	}
}

func TestFail2banUninstallWithoutManifestNeedsForce(t *testing.T) {
	root := sandbox(t)
	jailDir := filepath.Join(root, "etc/fail2ban/jail.d")
	if err := os.MkdirAll(jailDir, 0o755); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(jailDir, "sshd.local")
	foreign := filepath.Join(jailDir, "legacy.local")
	for _, path := range []string{managed, foreign} {
		if err := os.WriteFile(path, []byte("[x]\nenabled = true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stubFail2ban(t, &fail2banStub{}, "")

	report, err := UninstallFail2ban(context.Background(), UninstallFail2banSpec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !report.NeedForce || len(report.Candidates) != 2 {
		t.Fatalf("report = %+v, want two candidates and NeedForce", report)
	}
	if _, err := os.Stat(managed); err != nil {
		t.Fatal("nothing may be deleted before --force")
	}

	report, err = UninstallFail2ban(context.Background(), UninstallFail2banSpec{Root: root, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(managed); !os.IsNotExist(err) {
		t.Fatal("--force must remove the known Idleleo name")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("--force must never remove an unknown file")
	}
	if !containsString(report.Removed, managed) {
		t.Fatalf("removed = %v, want %s", report.Removed, managed)
	}
}

func TestFail2banUnbanVerifiesLiveList(t *testing.T) {
	stubFail2ban(t, &fail2banStub{
		statusOut: "Status\n|- Number of jail:\t1\n`- Jail list:\tsshd\n",
		jails: map[string]string{
			"sshd": "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n|  `- Total failed:\t2\n`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t2\n   `- Banned IP list:\t203.0.113.7 203.0.113.8\n",
		},
	}, "")

	report, err := UnbanFail2banIP(context.Background(), "sshd", "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if !report.WasBanned || !report.Unbanned {
		t.Fatalf("report = %+v", report)
	}
	if containsString(report.RemainingIPs, "203.0.113.7") || !containsString(report.RemainingIPs, "203.0.113.8") {
		t.Fatalf("remaining = %v", report.RemainingIPs)
	}

	absent, err := UnbanFail2banIP(context.Background(), "sshd", "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	if !absent.AlreadyAbsent || absent.WasBanned {
		t.Fatalf("absent = %+v", absent)
	}

	if _, err := UnbanFail2banIP(context.Background(), "sshd", "not-an-ip"); err == nil {
		t.Fatal("an invalid IP must be rejected")
	}
	if _, err := UnbanFail2banIP(context.Background(), "missing", "203.0.113.7"); err == nil ||
		!strings.Contains(err.Error(), "is not active") {
		t.Fatalf("err = %v, want an inactive-jail error", err)
	}
}

func TestFail2banJailToggleEditsOnlyManagedFile(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	seedNginxLogs(t, root, "access.log", "sni_error.log")
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stubFail2ban(t, &fail2banStub{}, "")

	if _, err := InstallFail2ban(context.Background(), Fail2banSpec{Root: root}); err != nil {
		t.Fatal(err)
	}
	report, err := ToggleFail2banJail(context.Background(), JailToggleSpec{Root: root, Jail: "nginx-no-host"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Enabled {
		t.Fatalf("report = %+v, want disabled", report)
	}
	body := readFile(t, filepath.Join(root, "etc/fail2ban/jail.d/nginx-no-host.local"))
	if !strings.Contains(body, "enabled  = false") {
		t.Fatalf("jail file was not disabled: %s", body)
	}
	if _, err := ToggleFail2banJail(context.Background(), JailToggleSpec{Root: root, Jail: "legacy", Enable: true}); err == nil {
		t.Fatal("a jail outside the manifest must be rejected")
	}
}

func TestFail2banTrustPersistsAndRollsBackOnReloadFailure(t *testing.T) {
	root := sandbox(t)
	seedFail2banPackage(t, root)
	stubService(t, func(context.Context, ...string) error { return nil }, func(context.Context, ...string) string { return "active" })
	stub := stubFail2ban(t, &fail2banStub{
		statusOut: "`- Jail list:\tsshd\n",
		jails:     map[string]string{"sshd": "`- Banned IP list:\t\n"},
	}, "")

	report, err := Fail2banTrust(context.Background(), TrustSpec{Root: root, Jail: "sshd", Value: "203.0.113.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Applied || !report.Persisted {
		t.Fatalf("report = %+v", report)
	}
	body := readFile(t, filepath.Join(root, "etc/fail2ban/jail.d/zzz-idleleo-trust.local"))
	if !strings.Contains(body, "[sshd]") || !strings.Contains(body, "ignoreip = 203.0.113.7/32") {
		t.Fatalf("trust file = %s", body)
	}
	if !containsString(mustManifest(t, root).Files, "etc/fail2ban/jail.d/zzz-idleleo-trust.local") {
		t.Fatal("the trust file must be recorded in the manifest")
	}

	// Second value merges into the same section.
	if _, err := Fail2banTrust(context.Background(), TrustSpec{Root: root, Jail: "sshd", Value: "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	body = readFile(t, filepath.Join(root, "etc/fail2ban/jail.d/zzz-idleleo-trust.local"))
	if !strings.Contains(body, "ignoreip = 10.0.0.0/8 203.0.113.7/32") {
		t.Fatalf("trust file did not merge: %s", body)
	}

	// A failing reload must restore the previous file.
	before := body
	stub.reloadFails = true
	if _, err := Fail2banTrust(context.Background(), TrustSpec{Root: root, Jail: "sshd", Value: "192.0.2.0/24"}); err == nil {
		t.Fatal("a failed reload must be reported")
	}
	if after := readFile(t, filepath.Join(root, "etc/fail2ban/jail.d/zzz-idleleo-trust.local")); after != before {
		t.Fatalf("file was not rolled back:\n%s", after)
	}
}

func mustPaths(t *testing.T, root string) host.Paths {
	t.Helper()
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

func mustManifest(t *testing.T, root string) fail2banManifest {
	t.Helper()
	return loadFail2banManifest(mustPaths(t, root))
}
