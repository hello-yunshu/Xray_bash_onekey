package cli

import (
	"strings"
	"testing"
)

// TestUnknownFlagIsRejectedForEveryCommand proves the whitelist is wired into
// every command that owns flags, not only `schedule install`.
func TestUnknownFlagIsRejectedForEveryCommand(t *testing.T) {
	cases := [][]string{
		{"status", "--bogus"},
		{"show", "--bogus"},
		{"config", "inspect", "--bogus"},
		{"change", "set-inbound-port", "--bogus"},
		{"change", "recover", "--bogus"},
		{"xray", "generate", "--bogus"},
		{"xray", "install", "--bogus"},
		{"xray", "uninstall", "--bogus"},
		{"xray", "recover", "--bogus"},
		{"xray", "share", "--bogus"},
		{"xray", "relay", "--bogus"},
		{"xray", "user", "list", "--bogus"},
		{"xray", "user", "add", "--bogus"},
		{"xray", "cert", "issue", "--bogus"},
		{"xray", "cert", "renew", "--bogus"},
		{"bridge", "audit", "--bogus"},
		{"bridge", "prepare", "--bogus"},
		{"bridge", "validate", "--bogus"},
		{"bridge", "activate", "--bogus"},
		{"bridge", "recover", "--bogus"},
		{"bridge", "deactivate", "--bogus"},
		{"bridge", "status", "--bogus"},
		{"recover", "--bogus"},
		{"metadata", "import", "--bogus"},
		{"metadata", "export", "--bogus"},
		{"schedule", "install", "--bogus"},
		{"schedule", "remove", "--bogus"},
		{"schedule", "run", "--bogus"},
		{"schedule", "alert", "--bogus"},
		{"schedule", "status", "--bogus"},
		{"update", "status", "--bogus"},
		{"update", "check", "--bogus"},
		{"update", "configure", "--bogus"},
		{"update", "apply", "--bogus"},
		{"stats", "--bogus"},
		{"service", "status", "--bogus"},
		{"service", "start", "--bogus"},
		{"service", "logs", "--bogus"},
		{"tcp", "status", "--bogus"},
		{"tcp", "plan", "--bogus"},
		{"tcp", "apply", "--bogus"},
		{"tcp", "rollback", "--bogus"},
		{"speedtest", "--bogus"},
		{"rill", "status", "--bogus"},
	}
	root := t.TempDir()
	for _, args := range cases {
		full := append([]string{"--root", root, "--lang", "en"}, args...)
		code, _, errOut := run(t, full...)
		if code != 2 {
			t.Errorf("%v: code=%d err=%q, want 2", args, code, errOut)
			continue
		}
		if !strings.Contains(errOut, "--bogus") {
			t.Errorf("%v: err=%q does not name the unknown flag", args, errOut)
		}
	}
}

// TestMisspelledScheduleFlagNoLongerBecomesADefault is the original regression:
// a typo used to succeed with intervalSeconds=3600.
func TestMisspelledScheduleFlagNoLongerBecomesADefault(t *testing.T) {
	root := t.TempDir()
	code, _, errOut := run(t, "--root", root, "--lang", "en", "schedule", "install", "--intervall", "60")
	if code != 2 {
		t.Fatalf("code=%d err=%q, want 2", code, errOut)
	}
	if !strings.Contains(errOut, "--intervall") {
		t.Fatalf("stderr does not name --intervall: %q", errOut)
	}
}

// TestKnownFlagFormsAreAccepted covers the spellings scripts and operators use:
// double dash, single dash, --name=value, and positional arguments after "--".
func TestKnownFlagFormsAreAccepted(t *testing.T) {
	root := fixture(t)
	for _, args := range [][]string{
		{"config", "inspect", "--path", "etc/idleleo/conf/xray/config.json", "--json"},
		{"config", "inspect", "-path", "etc/idleleo/conf/xray/config.json", "-json"},
		{"config", "inspect", "--path=etc/idleleo/conf/xray/config.json", "--json"},
		{"config", "inspect", "--json", "--", "--this-is-positional"},
		{"schedule", "status"},
	} {
		full := append([]string{"--root", root, "--lang", "en"}, args...)
		code, out, errOut := run(t, full...)
		if code != 0 {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestFlagValueSupportsInlineValues(t *testing.T) {
	args := []string{"--path=a/b", "-json", "--flag", "value"}
	if got := flagValue(args, "--path"); got != "a/b" {
		t.Fatalf("inline value: %q", got)
	}
	if !hasFlag(args, "--json") {
		t.Fatal("single-dash boolean flag not detected")
	}
	if got := flagValue(args, "--flag"); got != "value" {
		t.Fatalf("separate value: %q", got)
	}
	if got := flagValue([]string{"-1", "--flag"}, "--flag"); got != "" {
		t.Fatalf("negative number treated as value: %q", got)
	}
}

func TestStatsRejectsUnsafePathOverrides(t *testing.T) {
	root := fixture(t)
	for _, path := range []string{"/etc/passwd", "../escape", "etc/../../escape"} {
		code, _, errOut := run(t, "--root", root, "--lang", "en", "stats", "--path", path)
		if code != 2 {
			t.Errorf("--path %q: code=%d err=%q, want 2", path, code, errOut)
		}
		if !strings.Contains(errOut, "relative path inside --root") {
			t.Errorf("--path %q: err=%q", path, errOut)
		}
	}
}

func TestStatsRejectsInvalidTimeout(t *testing.T) {
	root := fixture(t)
	for _, value := range []string{"nonsense", "0s", "-5s"} {
		code, _, errOut := run(t, "--root", root, "--lang", "en", "stats", "--timeout", value)
		if code != 2 {
			t.Errorf("--timeout %q: code=%d err=%q, want 2", value, code, errOut)
		}
		if !strings.Contains(errOut, "invalid --timeout") {
			t.Errorf("--timeout %q: err=%q", value, errOut)
		}
	}
}
