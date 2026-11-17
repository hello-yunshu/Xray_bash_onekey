package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
)

func captureCertSpec(t *testing.T, args ...string) acme.Config {
	t.Helper()
	spec, _ := captureCertRun(t, args...)
	return spec
}

func captureCertRun(t *testing.T, args ...string) (acme.Config, string) {
	t.Helper()
	origIssue, origRenew, origPreflight := acmeIssueFn, acmeRenewFn, acmePreflightFn
	t.Cleanup(func() { acmeIssueFn, acmeRenewFn, acmePreflightFn = origIssue, origRenew, origPreflight })

	var captured acme.Config
	stub := func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		captured = spec
		return acme.Result{Domain: spec.Domain, Issued: true}, nil
	}
	acmeIssueFn, acmeRenewFn = stub, stub
	acmePreflightFn = func(context.Context, acme.Config) error { return nil }

	var out, errOut bytes.Buffer
	code := xrayCert(context.Background(),
		Options{Out: &out, Err: &errOut}, config{root: "/", lang: "en"},
		append([]string{"issue", "--domain", "example.com", "--webroot", "/tmp/web",
			"--cert-out", "/tmp/xray.crt", "--key-out", "/tmp/xray.key"}, args...))
	if code != 0 {
		t.Fatalf("xrayCert code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	return captured, out.String()
}

func TestCertDefaultsToStaging(t *testing.T) {
	spec := captureCertSpec(t)
	if spec.DirectoryURL != acme.StagingDirectory {
		t.Fatalf("directory=%q", spec.DirectoryURL)
	}
}

func TestCertProductionFlag(t *testing.T) {
	spec := captureCertSpec(t, "--production")
	if spec.DirectoryURL != acme.ProductionDirectory {
		t.Fatalf("directory=%q", spec.DirectoryURL)
	}
}

func TestCertDirectoryEnvOverride(t *testing.T) {
	t.Setenv("IDLELEO_ACME_DIRECTORY", "https://ca.example/dir")
	spec := captureCertSpec(t)
	if spec.DirectoryURL != "https://ca.example/dir" {
		t.Fatalf("directory=%q", spec.DirectoryURL)
	}
}

func TestCertExplicitDirectoryWins(t *testing.T) {
	t.Setenv("IDLELEO_ACME_DIRECTORY", "https://ca.example/dir")
	spec := captureCertSpec(t, "--directory", "https://explicit.example/dir")
	if spec.DirectoryURL != "https://explicit.example/dir" {
		t.Fatalf("directory=%q", spec.DirectoryURL)
	}
}

func TestCertAccountStateDefaultsOutsideCertTree(t *testing.T) {
	spec := captureCertSpec(t)
	wantKey := "/etc/idleleo/acme/account.key"
	wantState := "/etc/idleleo/acme/account.json"
	if spec.AccountKeyFile != wantKey || spec.StateFile != wantState {
		t.Fatalf("account paths = %q, %q; want %q, %q",
			spec.AccountKeyFile, spec.StateFile, wantKey, wantState)
	}
}

func TestCertProductionRunsStagingPreflightByDefault(t *testing.T) {
	origIssue, origPreflight := acmeIssueFn, acmePreflightFn
	t.Cleanup(func() { acmeIssueFn, acmePreflightFn = origIssue, origPreflight })
	calls := 0
	acmeIssueFn = func(_ context.Context, spec acme.Config) (acme.Result, error) {
		return acme.Result{Domain: spec.Domain, Issued: true}, nil
	}
	acmePreflightFn = func(_ context.Context, spec acme.Config) error {
		calls++
		if spec.DirectoryURL != acme.ProductionDirectory {
			t.Fatalf("preflight directory=%q", spec.DirectoryURL)
		}
		return nil
	}
	var out, errOut bytes.Buffer
	code := xrayCert(context.Background(),
		Options{Out: &out, Err: &errOut}, config{root: "/", lang: "en"},
		[]string{"issue", "--domain", "example.com", "--webroot", "/tmp/web",
			"--cert-out", "/tmp/xray.crt", "--key-out", "/tmp/xray.key", "--production"})
	if code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if calls != 1 {
		t.Fatalf("staging preflight calls = %d, want 1", calls)
	}
}

func runCertExpectPreflight(t *testing.T, want bool, extra ...string) {
	t.Helper()
	origIssue, origPreflight := acmeIssueFn, acmePreflightFn
	t.Cleanup(func() { acmeIssueFn, acmePreflightFn = origIssue, origPreflight })
	acmeIssueFn = func(_ context.Context, spec acme.Config) (acme.Result, error) {
		return acme.Result{Domain: spec.Domain, Issued: true}, nil
	}
	called := false
	acmePreflightFn = func(context.Context, acme.Config) error { called = true; return nil }

	var out, errOut bytes.Buffer
	args := append([]string{"issue", "--domain", "example.com", "--webroot", "/tmp/web",
		"--cert-out", "/tmp/xray.crt", "--key-out", "/tmp/xray.key", "--production"}, extra...)
	if code := xrayCert(context.Background(), Options{Out: &out, Err: &errOut},
		config{root: "/", lang: "en"}, args); code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if called != want {
		t.Fatalf("staging preflight called=%v, want %v", called, want)
	}
}

func TestCertNoStagingCheckSkipsPreflight(t *testing.T) {
	runCertExpectPreflight(t, false, "--no-staging-check")
}

func TestCertExplicitDirectorySkipsPreflight(t *testing.T) {
	runCertExpectPreflight(t, false, "--directory", "https://harness.example/dir")
}

func TestCertRenewDryRunDoesNotContactCA(t *testing.T) {
	origIssue, origRenew, origPreflight := acmeIssueFn, acmeRenewFn, acmePreflightFn
	t.Cleanup(func() { acmeIssueFn, acmeRenewFn, acmePreflightFn = origIssue, origRenew, origPreflight })
	acmeIssueFn = func(context.Context, acme.Config) (acme.Result, error) {
		t.Fatal("issue must not run during dry-run")
		return acme.Result{}, nil
	}
	acmeRenewFn = func(context.Context, acme.Config) (acme.Result, error) {
		t.Fatal("renew must not run during dry-run")
		return acme.Result{}, nil
	}
	acmePreflightFn = func(context.Context, acme.Config) error { return nil }

	var out, errOut bytes.Buffer
	code := xrayCert(context.Background(),
		Options{Out: &out, Err: &errOut}, config{root: "/", lang: "en"},
		[]string{"renew", "--domain", "example.com", "--webroot", "/tmp/web",
			"--cert-out", "/tmp/idleleo-missing-test.crt", "--key-out", "/tmp/idleleo-missing-test.key",
			"--dry-run"})
	if code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	got := out.String()
	for _, want := range []string{"state=missing", "challenge: http-01", "directory:", "reload:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, got)
		}
	}
}

// A user-managed pair without --takeover is refused by Issue, so the CLI must
// not spend a staging order before failing.
func TestCertUserManagedSkipsStagingPreflight(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "xray.crt")
	if err := acme.MarkUserManaged(certFile); err != nil {
		t.Fatal(err)
	}

	origIssue, origPreflight := acmeIssueFn, acmePreflightFn
	t.Cleanup(func() { acmeIssueFn, acmePreflightFn = origIssue, origPreflight })
	issueCalls := 0
	acmeIssueFn = func(_ context.Context, spec acme.Config) (acme.Result, error) {
		issueCalls++
		return acme.Result{Domain: spec.Domain, Issued: true}, nil
	}
	preflightCalls := 0
	acmePreflightFn = func(context.Context, acme.Config) error {
		preflightCalls++
		return nil
	}

	var out, errOut bytes.Buffer
	code := xrayCert(context.Background(),
		Options{Out: &out, Err: &errOut}, config{root: "/", lang: "en"},
		[]string{"issue", "--domain", "example.com", "--webroot", "/tmp/web",
			"--cert-out", certFile, "--key-out", filepath.Join(dir, "xray.key"),
			"--production"})
	if code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if preflightCalls != 0 || issueCalls != 1 {
		t.Fatalf("preflight=%d issue=%d, want 0/1", preflightCalls, issueCalls)
	}
}

// --takeover means the operator asked this manager to adopt the pair, so the
// staging preflight must run again before the production order.
func TestCertTakeoverRunsStagingPreflight(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "xray.crt")
	if err := acme.MarkUserManaged(certFile); err != nil {
		t.Fatal(err)
	}

	origIssue, origPreflight := acmeIssueFn, acmePreflightFn
	t.Cleanup(func() { acmeIssueFn, acmePreflightFn = origIssue, origPreflight })
	acmeIssueFn = func(_ context.Context, spec acme.Config) (acme.Result, error) {
		if !spec.Takeover {
			t.Fatal("spec.Takeover = false, want true")
		}
		return acme.Result{Domain: spec.Domain, Issued: true}, nil
	}
	preflightCalls := 0
	acmePreflightFn = func(context.Context, acme.Config) error {
		preflightCalls++
		return nil
	}

	var out, errOut bytes.Buffer
	code := xrayCert(context.Background(),
		Options{Out: &out, Err: &errOut}, config{root: "/", lang: "en"},
		[]string{"issue", "--domain", "example.com", "--webroot", "/tmp/web",
			"--cert-out", certFile, "--key-out", filepath.Join(dir, "xray.key"),
			"--production", "--takeover"})
	if code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if preflightCalls != 1 {
		t.Fatalf("preflight=%d, want 1", preflightCalls)
	}
}
