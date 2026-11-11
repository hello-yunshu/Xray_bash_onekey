package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
)

func captureCertSpec(t *testing.T, args ...string) acme.Config {
	t.Helper()
	origIssue, origRenew := acmeIssueFn, acmeRenewFn
	t.Cleanup(func() { acmeIssueFn, acmeRenewFn = origIssue, origRenew })

	var captured acme.Config
	stub := func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		captured = spec
		return acme.Result{Domain: spec.Domain, Issued: true}, nil
	}
	acmeIssueFn, acmeRenewFn = stub, stub

	var out, errOut bytes.Buffer
	code := xrayCert(context.Background(),
		Options{Out: &out, Err: &errOut}, config{root: "/", lang: "en"},
		append([]string{"issue", "--domain", "example.com", "--webroot", "/tmp/web",
			"--cert-out", "/tmp/xray.crt", "--key-out", "/tmp/xray.key"}, args...))
	if code != 0 {
		t.Fatalf("xrayCert code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	return captured
}

func TestCertDefaultsToStaging(t *testing.T) {
	spec := captureCertSpec(t)
	if spec.DirectoryURL != schedule.ACMEStagingDirectory {
		t.Fatalf("directory=%q", spec.DirectoryURL)
	}
}

func TestCertProductionFlag(t *testing.T) {
	spec := captureCertSpec(t, "--production")
	if spec.DirectoryURL != schedule.ACMEProductionDirectory {
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
