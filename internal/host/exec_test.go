package host

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunTimeoutSurvivesChildHoldingStdout pins the WaitDelay behaviour: a shim
// that forks `sleep` keeps the stdout pipe open, which used to defeat the
// timeout and block until the child exited.
func TestRunTimeoutSurvivesChildHoldingStdout(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "forking-shim")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := Run(context.Background(), ExecSpec{Path: bin, Timeout: 200 * time.Millisecond})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Run blocked for %s; timeout not enforced", elapsed)
	}
	if err == nil || !res.TimedOut {
		t.Fatalf("err=%v timedOut=%v, want timeout error", err, res.TimedOut)
	}
}

// TestRedactKeepsNginxConfigureArguments proves the redaction pass does not eat
// the diagnostic we depend on in deploy.streamModule.
func TestRedactKeepsNginxConfigureArguments(t *testing.T) {
	in := "nginx version: nginx/1.24.0 (Ubuntu)\n" +
		"built with OpenSSL 3.0.13\n" +
		"configure arguments: --prefix=/usr/share/nginx --with-stream=dynamic " +
		"--with-stream_ssl_module --with-http_ssl_module --user=www-data --pid-path=/run/nginx.pid\n"
	out := redact(in)
	if !strings.Contains(out, "--with-stream=dynamic") {
		t.Fatalf("redaction removed the module marker: %q", out)
	}
}
