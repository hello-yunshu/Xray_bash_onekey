package schedule

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
)

func TestCertRenewJobReportsClearAlertFailure(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(20*24*time.Hour))
	// A non-empty directory makes os.Remove fail with ENOTEMPTY, proving the
	// clear error is surfaced instead of swallowed.
	alertPath := filepath.Join(root, AlertsDirRel, "cert-renew.json")
	if err := os.MkdirAll(alertPath, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, AlertsDirRel+"/cert-renew.json/keep", "x", 0o600)

	cfg := testCertConfig()
	restoreCertHooks(t)
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(60*24*time.Hour))
		return acme.Result{Issued: true}, nil
	}
	reloadServices = func(ctx context.Context, root string) (string, error) { return "ok", nil }

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "ok" {
		t.Fatalf("clear failure must not turn a successful renewal into a failure: %+v", res)
	}
	if !strings.Contains(res.Detail, "alert not cleared") {
		t.Fatalf("detail does not report the clear failure: %q", res.Detail)
	}
}

func TestCertRenewJobReportsClearAlertFailureWhenNoRenewalIsDue(t *testing.T) {
	root := sandbox(t)
	writeCert(t, root, CertDirRel+"/xray.crt", time.Now().Add(90*24*time.Hour))
	alertPath := filepath.Join(root, AlertsDirRel, "cert-renew.json")
	if err := os.MkdirAll(alertPath, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, AlertsDirRel+"/cert-renew.json/keep", "x", 0o600)

	cfg := testCertConfig()
	restoreCertHooks(t)
	renewCertificate = func(ctx context.Context, spec acme.Config) (acme.Result, error) {
		t.Fatal("renewal must not run outside the window")
		return acme.Result{}, nil
	}
	reloadServices = func(ctx context.Context, root string) (string, error) { return "ok", nil }

	res := certRenewJob(context.Background(), root, cfg, "2026-11-12T00:00:00Z")
	if res.Result != "ok" {
		t.Fatalf("no-renewal path failed: %+v", res)
	}
	if !strings.Contains(res.Detail, "alert not cleared") {
		t.Fatalf("detail does not report the clear failure: %q", res.Detail)
	}
}

func TestRunReportsLogWarningWithoutChangingResults(t *testing.T) {
	root := sandbox(t)
	write(t, root, ConfigRel, `{"schemaVersion":1,"intervalSeconds":3600,"jobs":["auto-update"]}`, 0o600)
	// Turn the log directory into a regular file so appendLog cannot create it.
	write(t, root, "var/log/idleleo/schedule", "not a directory", 0o600)

	rep, err := Run(context.Background(), RunOptions{Root: root})
	if err != nil {
		t.Fatalf("a lost log line must not fail the run: %v", err)
	}
	if rep.LogWarning == "" {
		t.Fatal("log write failure was not reported")
	}
	if len(rep.Results) != 1 || rep.Results[0].Result != "degraded" {
		t.Fatalf("job results changed: %+v", rep.Results)
	}
	if _, err := os.Stat(path(root, StateRel)); err != nil {
		t.Fatalf("state was not written after a log failure: %v", err)
	}
}

func TestUnsafeConfigPathIsRejectedAtLoad(t *testing.T) {
	root := sandbox(t)
	write(t, root, ConfigRel, `{"schemaVersion":1,"jobs":["geodata-refresh"],"geodataDir":"../escape"}`, 0o600)

	_, err := loadConfig(root)
	if err == nil || !strings.Contains(err.Error(), `unsafe schedule config path: geodataDir "../escape"`) {
		t.Fatalf("loadConfig err=%v", err)
	}
	if _, err := Run(context.Background(), RunOptions{Root: root}); err == nil ||
		!strings.Contains(err.Error(), "unsafe schedule config path") {
		t.Fatalf("Run err=%v", err)
	}
}

func TestInstallRejectsUnsafeCertPath(t *testing.T) {
	root := sandbox(t)
	_, err := Install(context.Background(), InstallOptions{Root: root, CertFile: "../escape.crt"})
	if err == nil || !strings.Contains(err.Error(), `unsafe schedule config path: certFile "../escape.crt"`) {
		t.Fatalf("Install err=%v", err)
	}
}

func TestWriteAtomicCleansTempFilesOnFailure(t *testing.T) {
	dir := t.TempDir()
	// Renaming a file over a non-empty directory fails after the temp file was
	// written, which used to leave <target>.tmp behind.
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(target, []byte("payload"), 0o600); err == nil {
		t.Fatal("writeAtomic succeeded over a directory")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, "target.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("existing target was disturbed: %v", err)
	}
}

func TestWriteAtomicConcurrentWritersKeepOneCompleteVersion(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	versions := [][]byte{
		bytes.Repeat([]byte("a"), 64*1024),
		bytes.Repeat([]byte("b"), 64*1024),
		bytes.Repeat([]byte("c"), 64*1024),
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 10; n++ {
				if err := writeAtomic(target, versions[i%len(versions)], 0o600); err != nil {
					t.Errorf("writeAtomic: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	complete := false
	for _, v := range versions {
		if bytes.Equal(got, v) {
			complete = true
		}
	}
	if !complete {
		t.Fatalf("final file is not one complete version (len=%d)", len(got))
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, "state.json.tmp.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}
