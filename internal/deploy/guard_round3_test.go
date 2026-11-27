package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

func stubInspectNginxProcess(t *testing.T, fn func(bin string, pid int) (nginxProcess, error)) {
	t.Helper()
	old := inspectNginxProcess
	inspectNginxProcess = fn
	t.Cleanup(func() { inspectNginxProcess = old })
}

func seedRunningNginx(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(root, "usr/local/nginx/sbin/nginx")
	writeGuardTestFile(t, bin, []byte("#!/bin/sh\n"))
	writeGuardTestFile(t, filepath.Join(root, "usr/local/nginx/logs/nginx.pid"), []byte("4242\n"))
	return bin
}

// D04 repro: the managed master is alive, but the policy files were edited
// afterwards and never reloaded. This must not be reported as active.
func TestInspectSNIGuardDoesNotClaimActiveWithoutReloadProof(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	bin := seedRunningNginx(t, root)
	stubInspectNginxProcess(t, func(gotBin string, pid int) (nginxProcess, error) {
		return nginxProcess{Alive: true, Exe: gotBin, Started: time.Now().Add(-time.Hour)}, nil
	})
	// A hand edit after the master started. The content change also invalidates
	// any reload record that was bound to the previous fragment.
	frag := filepath.Join(root, nginxDirRel, "03-isolate.conf")
	writeGuardTestFile(t, frag, []byte(isolateFragment()+"# hand edit after reload\n"))
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(frag, future, future); err != nil {
		t.Fatal(err)
	}

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "runtime-unverified" {
		t.Fatalf("an unreloaded policy change must not be active: %+v", st)
	}
	if !strings.Contains(strings.Join(st.Warnings, " "), "no verified reload record") {
		t.Fatalf("the operator must be told why the policy is unverified: %v", st.Warnings)
	}
	if !st.MetadataSynced {
		t.Fatal("metadata still matches the files here; only the runtime is unverified")
	}
	_ = bin
}

func TestInspectSNIGuardDoesNotInferLoadedContentFromStartTime(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	seedRunningNginx(t, root)
	stubInspectNginxProcess(t, func(bin string, pid int) (nginxProcess, error) {
		return nginxProcess{Alive: true, Exe: bin, Started: time.Now().Add(time.Minute)}, nil
	})

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "runtime-unverified" {
		t.Fatalf("process start time cannot prove loaded policy content: %+v", st)
	}
}

func TestInspectSNIGuardReportsActiveAfterVerifiedReloadRecord(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	seedRunningNginx(t, root)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeGuardRuntimeRecord(paths, SNIPolicyIsolate, guardRuntimeEvidence(paths), 4242, 12345); err != nil {
		t.Fatal(err)
	}
	stubInspectNginxProcess(t, func(bin string, pid int) (nginxProcess, error) {
		return nginxProcess{Alive: true, Exe: bin, Started: time.Now().Add(-time.Hour), PID: 4242, StartTicks: 12345}, nil
	})

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "active" {
		t.Fatalf("a content-bound reload record proves the load: %+v", st)
	}
}

func TestInspectSNIGuardRejectsForeignProcess(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	seedRunningNginx(t, root)
	stubInspectNginxProcess(t, func(bin string, pid int) (nginxProcess, error) {
		return nginxProcess{Alive: true, Exe: "/usr/bin/sleep", Started: time.Now().Add(time.Hour)}, nil
	})

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "runtime-unverified" {
		t.Fatalf("an unrelated pid must not prove the managed Nginx policy: %+v", st)
	}
}

// D04 (round 4): a reload record from a previous master must not survive a
// restart or pid reuse. The record is bound to pid + kernel start ticks.
func TestInspectSNIGuardRejectsReloadRecordFromAnotherProcessInstance(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	seedRunningNginx(t, root)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	// Same pid, same content, but the recorded start ticks belong to the old
	// process that has since been replaced.
	if err := writeGuardRuntimeRecord(paths, SNIPolicyIsolate, guardRuntimeEvidence(paths), 4242, 111); err != nil {
		t.Fatal(err)
	}
	stubInspectNginxProcess(t, func(bin string, pid int) (nginxProcess, error) {
		return nginxProcess{Alive: true, Exe: bin, Started: time.Now().Add(-time.Hour), PID: 4242, StartTicks: 999}, nil
	})

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "runtime-unverified" {
		t.Fatalf("a reload record from another process instance must not prove active: %+v", st)
	}
}

// The kernel start time must come from /proc/<pid>/stat, not the /proc/<pid>
// directory mtime.
func TestProcessStartTimeComesFromProcStat(t *testing.T) {
	ticks, started, err := processStartTime(os.Getpid())
	if err != nil {
		t.Skipf("no usable /proc on this host: %v", err)
	}
	if ticks == 0 {
		t.Fatal("start ticks must be non-zero for a live process")
	}
	if started.IsZero() || started.After(time.Now().Add(time.Minute)) {
		t.Fatalf("implausible process start time %v", started)
	}
}

func TestNginxWorkerGenerationRequiresANewDirectChild(t *testing.T) {
	masterPID := os.Getpid()
	masterTicks, _, err := processStartTime(masterPID)
	if err != nil {
		t.Skipf("no usable /proc on this host: %v", err)
	}
	baselineChild := exec.Command("sleep", "2")
	if err := baselineChild.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = baselineChild.Process.Kill()
		_ = baselineChild.Wait()
	})
	previous, err := nginxWorkerIdentities(masterPID)
	if err != nil {
		t.Skipf("cannot inspect current process children: %v", err)
	}
	child := exec.Command("sleep", "2")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	if err := waitNginxWorkerGeneration(context.Background(), masterPID, masterTicks, previous, time.Second); err != nil {
		t.Fatalf("a new live child should confirm the process generation: %v", err)
	}
}

func TestInspectSNIGuardMetadataSyncedFalseOnDrift(t *testing.T) {
	root := seedGuardInstall(t)
	if _, err := SetSNIGuard(context.Background(), SNIGuardSpec{Root: root, Policy: SNIPolicyIsolate}); err != nil {
		t.Fatal(err)
	}
	meta := loadGuardTestMetadata(t, root)
	meta.SNIGuard.Policy = SNIPolicyReject
	writeGuardTestFile(t, filepath.Join(root, "etc/idleleo/v1/metadata.json"), mustJSON(t, meta))

	st, err := InspectSNIGuard(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "drift" || st.MetadataSynced {
		t.Fatalf("metadata must not be reported as synced while it drifts: %+v", st)
	}
}
