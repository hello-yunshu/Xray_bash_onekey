package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--bridge-self-check" {
		fmt.Printf("{\"protocol\":%q,\"schema\":2,\"goos\":%q,\"goarch\":%q}\n", Protocol, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func put(t *testing.T, root, rel string, data []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, data, mode); e != nil {
		t.Fatal(e)
	}
}
func fixture(t *testing.T, kind string) string {
	t.Helper()
	root := t.TempDir()
	put(t, root, sandboxMarker, []byte(markerValue+"\n"), 0600)
	put(t, root, "etc/idleleo/install.sh", []byte("#!/bin/sh\necho legacy\n"), 0700)
	e := os.MkdirAll(filepath.Join(root, "usr/bin"), 0700)
	if e != nil {
		t.Fatal(e)
	}
	e = os.Symlink("../../etc/idleleo/install.sh", filepath.Join(root, entryFile))
	if e != nil {
		t.Fatal(e)
	}
	if kind == "relay" {
		put(t, root, legacyConfig, []byte(`{"role":"relay","tls":"None","relay_backend_host":"192.0.2.10","relay_backend_port":"443","relay_listen_port":"9443"}`), 0600)
		put(t, root, relayConfig, []byte("stream {server {listen 9443; proxy_pass 192.0.2.10:443; }}\n"), 0600)
	} else {
		mode := "Reality"
		shell := "Reality"
		if kind == "tls" {
			mode = "TLS"
			shell = "Nginx+ws+TLS"
		}
		if kind == "xtls" {
			mode = "None"
			shell = "XTLS ONLY"
		}
		legacy := fmt.Sprintf(`{"shell_mode":%q,"tls":%q,"transport_mode":"onlyws","id":"11111111-1111-4111-8111-111111111111","privateKey":"SYNTHETIC_SECRET","password":"DO_NOT_DUPLICATE","unknownExtension":{"preserve":true}}`, shell, mode)
		put(t, root, legacyConfig, []byte(legacy), 0600)
		native := `{"inbounds":[{"tag":"VLESS-Reality-in","settings":{"clients":[{"id":"11111111-1111-4111-8111-111111111111"},{"id":"22222222-2222-4222-8222-222222222222"}]},"streamSettings":{"security":"reality","realitySettings":{"privateKey":"SYNTHETIC_SECRET","shortIds":["abcdef12"]}}}],"outbounds":[{"protocol":"freedom","tag":"custom"}],"routing":{"rules":[{"outboundTag":"custom"}]}}`
		if kind == "tls" {
			native = `{"inbounds":[{"tag":"VLESS-ws-in","settings":{"clients":[{"id":"11111111-1111-4111-8111-111111111111"}]},"streamSettings":{"security":"none","network":"ws"}}]}`
		}
		put(t, root, nativeXray, []byte(native), 0600)
	}
	return root
}
func stage(t *testing.T, root string) string {
	t.Helper()
	src, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(src)
	if e != nil {
		t.Fatal(e)
	}
	put(t, root, candidateFile, b, 0700)
	return digest(b)
}
func prep(t *testing.T, root string) Journal {
	t.Helper()
	pin := stage(t, root)
	j, e := Prepare(root, pin, "")
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func readBytes(t *testing.T, root, rel string) []byte {
	t.Helper()
	b, e := file(root, rel)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestInspectNoWriteAndRedactedMetadata(t *testing.T) {
	root := fixture(t, "reality")
	p, e := Inspect(root)
	if e != nil {
		t.Fatal(e)
	}
	if p.Role != "node" || p.TLS != "Reality" {
		t.Fatal(p)
	}
	if _, e = os.Stat(filepath.Join(root, journalFile)); !os.IsNotExist(e) {
		t.Fatal("inspect wrote journal")
	}
	old := readBytes(t, root, nativeXray)
	prep(t, root)
	cfg := readBytes(t, root, managerConfig)
	for _, s := range []string{"SYNTHETIC_SECRET", "DO_NOT_DUPLICATE", "11111111-1111"} {
		if strings.Contains(string(cfg), s) {
			t.Errorf("secret material copied: %s", s)
		}
	}
	if digest(old) != digest(readBytes(t, root, nativeXray)) {
		t.Fatal("runtime changed")
	}
}
func TestRelayAndTLS(t *testing.T) {
	for _, kind := range []string{"relay", "tls"} {
		t.Run(kind, func(t *testing.T) {
			root := fixture(t, kind)
			p, e := Inspect(root)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "relay" && p.Role != "relay" {
				t.Fatal(p)
			}
			prep(t, root)
		})
	}
}
func TestXTLSAndInvalidNodeRejected(t *testing.T) {
	root := fixture(t, "xtls")
	if _, e := Inspect(root); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
	root = fixture(t, "reality")
	put(t, root, nativeXray, []byte(`{"inbounds":[{}]}`), 0600)
	if _, e := Inspect(root); !errors.Is(e, ErrUnsupported) {
		t.Fatal(e)
	}
}
func TestHappyCandidateCommitWithRelativeEntrypoint(t *testing.T) {
	root := fixture(t, "reality")
	old := readBytes(t, root, nativeXray)
	prep(t, root)
	j, e := Activate(root, "")
	if e != nil || j.State != "COMMITTED" {
		t.Fatalf("%+v %v", j, e)
	}
	if !entryCandidate(root) {
		t.Fatal("entry not candidate")
	}
	status, e := Status(root)
	if e != nil || !status.RuntimeUntouched || !status.EntryIsGo {
		t.Fatal(status, e)
	}
	entry := filepath.Join(root, entryFile)
	out, e := exec.Command(entry, "--bridge-self-check").Output()
	if e != nil || !strings.Contains(string(out), Protocol) {
		t.Fatalf("entry not runnable %v %s", e, out)
	}
	if digest(readBytes(t, root, nativeXray)) != digest(old) {
		t.Fatal("runtime touched")
	}
}
func TestAfterSwapRecoveryAndIdempotency(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	_, e := Activate(root, "after-swap")
	if !errors.Is(e, ErrInterrupted) {
		t.Fatal(e)
	}
	j, e := Recover(root)
	if e != nil || j.State != "ROLLED_BACK" {
		t.Fatal(j, e)
	}
	j, e = Recover(root)
	if e != nil || j.State != "ROLLED_BACK" {
		t.Fatal(j, e)
	}
	h, e := Status(root)
	if e != nil || !h.EntryIsLegacy || h.ManagerPresent || !h.RuntimeUntouched {
		t.Fatal(h, e)
	}
}
func TestInterruptedPrepareBeforeOrAfterManagerWrite(t *testing.T) {
	for _, fault := range []string{"after-journal", "after-config"} {
		t.Run(fault, func(t *testing.T) {
			root := fixture(t, "reality")
			pin := stage(t, root)
			_, e := Prepare(root, pin, fault)
			if !errors.Is(e, ErrInterrupted) {
				t.Fatal(e)
			}
			j, e := Recover(root)
			if e != nil || j.State != "ROLLED_BACK" {
				t.Fatal(j, e)
			}
			if !entryOriginal(root, j) {
				t.Fatal("entry changed")
			}
		})
	}
}
func TestAfterActivatingBeforeSwapRecovery(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	_, e := Activate(root, "after-activating")
	if !errors.Is(e, ErrInterrupted) {
		t.Fatal(e)
	}
	j, e := Recover(root)
	if e != nil || j.State != "ROLLED_BACK" || !entryOriginal(root, j) {
		t.Fatal(j, e)
	}
}
func TestTextExecutableRejected(t *testing.T) {
	root := fixture(t, "reality")
	b := []byte("#!/bin/sh\necho NOT_A_GO_MANAGER\n")
	put(t, root, candidateFile, b, 0700)
	if _, e := Prepare(root, digest(b), ""); e == nil {
		t.Fatal("text candidate was accepted")
	}
}
func TestBadPinRejected(t *testing.T) {
	root := fixture(t, "reality")
	stage(t, root)
	if _, e := Prepare(root, strings.Repeat("0", 64), ""); e == nil {
		t.Fatal("bad pin accepted")
	}
}
func TestCandidateChangeAfterPrepareRejected(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	put(t, root, candidateFile, []byte("new candidate"), 0700)
	if _, e := Activate(root, ""); e == nil {
		t.Fatal("candidate drift accepted")
	}
}
func TestEntrypointChangeAfterPrepareRejected(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	p := filepath.Join(root, entryFile)
	os.Remove(p)
	put(t, root, entryFile, []byte("#!/bin/sh\necho unrelated\n"), 0700)
	if _, e := Activate(root, ""); e == nil {
		t.Fatal("entry drift accepted")
	}
}
func TestRecoverRefusesOverwriteUnrelatedEntry(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	_, e := Activate(root, "after-swap")
	if !errors.Is(e, ErrInterrupted) {
		t.Fatal(e)
	}
	p := filepath.Join(root, entryFile)
	os.Remove(p)
	put(t, root, entryFile, []byte("#!/bin/sh\necho unrelated\n"), 0700)
	j, e := Recover(root)
	if !errors.Is(e, ErrRecoveryRequired) || j.State != "RECOVERY_REQUIRED" {
		t.Fatal(j, e)
	}
	b := readBytes(t, root, entryFile)
	if !strings.Contains(string(b), "unrelated") {
		t.Fatal("unrelated data overwritten")
	}
}
func TestRuntimeDriftRejected(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	b := readBytes(t, root, nativeXray)
	put(t, root, nativeXray, append(b, ' '), 0600)
	if _, e := Activate(root, ""); e == nil {
		t.Fatal("runtime drift accepted")
	}
}
func TestManagerDriftRejected(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	put(t, root, managerConfig, []byte(`{}`), 0600)
	if _, e := Activate(root, ""); e == nil {
		t.Fatal("manager drift accepted")
	}
}
func TestRecoveryDoesNotDeleteModifiedManager(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	put(t, root, managerConfig, []byte(`{"owner":"someone else"}`), 0600)
	j, e := Recover(root)
	if !errors.Is(e, ErrRecoveryRequired) || j.State != "RECOVERY_REQUIRED" {
		t.Fatal(j, e)
	}
	if !strings.Contains(string(readBytes(t, root, managerConfig)), "someone else") {
		t.Fatal("manager overwritten")
	}
}
func TestCommittedRecoveryIsNotImplicit(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	if _, e := Activate(root, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := Recover(root); e == nil {
		t.Fatal("commit was reverted")
	}
}
func TestNoMarkerAndRootPath(t *testing.T) {
	root := t.TempDir()
	if _, e := Root(root); e == nil {
		t.Fatal("missing marker accepted")
	}
	if _, e := Root("/"); e == nil {
		t.Fatal("root accepted")
	}
}
func TestSymlinkParentRejected(t *testing.T) {
	root := fixture(t, "reality")
	os.RemoveAll(filepath.Join(root, "var"))
	os.Symlink(t.TempDir(), filepath.Join(root, "var"))
	pin := stage(t, root)
	if _, e := Prepare(root, pin, ""); e == nil {
		t.Fatal("symlink parent accepted")
	}
}
func TestLockRefusesConcurrentOperations(t *testing.T) {
	root := fixture(t, "reality")
	unlock, e := takeLock(root)
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	pin := stage(t, root)
	if _, e := Prepare(root, pin, ""); e == nil {
		t.Fatal("second concurrent actor acquired lock")
	}
}
func TestLegacyRegularExecutableBackedUpOutsideJournal(t *testing.T) {
	root := fixture(t, "reality")
	entry := filepath.Join(root, entryFile)
	os.Remove(entry)
	put(t, root, entryFile, []byte("#!/bin/sh\necho original manager\n"), 0700)
	j := prep(t, root)
	raw, e := os.ReadFile(filepath.Join(root, journalFile))
	if e != nil {
		t.Fatal(e)
	}
	var parsed map[string]any
	if json.Unmarshal(raw, &parsed) != nil {
		t.Fatal("bad journal")
	}
	if strings.Contains(string(raw), "original manager") {
		t.Fatal("raw backup is embedded in journal")
	}
	if _, e := Activate(root, "after-swap"); !errors.Is(e, ErrInterrupted) {
		t.Fatal(e)
	}
	j, e = Recover(root)
	if e != nil || j.State != "ROLLED_BACK" {
		t.Fatal(j, e)
	}
	if !strings.Contains(string(readBytes(t, root, entryFile)), "original manager") {
		t.Fatal("regular entry not restored")
	}
}
func TestNoSecretInError(t *testing.T) {
	root := fixture(t, "reality")
	p, e := Inspect(root)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := JSON(p)
	if strings.Contains(string(b), "SYNTHETIC_SECRET") {
		t.Fatal("metadata leak")
	}
}
func TestPreparedManagerMode0600(t *testing.T) {
	root := fixture(t, "reality")
	prep(t, root)
	fi, e := os.Stat(filepath.Join(root, managerConfig))
	if e != nil || fi.Mode().Perm() != 0600 {
		t.Fatal(fi, e)
	}
}

var _ io.Reader
