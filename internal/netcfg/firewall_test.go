package netcfg

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// fakeNetfilter is an in-memory ruleset that understands exactly the command
// forms netcfg emits, so the transaction logic is exercised without root.
type fakeNetfilter struct {
	rules  map[string]bool
	failOn string
	calls  int
}

func newFakeNetfilter() *fakeNetfilter {
	return &fakeNetfilter{rules: map[string]bool{}}
}

func ruleKey(bin string, args []string) string {
	return bin + "|" + strings.Join(args[1:], " ")
}

func (f *fakeNetfilter) run(_ context.Context, c Command) (string, int, error) {
	f.calls++
	line := c.String()
	if f.failOn != "" && strings.Contains(line, f.failOn) {
		f.failOn = ""
		return "", 1, nil
	}
	if strings.HasSuffix(c.Bin, "-save") {
		return f.dump(c.Bin), 0, nil
	}
	if len(c.Args) == 0 {
		return "", 1, nil
	}
	key := ruleKey(c.Bin, c.Args)
	switch c.Args[0] {
	case "-C":
		if f.rules[key] {
			return "", 0, nil
		}
		return "", 1, nil
	case "-I", "-A":
		f.rules[key] = true
		return "", 0, nil
	case "-D":
		if f.rules[key] {
			delete(f.rules, key)
			return "", 0, nil
		}
		return "", 1, nil
	}
	return "", 1, nil
}

func (f *fakeNetfilter) dump(bin string) string {
	var lines []string
	for key := range f.rules {
		parts := strings.SplitN(key, "|", 2)
		if parts[0] != strings.TrimSuffix(bin, "-save") {
			continue
		}
		lines = append(lines, "-A "+parts[1])
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func joinInts(in []int) string {
	parts := make([]string, 0, len(in))
	for _, n := range in {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}

func setupFW(t *testing.T) (string, *fakeNetfilter) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"etc/idleleo", "usr/local/bin"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".idleleo-phase01-sandbox"),
		[]byte("I_ACCEPT_DISPOSABLE_SANDBOX\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fw := newFakeNetfilter()
	oldRun, oldTool := runCommand, toolAvailable
	runCommand = fw.run
	toolAvailable = func(string) bool { return true }
	t.Cleanup(func() {
		runCommand = oldRun
		toolAvailable = oldTool
	})
	return root, fw
}

func mustApply(t *testing.T, root string, spec Spec) Report {
	t.Helper()
	spec.Root = root
	report, err := Apply(context.Background(), spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return report
}

func TestFamiliesForMode(t *testing.T) {
	cases := []struct {
		mode   string
		hasV6  bool
		wanted []string
	}{
		{"ipv6", true, []string{FamilyV6}},
		{"dual", false, []string{FamilyV4, FamilyV6}},
		{"ipv4", true, []string{FamilyV4}},
		{"manual", true, []string{FamilyV4}},
		{"auto", true, []string{FamilyV4, FamilyV6}},
		{"auto", false, []string{FamilyV4}},
		{"", false, []string{FamilyV4}},
	}
	for _, tc := range cases {
		got := FamiliesForMode(tc.mode, tc.hasV6)
		if strings.Join(got, ",") != strings.Join(tc.wanted, ",") {
			t.Errorf("FamiliesForMode(%q,%t) = %v, want %v", tc.mode, tc.hasV6, got, tc.wanted)
		}
	}
}

func TestParsePortList(t *testing.T) {
	got, err := ParsePortList("8443,443,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("ports = %v, want [443 8443]", got)
	}
	for _, bad := range []string{"0", "65536", "abc", "443,,8443", "-1"} {
		if _, err := ParsePortList(bad); err == nil {
			t.Errorf("ParsePortList(%q) accepted an invalid list", bad)
		}
	}
	empty, err := ParsePortList("  ")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list = %v, %v", empty, err)
	}
}

func TestApplyReconcilesDiffAndPersists(t *testing.T) {
	root, fw := setupFW(t)
	mustApply(t, root, Spec{New: NewPorts([]int{443}, []int{443}), Mode: "auto"})
	if len(fw.rules) != 8 {
		t.Fatalf("rules = %d, want 8 (2 families x 2 protos x 2 chains)", len(fw.rules))
	}
	ports, fams, installed, err := loadState(root)
	if err != nil || !installed {
		t.Fatalf("state: installed=%t err=%v", installed, err)
	}
	if joinInts(ports.TCP) != "443" || joinInts(ports.UDP) != "443" {
		t.Fatalf("state ports = %+v", ports)
	}
	if strings.Join(fams, ",") != "iptables,ip6tables" {
		t.Fatalf("state families = %v", fams)
	}
	for _, rel := range []string{rulesV4Rel, rulesV6Rel} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("persisted rules missing: %s", rel)
		}
	}

	report := mustApply(t, root, Spec{New: NewPorts([]int{8443}, nil), Mode: "auto"})
	if joinInts(report.Old.TCP) != "443" {
		t.Fatalf("old ports = %v", report.Old.TCP)
	}
	if len(fw.rules) != 4 {
		t.Fatalf("rules = %d, want 2 tcp INPUT/OUTPUT rules in each family", len(fw.rules))
	}
	for key := range fw.rules {
		if !strings.Contains(key, "8443") {
			t.Errorf("stale rule after the diff: %q", key)
		}
	}
	if strings.Contains(fw.dump("iptables-save"), "--dport 443") ||
		strings.Contains(fw.dump("iptables-save"), "--sport 443") {
		t.Error("persisted v4 rules still contain the removed port")
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	root, fw := setupFW(t)
	spec := Spec{New: NewPorts([]int{443}, nil), Mode: "ipv4"}
	mustApply(t, root, spec)
	before := len(fw.rules)
	report := mustApply(t, root, spec)
	if len(fw.rules) != before {
		t.Fatalf("rules = %d, want %d", len(fw.rules), before)
	}
	for _, c := range report.Commands {
		if len(c.Args) > 0 && c.Args[0] == "-I" {
			t.Fatalf("idempotent apply still inserted: %s", c)
		}
	}
}

func TestApplyDryRunWritesNothing(t *testing.T) {
	root, fw := setupFW(t)
	report, err := Apply(context.Background(), Spec{
		Root: root, New: NewPorts([]int{443}, nil), Mode: "dual", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fw.calls != 0 {
		t.Fatalf("dry-run executed %d commands", fw.calls)
	}
	if len(report.Commands) == 0 || !report.DryRun || report.Persisted {
		t.Fatalf("dry-run report = %+v", report)
	}
	if _, err := os.Stat(filepath.Join(root, portsStateRel)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run wrote state: %v", err)
	}
}

func TestApplyRollsBackOnCommandFailure(t *testing.T) {
	root, fw := setupFW(t)
	fw.failOn = "ip6tables -I"
	report, err := Apply(context.Background(), Spec{
		Root: root, New: NewPorts([]int{443}, []int{443}), Mode: "dual",
	})
	if err == nil {
		t.Fatal("Apply succeeded despite the injected failure")
	}
	if !report.RolledBack {
		t.Fatal("report did not flag the rollback")
	}
	if len(fw.rules) != 0 {
		t.Fatalf("rules after rollback = %d, want 0", len(fw.rules))
	}
	if _, err := os.Stat(filepath.Join(root, portsStateRel)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed transaction wrote state: %v", err)
	}
}

func TestApplyFailsClosedWithoutFamilyTool(t *testing.T) {
	root, fw := setupFW(t)
	toolAvailable = func(name string) bool { return name == FamilyV4 }
	_, err := Apply(context.Background(), Spec{
		Root: root, New: NewPorts([]int{443}, nil), Mode: "dual",
	})
	if !errors.Is(err, ErrToolMissing) {
		t.Fatalf("err = %v, want ErrToolMissing", err)
	}
	if len(fw.rules) != 0 {
		t.Fatalf("rules = %d, want 0", len(fw.rules))
	}
}

func TestApplyRollsBackWhenStateWriteFails(t *testing.T) {
	root, fw := setupFW(t)
	mustApply(t, root, Spec{New: NewPorts([]int{443}, nil), Mode: "ipv4"})
	statePath := filepath.Join(root, familiesStateRel)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := Apply(context.Background(), Spec{
		Root: root, New: NewPorts([]int{8443}, nil), Mode: "ipv4",
	})
	if err == nil {
		t.Fatal("Apply succeeded despite an unwritable state file")
	}
	if !report.RolledBack {
		t.Fatal("report did not flag the rollback")
	}
	if _, statErr := os.Stat(statePath); statErr != nil {
		t.Fatalf("the squatting state path was removed: %v", statErr)
	}
	key := "iptables|INPUT -p tcp --dport 443 -j ACCEPT"
	if !fw.rules[key] {
		t.Fatalf("the previous rule was not restored; rules=%v", fw.rules)
	}
	if fw.rules["iptables|INPUT -p tcp --dport 8443 -j ACCEPT"] {
		t.Fatal("the new rule survived the rollback")
	}
}

func TestApplyWarnsWhenPersistenceFails(t *testing.T) {
	root, fw := setupFW(t)
	fw.failOn = "iptables-save"
	report := mustApply(t, root, Spec{New: NewPorts([]int{443}, nil), Mode: "ipv4"})
	if report.Persisted {
		t.Fatal("report claims persistence succeeded")
	}
	if len(report.Warnings) == 0 {
		t.Fatal("persistence failure produced no warning")
	}
	if len(fw.rules) != 2 {
		t.Fatalf("rules = %d, want 2 runtime rules", len(fw.rules))
	}
}

func TestStatusAndRevert(t *testing.T) {
	root, fw := setupFW(t)
	toolAvailable = func(name string) bool { return name == FamilyV4 }
	mustApply(t, root, Spec{New: NewPorts([]int{443}, nil), Mode: "ipv4"})
	status, err := Status(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || len(status.Checks) != 1 {
		t.Fatalf("status = %+v", status)
	}
	if status.Checks[0].Input != "present" || status.Checks[0].Output != "present" {
		t.Fatalf("checks = %+v", status.Checks)
	}
	delete(fw.rules, "iptables|OUTPUT -p tcp --sport 443 -j ACCEPT")
	status, err = Status(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if status.Checks[0].Output != "missing" {
		t.Fatalf("missing rule reported as %q", status.Checks[0].Output)
	}

	report, err := Revert(context.Background(), Spec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.rules) != 0 || len(report.New.TCP) != 0 {
		t.Fatalf("revert left rules=%d new=%+v", len(fw.rules), report.New)
	}
	if strings.Join(report.NewFamilies, ",") != "iptables" {
		t.Fatalf("revert changed the family set: %v", report.NewFamilies)
	}
	again, err := Revert(context.Background(), Spec{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Commands) != 0 {
		t.Fatalf("second revert was not a no-op: %v", again.Commands)
	}
	var stored Ports
	raw, err := os.ReadFile(filepath.Join(root, portsStateRel))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.TCP) != 0 || len(stored.UDP) != 0 {
		t.Fatalf("state after revert = %+v", stored)
	}
}

func TestStatusChecksOnlyManagedFamilies(t *testing.T) {
	root, _ := setupFW(t)
	// setupFW reports both tools as available; an ipv4 apply manages only
	// iptables, so ip6tables holding no rule must not appear as drift.
	mustApply(t, root, Spec{New: NewPorts([]int{443}, nil), Mode: "ipv4"})
	status, err := Status(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(status.Families, ",") != "iptables" {
		t.Fatalf("state families = %v", status.Families)
	}
	if len(status.Checks) != 1 || status.Checks[0].Family != FamilyV4 {
		t.Fatalf("status checked an unmanaged family: %+v", status.Checks)
	}
}

func TestFreshApplyPersistsOnlyRequestedFamilies(t *testing.T) {
	root, _ := setupFW(t)
	mustApply(t, root, Spec{New: NewPorts([]int{443}, nil), Mode: "ipv4"})
	if _, err := os.Stat(filepath.Join(root, rulesV6Rel)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an ipv4-only apply wrote rules.v6: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, rulesV4Rel)); err != nil {
		t.Fatalf("rules.v4 missing: %v", err)
	}
}

func TestLegacyStateCleansEveryInstalledFamily(t *testing.T) {
	root, fw := setupFW(t)
	// A state file from before managed_families.json: ports recorded, family
	// file absent, and the old rules live in both families.
	if err := os.WriteFile(filepath.Join(root, portsStateRel),
		[]byte("{\"tcp\":[443],\"udp\":[]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, bin := range []string{FamilyV4, FamilyV6} {
		fw.rules[bin+"|INPUT -p tcp --dport 443 -j ACCEPT"] = true
	}
	report := mustApply(t, root, Spec{New: NewPorts([]int{8443}, nil), Mode: "ipv4"})
	if strings.Join(report.OldFamilies, ",") != "iptables,ip6tables" {
		t.Fatalf("legacy old families = %v", report.OldFamilies)
	}
	if fw.rules[FamilyV6+"|INPUT -p tcp --dport 443 -j ACCEPT"] {
		t.Fatal("the legacy ip6tables rule was not cleaned")
	}
	if !fw.rules[FamilyV4+"|INPUT -p tcp --dport 8443 -j ACCEPT"] {
		t.Fatal("the new ipv4 rule was not added")
	}
}

func TestApplyRejectsUnmarkedSandbox(t *testing.T) {
	root := t.TempDir()
	_, err := Apply(context.Background(), Spec{
		Root: root, New: NewPorts([]int{443}, nil), Mode: "ipv4",
	})
	if err == nil || !strings.Contains(err.Error(), "sandbox") {
		t.Fatalf("err = %v, want a sandbox marker refusal", err)
	}
}
