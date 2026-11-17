package netcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// Netfilter binaries and the managed state files.
const (
	FamilyV4 = "iptables"
	FamilyV6 = "ip6tables"

	portsStateRel    = "etc/idleleo/managed_ports.json"
	familiesStateRel = "etc/idleleo/managed_families.json"
	rulesV4Rel       = "etc/iptables/rules.v4"
	rulesV6Rel       = "etc/iptables/rules.v6"
)

var (
	// ErrToolMissing means a family the new mode requires has no binary. The
	// transaction fails closed instead of silently degrading to one family.
	ErrToolMissing = errors.New("required netfilter tool is missing")
	// ErrRollback means an undo command failed, so the operator must inspect
	// the ruleset by hand.
	ErrRollback = errors.New("firewall rollback failed")
)

// runCommand executes one netfilter command. It is a seam so unit tests can
// simulate a ruleset without root; the fixture uses real shim binaries.
var runCommand = func(ctx context.Context, c Command) (string, int, error) {
	res, err := host.Run(ctx, host.ExecSpec{Path: c.Bin, Args: c.Args})
	return res.Stdout, res.ExitCode, err
}

// toolAvailable reports whether a netfilter binary is reachable in the fixed
// PATH. It is a seam for the "dual without ip6tables" fail-closed test.
var toolAvailable = func(name string) bool {
	_, err := host.ResolveBinary(name)
	return err == nil
}

// FamilySet is an ordered, deduplicated list of netfilter binaries.
type FamilySet []string

// FamiliesForMode maps a network mode onto the binaries to manage. It is a pure
// function so callers can compute an old family set independently of the
// current mode: ipv6 -> ip6tables, dual -> both, ipv4/manual -> iptables, and
// auto/empty -> iptables plus ip6tables only when the tool exists.
func FamiliesForMode(mode string, hasIPv6 bool) FamilySet {
	switch strings.TrimSpace(mode) {
	case "ipv6":
		return FamilySet{FamilyV6}
	case "dual":
		return FamilySet{FamilyV4, FamilyV6}
	case "ipv4", "manual":
		return FamilySet{FamilyV4}
	default:
		if hasIPv6 {
			return FamilySet{FamilyV4, FamilyV6}
		}
		return FamilySet{FamilyV4}
	}
}

// Ports is the managed port set persisted under managed_ports.json.
type Ports struct {
	TCP []int `json:"tcp"`
	UDP []int `json:"udp"`
}

// NewPorts normalises a port set: nil becomes an empty slice, duplicates are
// removed and the order is ascending so the state file is stable.
func NewPorts(tcp, udp []int) Ports {
	return Ports{TCP: normalisePorts(tcp), UDP: normalisePorts(udp)}
}

func normalisePorts(in []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(in))
	for _, p := range in {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ParsePortList parses a comma separated port list. An empty string is an
// empty set; anything outside 1-65535 is a usage error.
func ParsePortList(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", raw)
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q: want 1-65535", part)
		}
		out = append(out, n)
	}
	return normalisePorts(out), nil
}

// Command is one netfilter invocation, kept in the report for audits and
// dry-runs.
type Command struct {
	Bin  string   `json:"bin"`
	Args []string `json:"args"`
}

func (c Command) String() string {
	return c.Bin + " " + strings.Join(c.Args, " ")
}

// Spec is one firewall transaction request. Families, when set, overrides the
// family set derived from Mode; otherwise Mode is authoritative.
type Spec struct {
	Root                 string
	New                  Ports
	Mode                 string
	Families             FamilySet
	DryRun               bool
	AllowContainerWrites bool
}

// Report is the JSON contract for `net firewall apply|revert`.
type Report struct {
	Old         Ports     `json:"old"`
	New         Ports     `json:"new"`
	OldFamilies []string  `json:"oldFamilies"`
	NewFamilies []string  `json:"newFamilies"`
	Commands    []Command `json:"commands"`
	Persisted   bool      `json:"persisted"`
	RolledBack  bool      `json:"rolledBack"`
	DryRun      bool      `json:"dryRun"`
	Warnings    []string  `json:"warnings,omitempty"`
}

// StatusReport is the read-only view of the persistence state and live rules.
type StatusReport struct {
	StateFile string       `json:"stateFile"`
	Installed bool         `json:"installed"`
	Ports     Ports        `json:"ports"`
	Families  []string     `json:"families"`
	Checks    []PortStatus `json:"checks"`
	Warnings  []string     `json:"warnings,omitempty"`
}

// PortStatus records whether the INPUT/OUTPUT rule exists in one family.
type PortStatus struct {
	Family string `json:"family"`
	Proto  string `json:"proto"`
	Port   int    `json:"port"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

// Apply reconciles the managed ruleset from the persisted set to spec.New.
func Apply(ctx context.Context, spec Spec) (Report, error) {
	return apply(ctx, spec, false)
}

// Revert removes every managed port while keeping the managed family set, so a
// second call is a no-op.
func Revert(ctx context.Context, spec Spec) (Report, error) {
	return apply(ctx, spec, true)
}

func apply(ctx context.Context, spec Spec, revert bool) (Report, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return Report{}, &change.UsageError{Msg: err.Error()}
	}
	if !spec.DryRun {
		if err := host.RequireSystemWrite(paths.Root, spec.AllowContainerWrites); err != nil {
			return Report{}, &change.UsageError{Msg: err.Error()}
		}
	}
	root := paths.Root
	oldPorts, oldFamilies, _, err := loadState(root)
	if err != nil {
		return Report{}, err
	}
	if len(oldFamilies) == 0 && (len(oldPorts.TCP) > 0 || len(oldPorts.UDP) > 0) {
		// A state file written before managed_families.json existed: its rules
		// may live in every installed family, so clean them all. A fresh state
		// keeps an empty old set and never persists an unrequested family.
		oldFamilies = availableFamilies()
	}
	oldFamilies = canonicalFamilies(oldFamilies)

	newPorts := spec.New
	newFamilies := canonicalFamilies(spec.Families)
	if revert {
		newPorts = NewPorts(nil, nil)
		newFamilies = oldFamilies
	} else if len(newFamilies) == 0 {
		newFamilies = canonicalFamilies(FamiliesForMode(spec.Mode, toolAvailable(FamilyV6)))
	}

	if oldFamilies == nil {
		oldFamilies = FamilySet{}
	}
	if newFamilies == nil {
		newFamilies = FamilySet{}
	}
	report := Report{
		Old:         oldPorts,
		New:         newPorts,
		OldFamilies: oldFamilies,
		NewFamilies: newFamilies,
		Commands:    []Command{},
		DryRun:      spec.DryRun,
	}
	for _, fam := range newFamilies {
		if !toolAvailable(fam) {
			return report, fmt.Errorf("%w: %s", ErrToolMissing, fam)
		}
	}

	t := &txn{ctx: ctx, dry: spec.DryRun}
	if err := t.reconcile(oldFamilies, newFamilies, oldPorts, newPorts); err != nil {
		report.Commands = t.commands()
		if !spec.DryRun {
			report.RolledBack = true
			if undoErr := t.rollback(); undoErr != nil {
				return report, fmt.Errorf("%w: %v", ErrRollback, undoErr)
			}
		}
		return report, err
	}
	report.Commands = t.commands()
	if spec.DryRun {
		return report, nil
	}

	snapshot := snapshotState(root)
	if err := writeState(root, newPorts, newFamilies); err != nil {
		report.RolledBack = true
		if undoErr := t.rollback(); undoErr != nil {
			return report, fmt.Errorf("%w: %v", ErrRollback, undoErr)
		}
		if restoreErr := snapshot.restore(); restoreErr != nil {
			return report, fmt.Errorf("%w: restore state: %v", ErrRollback, restoreErr)
		}
		return report, err
	}

	// Persist the union of old and new families: a family that was cleaned at
	// runtime must also be saved or its stale rule returns after a reboot.
	report.Persisted = true
	for _, fam := range canonicalFamilies(append(append(FamilySet{}, oldFamilies...), newFamilies...)) {
		if err := persist(ctx, root, fam); err != nil {
			report.Persisted = false
			report.Warnings = append(report.Warnings, fmt.Sprintf("persist %s: %v", fam, err))
		}
	}
	return report, nil
}

// Status inspects the saved port set against the live rules. It never mutates
// and tolerates a missing state file.
func Status(ctx context.Context, root string) (StatusReport, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return StatusReport{}, &change.UsageError{Msg: err.Error()}
	}
	statePath := filepath.Join(paths.Root, portsStateRel)
	ports, families, installed, err := loadState(paths.Root)
	if err != nil {
		return StatusReport{}, err
	}
	if families == nil {
		families = FamilySet{}
	}
	report := StatusReport{
		StateFile: statePath,
		Installed: installed,
		Ports:     ports,
		Families:  families,
		Checks:    []PortStatus{},
	}
	if !installed {
		return report, nil
	}
	commandFamilies := families
	if len(commandFamilies) == 0 {
		// Legacy state without managed_families.json: inspect every family whose
		// tool is installed. Otherwise only the managed families are checked, so
		// an unmanaged family never shows up as drift.
		commandFamilies = availableFamilies()
	}
	for _, fam := range commandFamilies {
		for _, proto := range []string{"tcp", "udp"} {
			for _, port := range portsFor(ports, proto) {
				input := presence(ctx, fam, "INPUT", proto, "--dport", port)
				output := presence(ctx, fam, "OUTPUT", proto, "--sport", port)
				report.Checks = append(report.Checks, PortStatus{
					Family: fam, Proto: proto, Port: port, Input: input, Output: output,
				})
			}
		}
	}
	return report, nil
}

func presence(ctx context.Context, fam, chain, proto, flag string, port int) string {
	c := Command{Bin: fam, Args: []string{"-C", chain, "-p", proto, flag, strconv.Itoa(port), "-j", "ACCEPT"}}
	_, code, err := runCommand(ctx, c)
	if err != nil || code != 0 {
		return "missing"
	}
	return "present"
}

func portsFor(p Ports, proto string) []int {
	if proto == "udp" {
		return p.UDP
	}
	return p.TCP
}

// txn records every command, the inverse of every successful mutation, and
// replays the inverses in reverse order on failure.
type txn struct {
	ctx  context.Context
	dry  bool
	cmds []Command
	undo []Command
}

func (t *txn) commands() []Command {
	if t.cmds == nil {
		return []Command{}
	}
	return t.cmds
}

func (t *txn) reconcile(oldFam, newFam FamilySet, oldPorts, newPorts Ports) error {
	for _, fam := range oldFam {
		if containsFamily(newFam, fam) {
			continue
		}
		if err := t.removeAll(fam, oldPorts); err != nil {
			return err
		}
	}
	for _, fam := range newFam {
		if containsFamily(oldFam, fam) {
			continue
		}
		if err := t.ensureAll(fam, newPorts); err != nil {
			return err
		}
	}
	for _, fam := range oldFam {
		if !containsFamily(newFam, fam) {
			continue
		}
		if err := t.removePorts(fam, "tcp", difference(oldPorts.TCP, newPorts.TCP)); err != nil {
			return err
		}
		if err := t.removePorts(fam, "udp", difference(oldPorts.UDP, newPorts.UDP)); err != nil {
			return err
		}
		if err := t.ensurePorts(fam, "tcp", newPorts.TCP); err != nil {
			return err
		}
		if err := t.ensurePorts(fam, "udp", newPorts.UDP); err != nil {
			return err
		}
	}
	return nil
}

func (t *txn) ensureAll(fam string, ports Ports) error {
	if err := t.ensurePorts(fam, "tcp", ports.TCP); err != nil {
		return err
	}
	return t.ensurePorts(fam, "udp", ports.UDP)
}

func (t *txn) removeAll(fam string, ports Ports) error {
	if err := t.removePorts(fam, "tcp", ports.TCP); err != nil {
		return err
	}
	return t.removePorts(fam, "udp", ports.UDP)
}

func (t *txn) ensurePorts(fam, proto string, ports []int) error {
	for _, port := range ports {
		n := strconv.Itoa(port)
		if err := t.ensure(fam, proto, "INPUT", "--dport", n); err != nil {
			return err
		}
		if err := t.ensure(fam, proto, "OUTPUT", "--sport", n); err != nil {
			return err
		}
	}
	return nil
}

func (t *txn) removePorts(fam, proto string, ports []int) error {
	for _, port := range ports {
		n := strconv.Itoa(port)
		if err := t.remove(fam, proto, "INPUT", "--dport", n); err != nil {
			return err
		}
		if err := t.remove(fam, proto, "OUTPUT", "--sport", n); err != nil {
			return err
		}
	}
	return nil
}

// ensure adds a rule only when the checking form reports it missing, and
// registers the deletion as its inverse.
func (t *txn) ensure(fam, proto, chain, flag, port string) error {
	check := Command{Bin: fam, Args: []string{"-C", chain, "-p", proto, flag, port, "-j", "ACCEPT"}}
	add := Command{Bin: fam, Args: []string{"-I", chain, "-p", proto, flag, port, "-j", "ACCEPT"}}
	if t.dry {
		t.cmds = append(t.cmds, check, add)
		return nil
	}
	exists, err := t.check(check)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if err := t.exec(add); err != nil {
		return err
	}
	t.undo = append(t.undo, Command{Bin: fam, Args: []string{"-D", chain, "-p", proto, flag, port, "-j", "ACCEPT"}})
	return nil
}

// remove deletes every copy of a rule, registering one insert per deletion so
// the undo replays the exact count. A dry-run emits one check plus one delete
// as intent without executing anything.
func (t *txn) remove(fam, proto, chain, flag, port string) error {
	check := Command{Bin: fam, Args: []string{"-C", chain, "-p", proto, flag, port, "-j", "ACCEPT"}}
	del := Command{Bin: fam, Args: []string{"-D", chain, "-p", proto, flag, port, "-j", "ACCEPT"}}
	if t.dry {
		t.cmds = append(t.cmds, check, del)
		return nil
	}
	for {
		exists, err := t.check(check)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if err := t.exec(del); err != nil {
			return err
		}
		t.undo = append(t.undo, Command{Bin: fam, Args: []string{"-I", chain, "-p", proto, flag, port, "-j", "ACCEPT"}})
	}
}

func (t *txn) check(c Command) (bool, error) {
	if t.dry {
		t.cmds = append(t.cmds, c)
		return false, nil
	}
	t.cmds = append(t.cmds, c)
	_, code, err := runCommand(t.ctx, c)
	if err != nil {
		return false, fmt.Errorf("%s: %w", c, err)
	}
	return code == 0, nil
}

func (t *txn) exec(c Command) error {
	t.cmds = append(t.cmds, c)
	_, code, err := runCommand(t.ctx, c)
	if err != nil {
		return fmt.Errorf("%s: %w", c, err)
	}
	if code != 0 {
		return fmt.Errorf("%s exited %d", c, code)
	}
	return nil
}

func (t *txn) rollback() error {
	for i := len(t.undo) - 1; i >= 0; i-- {
		c := t.undo[i]
		t.cmds = append(t.cmds, c)
		_, code, err := runCommand(t.ctx, c)
		if err != nil {
			return fmt.Errorf("%s: %w", c, err)
		}
		if code != 0 {
			return fmt.Errorf("%s exited %d", c, code)
		}
	}
	return nil
}

func difference(old, new []int) []int {
	keep := map[int]bool{}
	for _, p := range new {
		keep[p] = true
	}
	var out []int
	for _, p := range old {
		if !keep[p] {
			out = append(out, p)
		}
	}
	return out
}

func containsFamily(set FamilySet, fam string) bool {
	for _, item := range set {
		if item == fam {
			return true
		}
	}
	return false
}

// canonicalFamilies deduplicates and orders iptables before ip6tables so state
// files and command logs are stable.
func canonicalFamilies(in FamilySet) FamilySet {
	has := map[string]bool{}
	for _, fam := range in {
		if fam == FamilyV4 || fam == FamilyV6 {
			has[fam] = true
		}
	}
	var out FamilySet
	if has[FamilyV4] {
		out = append(out, FamilyV4)
	}
	if has[FamilyV6] {
		out = append(out, FamilyV6)
	}
	return out
}

func availableFamilies() FamilySet {
	out := FamilySet{}
	if toolAvailable(FamilyV4) {
		out = append(out, FamilyV4)
	}
	if toolAvailable(FamilyV6) {
		out = append(out, FamilyV6)
	}
	return out
}

func portsStatePath(root string) string    { return filepath.Join(root, portsStateRel) }
func familiesStatePath(root string) string { return filepath.Join(root, familiesStateRel) }

func loadState(root string) (Ports, FamilySet, bool, error) {
	ports := NewPorts(nil, nil)
	raw, err := os.ReadFile(portsStatePath(root))
	if errors.Is(err, os.ErrNotExist) {
		return ports, nil, false, nil
	}
	if err != nil {
		return ports, nil, false, err
	}
	var stored struct {
		TCP []int `json:"tcp"`
		UDP []int `json:"udp"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return ports, nil, true, fmt.Errorf("state %s: %w", portsStatePath(root), err)
	}
	ports = NewPorts(stored.TCP, stored.UDP)
	var fams []string
	if b, err := os.ReadFile(familiesStatePath(root)); err == nil {
		_ = json.Unmarshal(b, &fams)
	}
	return ports, canonicalFamilies(fams), true, nil
}

func writeState(root string, ports Ports, fams FamilySet) error {
	portsJSON, err := json.MarshalIndent(ports, "", "  ")
	if err != nil {
		return err
	}
	famsJSON, err := json.MarshalIndent([]string(fams), "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(portsStatePath(root), append(portsJSON, '\n'), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(familiesStatePath(root), append(famsJSON, '\n'), 0o644); err != nil {
		return err
	}
	return nil
}

type stateSnapshot struct {
	paths    []string
	data     [][]byte
	existed  []bool
	readable []bool
}

func snapshotState(root string) stateSnapshot {
	paths := []string{portsStatePath(root), familiesStatePath(root)}
	snap := stateSnapshot{paths: paths}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			snap.data = append(snap.data, nil)
			snap.existed = append(snap.existed, false)
			snap.readable = append(snap.readable, false)
			continue
		}
		b, err := os.ReadFile(path)
		snap.data = append(snap.data, b)
		snap.existed = append(snap.existed, true)
		// An unreadable entry (for example a directory squatting on the state
		// path) is left untouched: we never wrote through it, so restoring it
		// would destroy the cause of the failure.
		snap.readable = append(snap.readable, err == nil)
	}
	return snap
}

func (s stateSnapshot) restore() error {
	for i, path := range s.paths {
		switch {
		case !s.existed[i]:
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		case s.readable[i]:
			if err := writeFileAtomic(path, s.data[i], 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// persist saves one family's live ruleset next to the boot-time loader path.
// A failure is a warning, never a rollback: the runtime rules are already live.
func persist(ctx context.Context, root, fam string) error {
	out, code, err := runCommand(ctx, Command{Bin: fam + "-save"})
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s-save exited %d", fam, code)
	}
	rel := rulesV4Rel
	if fam == FamilyV6 {
		rel = rulesV6Rel
	}
	return writeFileAtomic(filepath.Join(root, rel), []byte(out), 0o644)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".idleleo-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
