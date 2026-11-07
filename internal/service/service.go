// Package service exposes the service-class commands that the legacy Bash
// menu offered (start/stop/restart/status/logs). It never starts its own daemon
// and never writes a unit: it only drives the systemd units the product owns.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const SchemaVersion = 1

// Units are the only units this manager drives. A caller cannot name an
// arbitrary unit, so an unrelated host service can never be stopped by mistake.
var Units = []string{"xray", "nginx", "idleleo-schedule.timer"}

// ErrRealRootOnly keeps service commands from querying or changing a sandbox
// or an unrelated host through a test root.
var ErrRealRootOnly = errors.New("service commands operate on the real system only (--root must be /)")

// UnitState is one unit's read-only projection.
type UnitState struct {
	Name    string `json:"name"`
	Unit    string `json:"unit"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}

// StatusReport is the read-only service view.
type StatusReport struct {
	SchemaVersion int         `json:"schemaVersion"`
	Root          string      `json:"root"`
	Units         []UnitState `json:"units"`
}

// Status queries is-active and is-enabled for the owned units. It writes
// nothing and never reloads a unit.
func Status(ctx context.Context, root string) (StatusReport, error) {
	rep := StatusReport{SchemaVersion: SchemaVersion, Root: root, Units: []UnitState{}}
	if root != "/" {
		return rep, ErrRealRootOnly
	}
	for _, name := range Units {
		u := UnitState{Name: name, Unit: name + ".service", Active: "unknown", Enabled: "unknown"}
		if name == "idleleo-schedule.timer" {
			u.Unit = name
		}
		u.Active = query(ctx, "is-active", u.Unit)
		u.Enabled = query(ctx, "is-enabled", u.Unit)
		rep.Units = append(rep.Units, u)
	}
	return rep, nil
}

func query(ctx context.Context, verb, unit string) string {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{verb, unit}, Timeout: 10 * time.Second})
	if err != nil {
		return "error"
	}
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		return fmt.Sprintf("exit-%d", res.ExitCode)
	}
	return out
}

// Action is a controlled lifecycle verb.
type Action string

const (
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
	ActionReload  Action = "reload"
)

// ActionReport records exactly what ran.
type ActionReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	Action        string `json:"action"`
	Unit          string `json:"unit"`
	Systemctl     string `json:"systemctl"`
	ExitCode      int    `json:"exitCode"`
	Output        string `json:"output,omitempty"`
}

// CheckUnit accepts only an owned unit name.
func CheckUnit(unit string) error {
	bare := strings.TrimSuffix(unit, ".service")
	for _, u := range Units {
		if u == unit || u == bare || strings.TrimSuffix(u, ".timer") == bare {
			return nil
		}
	}
	return fmt.Errorf("unit %q is not managed by idleleo", unit)
}

func fullName(unit string) string {
	bare := strings.TrimSuffix(unit, ".service")
	if bare == "idleleo-schedule.timer" || bare == "idleleo-schedule" {
		return "idleleo-schedule.timer"
	}
	return bare + ".service"
}

// Apply runs one lifecycle action and reports its real systemctl result.
func Apply(ctx context.Context, root string, action Action, unit string) (ActionReport, error) {
	rep := ActionReport{SchemaVersion: SchemaVersion, Action: string(action)}
	if root != "/" {
		return rep, ErrRealRootOnly
	}
	switch action {
	case ActionStart, ActionStop, ActionRestart, ActionReload:
	default:
		return rep, fmt.Errorf("unsupported action %q", action)
	}
	if err := CheckUnit(unit); err != nil {
		return rep, err
	}
	full := fullName(unit)
	rep.Unit = full
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{string(action), full}, Timeout: 60 * time.Second})
	rep.Systemctl = fmt.Sprintf("systemctl %s %s", action, full)
	if err != nil {
		return rep, err
	}
	rep.ExitCode = res.ExitCode
	rep.Output = strings.TrimSpace(strings.Join([]string{res.Stdout, res.Stderr}, " "))
	if res.ExitCode != 0 {
		return rep, fmt.Errorf("%s failed (exit %d): %s", rep.Systemctl, res.ExitCode, rep.Output)
	}
	return rep, nil
}

// LogsReport is the last N journal lines for one owned unit.
type LogsReport struct {
	SchemaVersion int    `json:"schemaVersion"`
	Unit          string `json:"unit"`
	Lines         int    `json:"lines"`
	Journalctl    string `json:"journalctl"`
	Output        string `json:"output"`
}

// Logs reads the journal without writing. It is allowed on the real root only,
// because a sandbox root has no journal for the host units.
func Logs(ctx context.Context, root, unit string, lines int) (LogsReport, error) {
	rep := LogsReport{SchemaVersion: SchemaVersion}
	if root != "/" {
		return rep, ErrRealRootOnly
	}
	if err := CheckUnit(unit); err != nil {
		return rep, err
	}
	if lines <= 0 {
		lines = 50
	}
	if lines > 500 {
		lines = 500
	}
	full := fullName(unit)
	rep.Unit, rep.Lines = full, lines
	args := []string{"-u", full, "-n", fmt.Sprint(lines), "--no-pager"}
	rep.Journalctl = "journalctl " + strings.Join(args, " ")
	res, err := host.Run(ctx, host.ExecSpec{Path: "journalctl", Args: args, Timeout: 30 * time.Second})
	if err != nil {
		return rep, err
	}
	rep.Output = strings.TrimSpace(res.Stdout + res.Stderr)
	if res.ExitCode != 0 {
		return rep, fmt.Errorf("%s failed (exit %d): %s", rep.Journalctl, res.ExitCode, rep.Output)
	}
	return rep, nil
}
