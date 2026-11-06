// Package runtime defines the minimal Phase 01 validator/service boundary.
// Phase 02 fills real Xray/Nginx deployment; this package only runs a real
// external validator and one injected service-apply command.
package runtime

import (
	"context"
	"fmt"
	"os"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// ValidationError reports a candidate rejected by the real validator.
type ValidationError struct {
	ExitCode int
	Output   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("candidate rejected by validator (exit %d): %s", e.ExitCode, e.Output)
}

// ServiceError reports that the apply hook failed after the file changed.
type ServiceError struct {
	ExitCode int
	Output   string
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("service apply failed (exit %d): %s", e.ExitCode, e.Output)
}

// XrayValidator invokes the real Xray binary with shell-free arguments.
type XrayValidator struct {
	Path string
}

// Validate runs `xray -test -config <candidate>`.
func (v XrayValidator) Validate(ctx context.Context, candidate string) error {
	if v.Path == "" {
		return &ValidationError{ExitCode: -1, Output: "validator path is required"}
	}
	res, err := host.Run(ctx, host.ExecSpec{Path: v.Path, Args: []string{"-test", "-config", candidate}})
	if err != nil {
		return &ValidationError{ExitCode: -1, Output: err.Error()}
	}
	if res.ExitCode != 0 {
		out := res.Stderr
		if out == "" {
			out = res.Stdout
		}
		return &ValidationError{ExitCode: res.ExitCode, Output: out}
	}
	return nil
}

// CommandService runs one injected apply hook. It never starts a stopped
// service by itself; the hook owns its own semantics.
type CommandService struct {
	Path string
}

// Apply executes the hook with the fixed argument "apply".
func (s CommandService) Apply(ctx context.Context) error {
	if s.Path == "" {
		return nil
	}
	res, err := host.Run(ctx, host.ExecSpec{Path: s.Path, Args: []string{"apply"}})
	if err != nil {
		return &ServiceError{ExitCode: -1, Output: err.Error()}
	}
	if res.ExitCode != 0 {
		out := res.Stderr
		if out == "" {
			out = res.Stdout
		}
		return &ServiceError{ExitCode: res.ExitCode, Output: out}
	}
	return nil
}

// ServiceState is a read-only systemd snapshot. Sandbox roots never query
// host systemd, so tests cannot be influenced by the developer machine.
type ServiceState struct {
	Xray    string `json:"xray"`
	Nginx   string `json:"nginx"`
	Enabled string `json:"enabled"`
	Source  string `json:"source"`
	Sandbox bool   `json:"sandbox"`
}

// InspectServices reads unit state on the real root only.
func InspectServices(ctx context.Context, root string) ServiceState {
	if root != "/" {
		return ServiceState{Xray: "sandbox-not-queried", Nginx: "sandbox-not-queried", Enabled: "sandbox-not-queried", Source: "sandbox", Sandbox: true}
	}
	if _, err := os.Stat("/usr/bin/systemctl"); err != nil {
		if _, err2 := os.Stat("/bin/systemctl"); err2 != nil {
			return ServiceState{Xray: "unavailable", Nginx: "unavailable", Enabled: "unavailable", Source: "systemctl-missing"}
		}
	}
	state := ServiceState{Source: "systemctl"}
	state.Xray = queryUnit(ctx, "xray")
	state.Nginx = queryUnit(ctx, "nginx")
	state.Enabled = queryEnabled(ctx, "xray")
	return state
}

func queryUnit(ctx context.Context, unit string) string {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-active", unit}})
	if err != nil || res.ExitCode != 0 {
		if res.Stdout != "" {
			return trimLine(res.Stdout)
		}
		return "inactive-or-unknown"
	}
	return trimLine(res.Stdout)
}

func queryEnabled(ctx context.Context, unit string) string {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-enabled", unit}})
	if err != nil {
		return "unknown"
	}
	if res.ExitCode != 0 {
		return "disabled-or-unknown"
	}
	return trimLine(res.Stdout)
}

func trimLine(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
