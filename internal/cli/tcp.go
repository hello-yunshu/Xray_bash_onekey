package cli

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/tcpcfg"
)

// tcpCommand exposes the project-owned TCP sysctl profile. It never touches a
// kernel it cannot already use and never downloads third-party scripts.
func tcpCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	m, err := tcpcfg.New(cfg.root)
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")
	switch sub {
	case "status":
		status, err := m.Status()
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, status)
		}
		fmt.Fprintf(opts.Out, "supported: %t\ngoos: %s\nkernel: %s\n", status.Supported, status.GOOS, status.KernelRelease)
		fmt.Fprintf(opts.Out, "congestion: %s\n", strings.Join(status.AvailableCongestion, " "))
		if status.ManagedFile.Path != "" {
			fmt.Fprintf(opts.Out, "managed: path=%s exists=%t owned=%t mode=%04o sha256=%s\n",
				status.ManagedFile.Path, status.ManagedFile.Exists, status.ManagedFile.Owned, status.ManagedFile.Mode, status.ManagedFile.SHA256)
		}
		fmt.Fprintf(opts.Out, "current:")
		for key, value := range status.Current {
			fmt.Fprintf(opts.Out, " %s=%s", key, value)
		}
		fmt.Fprintln(opts.Out)
		if status.State != nil {
			fmt.Fprintf(opts.Out, "state: profile=%s pending=%t applied=%t\n", status.State.Profile, status.State.Pending, status.State.AppliedHash != "")
		} else {
			fmt.Fprintf(opts.Out, "state: none (%s)\n", status.StatePath)
		}
		for _, conflict := range status.Conflicts {
			fmt.Fprintf(opts.Out, "conflict: %s\n", conflict)
		}
		for _, warning := range status.Warnings {
			fmt.Fprintf(opts.Out, "warning: %s\n", warning)
		}
		return 0
	case "plan":
		profile := tcpProfile(rest)
		if _, err := tcpcfg.ProfileKeys(profile); err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
		}
		plan, err := m.Plan(profile)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, plan)
		}
		fmt.Fprintf(opts.Out, "profile: %s\nsupported: %t\nbbr-supported: %t\n", plan.Profile, plan.Supported, plan.KernelSupportsBBR)
		fmt.Fprintf(opts.Out, "file: %s %s\n", plan.FileAction, plan.FilePath)
		for _, change := range plan.Keys {
			fmt.Fprintf(opts.Out, "key: %s: %s -> %s\n", change.Key, change.Old, change.New)
		}
		fmt.Fprintf(opts.Out, "noop: %t\nrestart-required: %t\n", plan.Noop, plan.RestartRequired)
		for _, conflict := range plan.Conflicts {
			fmt.Fprintf(opts.Out, "conflict: %s\n", conflict)
		}
		for _, impact := range plan.Impact {
			fmt.Fprintf(opts.Out, "impact: %s\n", impact)
		}
		return 0
	case "apply":
		profile := tcpProfile(rest)
		if _, err := tcpcfg.ProfileKeys(profile); err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
		}
		if err := tcpSandboxGate(m, cfg); err != nil {
			return fail(opts, cfg, err)
		}
		if !hasFlag(rest, "--confirm") {
			if !opts.TTY {
				return fail(opts, cfg, &change.UsageError{Msg: "tcp apply needs --confirm (or an interactive TTY confirmation)"})
			}
			fmt.Fprintf(opts.Out, "Apply TCP profile %s? [y/N] ", profile)
			scanner := bufio.NewScanner(opts.In)
			if !scanner.Scan() {
				fmt.Fprint(opts.Err, "aborted: no confirmation\n")
				return 2
			}
			switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
			case "y", "yes":
			default:
				fmt.Fprint(opts.Out, "cancelled: no changes were written\n")
				return 0
			}
		}
		result, err := m.Apply(profile)
		if cfg.json {
			if err != nil {
				_ = writeJSONNoExit(opts.Out, result)
				return fail(opts, cfg, err)
			}
			return writeJSON(opts, result)
		}
		if err != nil {
			return fail(opts, cfg, err)
		}
		printTCPResult(opts, "apply", result)
		return 0
	case "rollback":
		if err := tcpSandboxGate(m, cfg); err != nil {
			return fail(opts, cfg, err)
		}
		result, err := m.Rollback()
		if cfg.json {
			if err != nil {
				_ = writeJSONNoExit(opts.Out, result)
				return fail(opts, cfg, err)
			}
			return writeJSON(opts, result)
		}
		if err != nil {
			return fail(opts, cfg, err)
		}
		printTCPResult(opts, "rollback", result)
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func tcpProfile(args []string) string {
	if profile := flagValue(args, "--profile"); profile != "" {
		return profile
	}
	return tcpcfg.ProfileBBRFQ
}

// tcpSandboxGate keeps writes inside a marked disposable root. A real root
// still goes through the root check inside the manager.
func tcpSandboxGate(m *tcpcfg.Manager, cfg config) error {
	if !m.Paths.IsSandbox() {
		return nil
	}
	if err := m.Paths.RequireSandbox(); err != nil {
		return &change.UsageError{Msg: "tcp mutation requires a marked disposable sandbox: " + err.Error()}
	}
	return nil
}

func printTCPResult(opts Options, action string, result tcpcfg.Result) {
	fmt.Fprintf(opts.Out, "%s: changed=%t noop=%t", action, result.Changed, result.Noop)
	if result.Profile != "" {
		fmt.Fprintf(opts.Out, " profile=%s", result.Profile)
	}
	if result.FilePath != "" {
		fmt.Fprintf(opts.Out, " file=%s", result.FilePath)
	}
	fmt.Fprintln(opts.Out)
	for _, change := range result.Applied {
		fmt.Fprintf(opts.Out, "key: %s: %s -> %s\n", change.Key, change.Old, change.New)
	}
	if result.Message != "" {
		fmt.Fprintf(opts.Out, "message: %s\n", result.Message)
	}
}
