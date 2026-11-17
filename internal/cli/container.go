package cli

import (
	"context"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/container"
)

// containerCommand activates the managed services without assuming systemd.
func containerCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	if rc, ok := checkFlags(opts, cfg, rest, "container "+sub); ok && rc != 0 {
		return rc
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")
	spec := container.Spec{
		Root:                 cfg.root,
		AllowContainerWrites: hasFlag(rest, "--container"),
		DryRun:               hasFlag(rest, "--dry-run"),
	}
	switch sub {
	case "status":
		report, err := container.Status(cfg.root)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		printContainerStatus(opts, report.Root, string(report.Mode), report.InContainer, report.Xray, report.Nginx, report.Warnings)
		return 0
	case "up":
		report, err := container.Up(ctx, spec)
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, report)
			}
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "mode=%s started=%v skipped=%v\n", report.Mode, report.Started, report.Skipped)
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		return 0
	case "down":
		report, err := container.Down(ctx, spec)
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, report)
			}
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "mode=%s stopped=%v\n", report.Mode, report.Stopped)
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func printContainerStatus(opts Options, root, mode string, inContainer bool, xray, nginx container.ServiceState, warnings []string) {
	fmt.Fprintf(opts.Out, "root=%s inContainer=%t mode=%s\n", root, inContainer, mode)
	for _, svc := range []struct {
		name string
		st   container.ServiceState
	}{{"xray", xray}, {"nginx", nginx}} {
		fmt.Fprintf(opts.Out, "%s: required=%t config=%t pid=%d alive=%t source=%s\n",
			svc.name, svc.st.Required, svc.st.Config, svc.st.Pid, svc.st.Alive, svc.st.Source)
	}
	for _, w := range warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
}
