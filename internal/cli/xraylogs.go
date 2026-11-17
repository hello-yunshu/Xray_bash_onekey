package cli

import (
	"context"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
)

func xrayLogs(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	action, rest := args[0], args[1:]
	spec := deploy.LogsSpec{Root: cfg.root, AllowContainerWrites: hasFlag(rest, "--container")}
	switch action {
	case "clean":
		if !hasFlag(rest, "--yes") {
			return fail(opts, cfg, &change.UsageError{
				Msg: "xray logs clean truncates every *.log under the Xray and Nginx log directories; re-run with --yes to confirm",
			})
		}
		report, err := deploy.CleanLogs(ctx, spec)
		if err != nil {
			return fail(opts, cfg, err)
		}
		cfg.json = cfg.json || hasFlag(rest, "--json")
		if cfg.json {
			return writeJSON(opts, report)
		}
		for _, path := range report.Truncated {
			fmt.Fprintf(opts.Out, "truncated: %s\n", path)
		}
		for _, failure := range report.Failed {
			fmt.Fprintf(opts.Out, "warning: could not truncate %s (%s)\n", failure.Path, failure.Error)
		}
		fmt.Fprintf(opts.Out, "freedBytes=%d\n", report.Freed)
		if len(report.Failed) > 0 {
			fmt.Fprintf(opts.Out, "warning: %d log file(s) were not cleaned\n", len(report.Failed))
		}
		return 0
	case "rotate":
		if len(rest) == 0 {
			return usage(opts, cfg.lang, "help")
		}
		mode, flags := rest[0], rest[1:]
		spec.AllowContainerWrites = hasFlag(flags, "--container")
		var (
			report deploy.RotationReport
			err    error
		)
		switch mode {
		case "enable":
			report, err = deploy.EnableLogRotation(ctx, spec)
		case "disable":
			report, err = deploy.DisableLogRotation(ctx, spec)
		default:
			return usage(opts, cfg.lang, "help")
		}
		if err != nil {
			return fail(opts, cfg, err)
		}
		cfg.json = cfg.json || hasFlag(flags, "--json")
		if cfg.json {
			return writeJSON(opts, report)
		}
		if report.Enabled {
			fmt.Fprintf(opts.Out, "logrotate: %s\n", report.ConfigPath)
			fmt.Fprintf(opts.Out, "dropin: %s\n", report.DropinPath)
			fmt.Fprintf(opts.Out, "timerActive=%t\n", report.TimerActive)
		} else {
			fmt.Fprintf(opts.Out, "removed: %s\n", fmt.Sprint(report.Removed))
		}
		for _, warning := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", warning)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}
