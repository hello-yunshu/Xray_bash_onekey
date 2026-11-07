package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/service"
)

// serviceCommand is the service-class CLI the legacy Bash menu exposed.
func serviceCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	cfg.json = cfg.json || hasFlag(rest, "--json")
	unit := flagValue(rest, "--unit")
	if unit == "" {
		unit = "xray"
	}

	switch sub {
	case "status":
		rep, err := service.Status(ctx, cfg.root)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		for _, u := range rep.Units {
			fmt.Fprintf(opts.Out, "%s active=%s enabled=%s\n", u.Unit, u.Active, u.Enabled)
		}
		return 0
	case "start", "stop", "restart", "reload":
		if cfg.root != "/" {
			fmt.Fprint(opts.Err, service.ErrRealRootOnly.Error()+"\n")
			return 2
		}
		if err := host.RequireSystemWrite(cfg.root, hasFlag(rest, "--container")); err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		if err := service.CheckUnit(unit); err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		rep, err := service.Apply(ctx, cfg.root, service.Action(sub), unit)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "%s exit=%d output=%s\n", rep.Systemctl, rep.ExitCode, rep.Output)
		return 0
	case "logs":
		lines := 50
		if v := flagValue(rest, "--lines"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				lines = n
			}
		}
		rep, err := service.Logs(ctx, cfg.root, unit, lines)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "%s\n", rep.Output)
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}
