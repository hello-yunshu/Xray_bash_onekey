package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
)

// scheduleCommand implements the native replacement for the legacy cron jobs.
func scheduleCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	cfg.json = cfg.json || hasFlag(rest, "--json")

	switch sub {
	case "install":
		if err := schedule.RequireWriteAccess(cfg.root, hasFlag(rest, "--container")); err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		interval := schedule.DefaultIntervalSeconds
		if v := flagValue(rest, "--interval"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				fmt.Fprint(opts.Err, "invalid --interval\n")
				return 2
			}
			interval = n
		}
		rep, err := schedule.Install(ctx, schedule.InstallOptions{
			Root:            cfg.root,
			IntervalSeconds: interval,
			GeodataURL:      flagValue(rest, "--geodata-url"),
		})
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "config=%s\nservice=%s\ntimer=%s\ninterval=%ds\njobs=%s\nsystemd=%s\n",
			rep.ConfigPath, rep.ServicePath, rep.TimerPath, rep.IntervalSeconds, strings.Join(rep.Jobs, ","), rep.Systemd)
		for _, d := range rep.DegradedJobs {
			fmt.Fprintf(opts.Out, "degraded=%s\n", d)
		}
		return 0
	case "remove":
		if err := schedule.RequireWriteAccess(cfg.root, hasFlag(rest, "--container")); err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		actions, err := schedule.Remove(ctx, cfg.root)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, map[string]any{"schemaVersion": 1, "actions": actions})
		}
		for _, a := range actions {
			fmt.Fprintf(opts.Out, "%s\n", a)
		}
		return 0
	case "run":
		rep, err := schedule.Run(ctx, schedule.RunOptions{Root: cfg.root, Jobs: jobList(rest)})
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		code := 0
		for _, res := range rep.Results {
			if res.Result == "failed" {
				code = 1
			}
		}
		if cfg.json {
			if rc := writeJSON(opts, rep); rc != 0 {
				return rc
			}
			return code
		}
		for _, res := range rep.Results {
			fmt.Fprintf(opts.Out, "%s job=%s result=%s %s\n", res.At, res.Job, res.Result, res.Detail)
		}
		return code
	case "status":
		rep, err := schedule.Status(ctx, cfg.root)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		for _, line := range rep.SummaryLines() {
			fmt.Fprintln(opts.Out, line)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func jobList(args []string) []string {
	v := flagValue(args, "--jobs")
	if v == "" {
		v = flagValue(args, "--job")
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
