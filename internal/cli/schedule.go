package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
)

// scheduleCommand implements the native replacement for the legacy cron jobs.
func scheduleCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	if rc, ok := checkFlags(opts, cfg, rest, "schedule "+sub); ok && rc != 0 {
		return rc
	}
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
		acmeDir := flagValue(rest, "--acme-directory")
		if acmeDir == "" && hasFlag(rest, "--acme-production") {
			acmeDir = schedule.ACMEProductionDirectory
		}
		if acmeDir == "" {
			acmeDir = os.Getenv("IDLELEO_ACME_DIRECTORY")
		}
		rep, err := schedule.Install(ctx, schedule.InstallOptions{
			Root:            cfg.root,
			IntervalSeconds: interval,
			GeodataURL:      flagValue(rest, "--geodata-url"),
			CertDomain:      flagValue(rest, "--cert-domain"),
			CertWebroot:     flagValue(rest, "--cert-webroot"),
			CertFile:        flagValue(rest, "--cert-out"),
			CertKeyFile:     flagValue(rest, "--cert-key-out"),
			ACMEDirectory:   acmeDir,
			ACMEEmail:       flagValue(rest, "--acme-email"),
			AlertWebhook:    flagValue(rest, "--alert-webhook"),
		})
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "config=%s\nservice=%s\ntimer=%s\nalertService=%s\ninterval=%ds\njobs=%s\nsystemd=%s\n",
			rep.ConfigPath, rep.ServicePath, rep.TimerPath, rep.AlertServicePath,
			rep.IntervalSeconds, strings.Join(rep.Jobs, ","), rep.Systemd)
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
		if rep.LogWarning != "" {
			fmt.Fprintf(opts.Err, "log warning: %s\n", rep.LogWarning)
		}
		return code
	case "alert":
		job := flagValue(rest, "--job")
		if job == "" {
			job = "service-failure"
		}
		detail := flagValue(rest, "--detail")
		if detail == "" {
			detail = "scheduled job failed"
		}
		a, alertErr := schedule.RecordAlert(ctx, cfg.root, job, detail, time.Now().UTC().Format(time.RFC3339))
		if cfg.json {
			if rc := writeJSON(opts, a); rc != 0 {
				return rc
			}
		} else {
			fmt.Fprintf(opts.Out, "alert=%s result=%s webhook=%s\n", a.Job, a.Result, a.Webhook)
		}
		if alertErr != nil {
			// An alert that never reached disk is a lost alert: fail so systemd
			// records it instead of reporting a successful alert unit.
			fmt.Fprint(opts.Err, alertErr.Error()+"\n")
			return 1
		}
		return 0
	case "status":
		rep, err := schedule.Status(ctx, cfg.root)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			if rc := writeJSON(opts, rep); rc != 0 {
				return rc
			}
		} else {
			for _, line := range rep.SummaryLines() {
				fmt.Fprintln(opts.Out, line)
			}
		}
		if rep.AlertsUnreadable {
			return 1
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
