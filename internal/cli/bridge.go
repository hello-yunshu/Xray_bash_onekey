package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/legacybridge"
)

func bridgeCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	cfg.json = cfg.json || hasFlag(rest, "--json")
	switch sub {
	case "audit":
		audit, err := legacybridge.AuditMigration(cfg.root)
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, audit)
		}
		fmt.Fprintf(opts.Out, "verdict: %s\nrole: %s tls: %s transport: %s\n",
			audit.Verdict, audit.Role, audit.TLS, audit.Transport)
		fmt.Fprintf(opts.Out, "legacy: %s xray: %s users: %d runtime: %s\n",
			audit.LegacyVersion, audit.XrayVersion, audit.UserCount, audit.RuntimeSHA256)
		fmt.Fprintf(opts.Out, "entry: %s\n", audit.Entry.Path)
		for _, f := range audit.Findings {
			fmt.Fprintf(opts.Out, "finding[%s]: %s\n", f.Severity, f.Code+" "+f.Message)
		}
		return 0
	case "prepare":
		report, _, err := legacybridge.Prepare(ctx, legacybridge.PrepareOptions{
			Root:                 cfg.root,
			Candidate:            flagValue(rest, "--candidate"),
			Recovery:             flagValue(rest, "--recovery"),
			AllowContainerWrites: hasFlag(rest, "--container"),
		})
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "state=%s verdict=%s candidate=%s\n", report.State, report.Verdict, report.CandidateSHA256)
		fmt.Fprintf(opts.Out, "plan=%s snapshot=%s\n", report.PlanPath, report.SnapshotPath)
		fmt.Fprintf(opts.Out, "projectCronLines=%d\n", report.ProjectCronLines)
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		return 0
	case "validate":
		report, err := legacybridge.Validate(ctx, legacybridge.ValidateOptions{
			Root:                 cfg.root,
			XrayBin:              flagValue(rest, "--xray"),
			NginxBin:             flagValue(rest, "--nginx"),
			AllowContainerWrites: hasFlag(rest, "--container"),
		})
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "state=%s xray=%d nginx=%d candidate=%d\n",
			report.State, report.XrayExit, report.NginxExit, report.CandidateExit)
		return 0
	case "activate":
		report, err := legacybridge.Activate(ctx, legacybridge.ActivateOptions{
			Root:                 cfg.root,
			Crontab:              flagValue(rest, "--crontab"),
			Fault:                flagValue(rest, "--fault"),
			AllowContainerWrites: hasFlag(rest, "--container"),
		})
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "state=%s entry=%s\n", report.State, report.Entry)
		fmt.Fprintf(opts.Out, "removedCronLines=%d deferred=%v\n", report.RemovedCron, report.DeferredTasks)
		fmt.Fprintf(opts.Out, "service: xray=%s nginx=%s enabled=%s\n",
			report.ServiceXray, report.ServiceNginx, report.ServiceEnabled)
		return 0
	case "recover":
		report, err := legacybridge.Recover(legacybridge.RecoverOptions{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
		})
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, report)
		}
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if !cfg.json {
			fmt.Fprintf(opts.Out, "previous=%s state=%s\n", report.PreviousState, report.State)
			for _, a := range report.Actions {
				fmt.Fprintf(opts.Out, "action=%s\n", a)
			}
		}
		return 0
	case "status":
		report, err := legacybridge.Status(cfg.root)
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "state=%s verdict=%s entry=%s\n", report.State, report.Verdict, report.Entry)
		if len(report.DeferredTasks) > 0 {
			fmt.Fprintf(opts.Out, "deferred=%v\n", report.DeferredTasks)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func recoverCommand(opts Options, cfg config, args []string) int {
	report, err := legacybridge.Recover(legacybridge.RecoverOptions{
		Root:                 cfg.root,
		AllowContainerWrites: hasFlag(args, "--container"),
	})
	if hasFlag(args, "--json") || cfg.json {
		_ = writeJSONNoExit(opts.Out, report)
	}
	if err != nil {
		return bridgeFail(opts, cfg, err)
	}
	if !hasFlag(args, "--json") && !cfg.json {
		fmt.Fprintf(opts.Out, "state=%s\n", report.State)
		for _, a := range report.Actions {
			fmt.Fprintf(opts.Out, "action=%s\n", a)
		}
	}
	return 0
}

func bridgeFail(opts Options, cfg config, err error) int {
	var be *legacybridge.Error
	if errors.As(err, &be) {
		fmt.Fprint(opts.Err, be.Error()+"\n")
		return be.Code
	}
	return fail(opts, cfg, err)
}
