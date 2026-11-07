package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/legacybridge"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
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
		if hasFlag(rest, "--summary") {
			printAuditSummary(opts, cfg.root, audit)
			return 0
		}
		fmt.Fprintf(opts.Out, "verdict: %s\nrole: %s tls: %s transport: %s\n",
			audit.Verdict, audit.Role, audit.TLS, audit.Transport)
		fmt.Fprintf(opts.Out, "legacy: %s xray: %s users: %d runtime: %s\n",
			audit.LegacyVersion, audit.XrayVersion, audit.UserCount, audit.RuntimeSHA256)
		fmt.Fprintf(opts.Out, "entry: %s\n", audit.Entry.Path)
		fmt.Fprintf(opts.Out, "rill: %s installed=%t mode=%s age=%ds\n",
			audit.Rill.Status, audit.Rill.Installed, audit.Rill.Mode, audit.Rill.ObservationAgeSeconds)
		fmt.Fprintf(opts.Out, "customItems: %d permissionFixes: %d\n", len(audit.CustomItems), len(audit.PermissionFixes))
		for _, f := range audit.Findings {
			fmt.Fprintf(opts.Out, "finding[%s]: %s\n", f.Severity, f.Code+" "+f.Message)
		}
		return 0
	case "prepare":
		report, _, err := legacybridge.Prepare(ctx, legacybridge.PrepareOptions{
			Root:                 cfg.root,
			Candidate:            flagValue(rest, "--candidate"),
			Recovery:             flagValue(rest, "--recovery"),
			AcknowledgeCustom:    hasFlag(rest, "--acknowledge-custom"),
			Fault:                flagValue(rest, "--fault"),
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
		fmt.Fprintf(opts.Out, "projectCronLines=%d customItems=%d customAcknowledged=%t permissionFixes=%d rill=%s\n",
			report.ProjectCronLines, report.CustomItems, report.CustomAcked, report.PermissionFixes, report.RillStatus)
		fmt.Fprintf(opts.Out, "scheduledJobs=%v\n", report.ScheduledJobs)
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
		fmt.Fprintf(opts.Out, "candidateStatusExit=%d installed=%t matchesMetadata=%t\n",
			report.CandidateStatusExit, report.CandidateInstalled, report.CandidateMatchesMetadata)
		fmt.Fprintf(opts.Out, "rill=%s unchanged=%t\n", report.RillStatus, report.RillUnchanged)
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
		fmt.Fprintf(opts.Out, "removedCronLines=%d retainedCronLines=%v deferred=%v timer=%s\n",
			report.RemovedCron, report.RetainedCron, report.DeferredTasks, report.Timer)
		fmt.Fprintf(opts.Out, "scheduledJobs=%v\n", report.ScheduledJobs)
		for _, d := range report.DegradedJobs {
			fmt.Fprintf(opts.Out, "degraded=%s\n", d)
		}
		fmt.Fprintf(opts.Out, "permissionFixes=%d rill=%s rillUnchanged=%t\n",
			report.PermissionFixes, report.RillStatus, report.RillUnchanged)
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
			fmt.Fprintf(opts.Out, "previous=%s state=%s rillUnchanged=%t\n", report.PreviousState, report.State, report.RillUnchanged)
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
		fmt.Fprintf(opts.Out, "state=%s verdict=%s entry=%s rill=%s\n",
			report.State, report.Verdict, report.Entry, report.RillStatus)
		fmt.Fprintf(opts.Out, "scheduledJobs=%v\n", report.ScheduledJobs)
		for _, d := range report.DegradedJobs {
			fmt.Fprintf(opts.Out, "degraded=%s\n", d)
		}
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
		fmt.Fprintf(opts.Out, "state=%s rillUnchanged=%t\n", report.State, report.RillUnchanged)
		for _, a := range report.Actions {
			fmt.Fprintf(opts.Out, "action=%s\n", a)
		}
	}
	return 0
}

// printAuditSummary is the complete change summary shown before a human
// consent prompt. It includes every category the migration touches.
func printAuditSummary(opts Options, root string, a legacybridge.Audit) {
	fmt.Fprintf(opts.Out, "变更摘要 / migration summary (root=%s)\n", root)
	fmt.Fprintf(opts.Out, "verdict=%s role=%s tls=%s transport=%s port=%d nginxRequired=%t\n",
		a.Verdict, a.Role, a.TLS, a.Transport, a.Port, a.NginxRequired)
	fmt.Fprintf(opts.Out, "legacyVersion=%s xrayVersion=%s users=%d\n", a.LegacyVersion, a.XrayVersion, a.UserCount)
	fmt.Fprintf(opts.Out, "runtime=%s bytes=%d sha256=%s\n", a.RuntimePath, a.RuntimeBytes, a.RuntimeSHA256)
	fmt.Fprintf(opts.Out, "certificates=%d nginxFiles=%d projectCronLines=%d geoLegacyCron=%t\n",
		len(a.CertFiles), len(a.NginxFiles), a.ProjectCronLines, a.GeoLegacyCron)
	fmt.Fprintf(opts.Out, "entry=%s symlink=%t target=%s\n", a.Entry.Path, a.Entry.IsSymlink, a.Entry.LinkTarget)
	fmt.Fprintf(opts.Out, "rill=status:%s installed:%t mode:%s observationAge:%ds sha256:%s\n",
		a.Rill.Status, a.Rill.Installed, a.Rill.Mode, a.Rill.ObservationAgeSeconds, a.Rill.ObservationSHA256)
	fmt.Fprintf(opts.Out, "customItems=%d\n", len(a.CustomItems))
	for _, c := range a.CustomItems {
		fmt.Fprintf(opts.Out, "custom[%s] %s: %s\n", c.Kind, c.Path, c.Detail)
	}
	fmt.Fprintf(opts.Out, "permissionFixes=%d\n", len(a.PermissionFixes))
	for _, p := range a.PermissionFixes {
		fmt.Fprintf(opts.Out, "permission[%s] %s->%s: %s\n", p.Path, p.OldMode, p.NewMode, p.Reason)
	}
	fmt.Fprintf(opts.Out, "scheduledJobs=%v\n", schedule.Jobs)
	for _, d := range schedule.DegradedJobs {
		fmt.Fprintf(opts.Out, "degraded=%s\n", d)
	}
	for _, f := range a.Findings {
		fmt.Fprintf(opts.Out, "finding[%s]: %s %s\n", f.Severity, f.Code, f.Message)
	}
}

func bridgeFail(opts Options, cfg config, err error) int {
	var be *legacybridge.Error
	if errors.As(err, &be) {
		fmt.Fprint(opts.Err, be.Error()+"\n")
		return be.Code
	}
	return fail(opts, cfg, err)
}
