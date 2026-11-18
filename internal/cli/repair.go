package cli

import (
	"context"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/repair"
)

// repairCommand applies the reversible subset of doctor findings. A dry run is
// read-only; every other mode is gated like a mutation.
func repairCommand(ctx context.Context, opts Options, cfg config, paths host.Paths, args []string) int {
	if rc, ok := checkFlags(opts, cfg, args, "repair"); ok && rc != 0 {
		return rc
	}
	dryRun := hasFlag(args, "--dry-run")
	if !dryRun {
		if err := host.RequireSystemWrite(paths.Root, hasFlag(args, "--container")); err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
		}
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	rep, err := repair.Run(ctx, paths.Root, repair.Options{
		DryRun:  dryRun,
		FixLock: hasFlag(args, "--fix-lock"),
	})
	if err != nil {
		return fail(opts, cfg, err)
	}
	if cfg.json {
		if rc := writeJSON(opts, rep); rc != 0 {
			return rc
		}
	} else {
		for _, a := range rep.Actions {
			fmt.Fprintf(opts.Out, "action: %s\n", a)
		}
		for _, r := range rep.Remaining {
			fmt.Fprintf(opts.Out, "remaining: %s\n", r)
		}
		fmt.Fprintf(opts.Out, "summary: actions=%d remaining=%d healthy=%t\n",
			len(rep.Actions), len(rep.Remaining), rep.Healthy)
	}
	if !rep.Healthy {
		return 1
	}
	return 0
}
