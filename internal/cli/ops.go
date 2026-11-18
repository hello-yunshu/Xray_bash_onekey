package cli

import (
	"context"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/app"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/ops"
)

// opsCommand prints a read-only operator summary.
func opsCommand(ctx context.Context, opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 || args[0] != "summary" {
		return usage(opts, cfg.lang, "help")
	}
	if rc, ok := checkFlags(opts, cfg, args[1:], "ops summary"); ok && rc != 0 {
		return rc
	}
	cfg.json = cfg.json || hasFlag(args[1:], "--json")
	report, err := ops.Summary(ctx, a)
	if err != nil {
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprint(opts.Out, ops.Text(report))
	return 0
}
