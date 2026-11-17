package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
)

// xrayBalance manages the Nginx upstream backends of a managed front. It never
// touches the Xray runtime config or the stream main config.
func xrayBalance(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	action, rest := args[0], args[1:]
	upstream := flagValue(rest, "--upstream")
	if upstream == "" {
		return usage(opts, cfg.lang, "help")
	}
	spec := deploy.BalanceSpec{
		Root:                 cfg.root,
		AllowContainerWrites: hasFlag(rest, "--container"),
		Upstream:             upstream,
		Host:                 flagValue(rest, "--host"),
		Probe:                hasFlag(rest, "--probe"),
	}
	if raw := flagValue(rest, "--port"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return usage(opts, cfg.lang, "help")
		}
		spec.Port = v
	}
	if raw := flagValue(rest, "--weight"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return usage(opts, cfg.lang, "help")
		}
		spec.Weight = v
	}

	var report deploy.BalanceReport
	var err error
	switch action {
	case "list":
		report, err = deploy.ListBalance(spec)
	case "add", "remove":
		if spec.Host == "" {
			return usage(opts, cfg.lang, "help")
		}
		if action == "add" {
			report, err = deploy.AddBalance(ctx, spec)
		} else {
			report, err = deploy.RemoveBalance(ctx, spec)
		}
	default:
		return usage(opts, cfg.lang, "help")
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, report)
		}
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, report)
	}
	for _, b := range report.Backends {
		fmt.Fprintf(opts.Out, "%s\t%d\t%d\t%s\n", b.Host, b.Port, b.Weight, b.File)
	}
	if report.Changed {
		fmt.Fprintf(opts.Out, "changed: upstream=%s file=%s probed=%t\n", report.Upstream, report.File, report.Probed)
	}
	for _, w := range report.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}
