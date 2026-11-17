package cli

import (
	"context"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
)

// xrayTLS changes the managed Nginx TLS version. It replaces Bash's
// interactive `-tls` entry: no sed-in-place without a rollback.
func xrayTLS(ctx context.Context, opts Options, cfg config, args []string) int {
	version := flagValue(args, "--version")
	if version != deploy.TLSVersion13 && version != deploy.TLSVersion12Plus {
		return usage(opts, cfg.lang, "help")
	}
	rep, err := deploy.SetTLSVersion(ctx, deploy.TLSSpec{
		Root:                 cfg.root,
		AllowContainerWrites: hasFlag(args, "--container"),
		Version:              version,
	})
	cfg.json = cfg.json || hasFlag(args, "--json")
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, rep)
		}
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, rep)
	}
	fmt.Fprintf(opts.Out, "mode=%s version=%s changed=%t file=%s reloaded=%t\n",
		rep.Mode, rep.Version, rep.Changed, rep.File, rep.Reloaded)
	for _, w := range rep.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}
