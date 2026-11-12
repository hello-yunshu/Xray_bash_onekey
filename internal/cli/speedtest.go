package cli

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/speedtest"
)

// speedtestCommand replaces the downloaded superspeed.sh. It only reads the
// network and never writes host state, so it stays usable without root.
func speedtestCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if rc, ok := checkFlags(opts, cfg, args, "speedtest"); ok && rc != 0 {
		return rc
	}
	options := speedtest.Options{Server: flagValue(args, "--server")}
	if raw := flagValue(args, "--bytes"); raw != "" {
		bytes, err := strconv.Atoi(raw)
		if err != nil || bytes <= 0 {
			return usage(opts, cfg.lang, "help")
		}
		options.Bytes = bytes
	}
	if raw := flagValue(args, "--samples"); raw != "" {
		samples, err := strconv.Atoi(raw)
		if err != nil || samples <= 0 {
			return usage(opts, cfg.lang, "help")
		}
		options.Samples = samples
	}
	if raw := flagValue(args, "--timeout"); raw != "" {
		timeout, err := time.ParseDuration(raw)
		if err != nil || timeout <= 0 {
			return usage(opts, cfg.lang, "help")
		}
		options.Timeout = timeout
	}

	cfg.json = cfg.json || hasFlag(args, "--json")
	result, err := speedtest.Run(ctx, options)
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, result)
		}
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, result)
	}
	fmt.Fprintf(opts.Out, "server: %s\n", result.Server)
	fmt.Fprintf(opts.Out, "down: %.2f Mbps\n", result.DownMbps)
	fmt.Fprintf(opts.Out, "bytes: %d\nduration: %s\n", result.Bytes,
		(time.Duration(result.DurationMS) * time.Millisecond).Round(time.Millisecond))
	for i, value := range result.Samples {
		fmt.Fprintf(opts.Out, "sample[%d]: %.2f Mbps\n", i+1, value)
	}
	return 0
}
