package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/doctor"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// doctorCommand runs read-only diagnostics and uses exit 1 for a failed check
// so monitoring can alert without parsing text.
func doctorCommand(ctx context.Context, opts Options, cfg config, paths host.Paths, args []string) int {
	if rc, ok := checkFlags(opts, cfg, args, "doctor"); ok && rc != 0 {
		return rc
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	report := doctor.RunWith(ctx, paths.Root, doctor.Options{Deep: hasFlag(args, "--deep")})
	if cfg.json {
		if rc := writeJSON(opts, report); rc != 0 {
			return rc
		}
	} else {
		for _, c := range report.Checks {
			fmt.Fprintf(opts.Out, "[%s] %-16s %s", statusLabel(c.Status), c.ID, c.Message)
			if c.Detail != "" {
				fmt.Fprintf(opts.Out, " (%s)", c.Detail)
			}
			fmt.Fprintln(opts.Out)
			if c.Suggestion != "" {
				fmt.Fprintf(opts.Out, "        suggestion: %s\n", c.Suggestion)
			}
		}
		fmt.Fprintf(opts.Out, "summary: pass=%d warn=%d fail=%d unknown=%d skipped=%d\n",
			report.Summary.OK, report.Summary.Warn, report.Summary.Fail,
			report.Summary.Unknown, report.Summary.Skip)
	}
	if !report.Healthy {
		return 1
	}
	return 0
}

func statusLabel(s doctor.Status) string {
	switch s {
	case doctor.StatusOK:
		return "PASS"
	case doctor.StatusWarn:
		return "WARN"
	case doctor.StatusFail:
		return "FAIL"
	case doctor.StatusUnknown:
		return "UNKNOWN"
	case doctor.StatusSkip:
		return "SKIPPED"
	default:
		return strings.ToUpper(string(s))
	}
}
