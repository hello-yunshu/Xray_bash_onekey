package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
)

// xrayGuard implements `xray guard show|set` for the online unknown-SNI policy
// of a managed Reality+Nginx front (Bash menu 2 > 2 > 5).
func xrayGuard(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	action, rest := args[0], args[1:]
	cfg.json = cfg.json || hasFlag(rest, "--json")
	switch action {
	case "show":
		status, err := deploy.InspectSNIGuard(cfg.root)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, status)
		}
		fmt.Fprintf(opts.Out, "tls=%s applicable=%t status=%s enabled=%t policy=%s",
			status.TLS, status.Applicable, status.Status, status.Enabled, status.Policy)
		if status.DecoyDomain != "" {
			fmt.Fprintf(opts.Out, " decoyDomain=%s", status.DecoyDomain)
		}
		if status.DenyPort != 0 {
			fmt.Fprintf(opts.Out, " denyPort=%d", status.DenyPort)
		}
		fmt.Fprintf(opts.Out, " metadataSynced=%t\n", status.MetadataSynced)
		for _, source := range status.Evidence {
			fmt.Fprintf(opts.Out, "evidence=%s\n", source)
		}
		for _, warning := range status.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", warning)
		}
		return 0
	case "set":
		policy := flagValue(rest, "--policy")
		if policy == "" {
			return fail(opts, cfg, &change.UsageError{Msg: "--policy is required (isolate, reject or decoy)"})
		}
		var decoyIPs []string
		for _, raw := range strings.Split(flagValue(rest, "--decoy-ip"), ",") {
			if ip := strings.TrimSpace(raw); ip != "" {
				decoyIPs = append(decoyIPs, ip)
			}
		}
		report, err := deploy.SetSNIGuard(ctx, deploy.SNIGuardSpec{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
			Policy:               policy,
			DecoyDomain:          flagValue(rest, "--decoy-domain"),
			DecoyCert:            flagValue(rest, "--decoy-cert"),
			DecoyKey:             flagValue(rest, "--decoy-key"),
			DecoyIPs:             decoyIPs,
			DryRun:               hasFlag(rest, "--dry-run"),
		})
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "mode=%s policy=%s denyPort=%d changed=%t dryRun=%t reloaded=%t\n",
			report.Mode, report.Policy, report.DenyPort, report.Changed, report.DryRun, report.Reloaded)
		if report.DecoyDomain != "" {
			fmt.Fprintf(opts.Out, "decoyDomain=%s selfSigned=%t\n", report.DecoyDomain, report.SelfSigned)
		}
		for _, file := range report.Files {
			fmt.Fprintf(opts.Out, "file=%s\n", file)
		}
		for _, warning := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", warning)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}
