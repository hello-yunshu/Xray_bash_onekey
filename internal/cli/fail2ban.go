package cli

import (
	"context"
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
)

// fail2banCommand owns the fail2ban vocabulary. Every mutating path writes only
// under /etc/fail2ban or /etc/idleleo and never installs the package.
func fail2banCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	flagArgs, flagKey := rest, "fail2ban "+sub
	if (sub == "trust" || sub == "jail") && len(rest) > 0 {
		flagArgs, flagKey = rest[1:], flagKey+" "+rest[0]
	}
	if rc, ok := checkFlags(opts, cfg, flagArgs, flagKey); ok && rc != 0 {
		return rc
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")

	switch sub {
	case "status":
		status, err := deploy.Fail2banStatusReport(ctx)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, status)
		}
		if !status.Installed {
			fmt.Fprintln(opts.Out, "installed=false")
			fmt.Fprintln(opts.Out, "hint=install fail2ban first: apt-get install -y fail2ban")
			return 0
		}
		fmt.Fprintln(opts.Out, "installed=true")
		for _, jail := range status.Jails {
			fmt.Fprintf(opts.Out, "jail=%s currently_banned=%d total_banned=%d\n",
				jail.Name, jail.CurrentlyBanned, jail.TotalBanned)
		}
		return 0
	case "install":
		report, err := deploy.InstallFail2ban(ctx, deploy.Fail2banSpec{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
			DisableNoHost:        hasFlag(rest, "--no-nginx-no-host"),
			DisableTLSError:      hasFlag(rest, "--no-nginx-tls-error"),
		})
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		for _, jail := range report.Jails {
			if jail.Written {
				fmt.Fprintf(opts.Out, "jail=%s written=true log=%s\n", jail.Name, jail.LogPath)
				continue
			}
			fmt.Fprintf(opts.Out, "jail=%s written=false reason=%s\n", jail.Name, jail.Reason)
		}
		for _, file := range report.Files {
			fmt.Fprintf(opts.Out, "file=%s\n", file)
		}
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		fmt.Fprintf(opts.Out, "service=fail2ban restarted=%t\n", report.ServiceRestarted)
		if report.SSHClientIP != "" {
			fmt.Fprintf(opts.Out, "ssh_client_ip=%s\n", report.SSHClientIP)
			fmt.Fprintf(opts.Out, "trust_hint=%s\n", report.TrustHint)
			fmt.Fprintln(opts.Out, "note=not applied automatically: a dynamic client address would whitelist a stranger")
		}
		return 0
	case "uninstall":
		report, err := deploy.UninstallFail2ban(ctx, deploy.UninstallFail2banSpec{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
			Force:                hasFlag(rest, "--force"),
		})
		if err != nil {
			return fail(opts, cfg, err)
		}
		if report.NeedForce {
			if cfg.json {
				if rc := writeJSON(opts, report); rc != 0 {
					return rc
				}
			} else {
				fmt.Fprintln(opts.Out, "no Idleleo fail2ban manifest found; candidates:")
				for _, c := range report.Candidates {
					fmt.Fprintf(opts.Out, "  %s\n", c)
				}
			}
			return fail(opts, cfg, &change.UsageError{
				Msg: "no fail2ban manifest found; re-run with --force to remove only these Idleleo candidates",
			})
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		for _, file := range report.Removed {
			fmt.Fprintf(opts.Out, "removed=%s\n", file)
		}
		for _, file := range report.Preserved {
			fmt.Fprintf(opts.Out, "preserved=%s reason=not created by Idleleo\n", file)
		}
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		fmt.Fprintf(opts.Out, "service=fail2ban restarted=%t\n", report.ServiceRestarted)
		return 0
	case "banned":
		status, err := deploy.Fail2banBanned(ctx, flagValue(rest, "--jail"))
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, status)
		}
		for _, jail := range status.Jails {
			fmt.Fprintf(opts.Out, "jail=%s currently_banned=%d total_banned=%d\n",
				jail.Name, jail.CurrentlyBanned, jail.TotalBanned)
			for _, ip := range jail.BannedIPs {
				fmt.Fprintf(opts.Out, "banned=%s jail=%s\n", ip, jail.Name)
			}
		}
		return 0
	case "unban":
		jail, ip := flagValue(rest, "--jail"), flagValue(rest, "--ip")
		if jail == "" || ip == "" {
			return fail(opts, cfg, &change.UsageError{Msg: "unban needs --jail NAME and --ip ADDRESS"})
		}
		report, err := deploy.UnbanFail2banIP(ctx, jail, ip)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "jail=%s ip=%s was_banned=%t unbanned=%t\n",
			report.Jail, report.IP, report.WasBanned, report.Unbanned)
		if report.AlreadyAbsent {
			fmt.Fprintln(opts.Out, "already_absent=true")
		}
		for _, remaining := range report.RemainingIPs {
			fmt.Fprintf(opts.Out, "still_banned=%s\n", remaining)
		}
		return 0
	case "trust":
		action := ""
		if len(rest) > 0 {
			action = rest[0]
		}
		if action != "add" && action != "del" {
			return usage(opts, cfg.lang, "help")
		}
		jail, ip := flagValue(rest, "--jail"), flagValue(rest, "--ip")
		if jail == "" || ip == "" {
			return fail(opts, cfg, &change.UsageError{Msg: "trust " + action + " needs --jail NAME and --ip ADDRESS|CIDR"})
		}
		report, err := deploy.Fail2banTrust(ctx, deploy.TrustSpec{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
			Jail:                 jail,
			Value:                ip,
			Remove:               action == "del",
		})
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "jail=%s value=%s applied=%t persisted=%t file=%s\n",
			report.Jail, report.Value, report.Applied, report.Persisted, report.File)
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		return 0
	case "jail":
		action := ""
		if len(rest) > 0 {
			action = rest[0]
		}
		if action != "enable" && action != "disable" {
			return usage(opts, cfg.lang, "help")
		}
		name := flagValue(rest, "--name")
		if name == "" {
			return fail(opts, cfg, &change.UsageError{Msg: "jail " + action + " needs --name NAME"})
		}
		report, err := deploy.ToggleFail2banJail(ctx, deploy.JailToggleSpec{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
			Jail:                 name,
			Enable:               action == "enable",
		})
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "jail=%s file=%s enabled=%t restarted=%t\n",
			report.Jail, report.File, report.Enabled, report.ServiceRestarted)
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}
