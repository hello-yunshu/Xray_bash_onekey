package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/netcfg"
)

// netCommand owns the read-only dual-stack qualification and the transactional
// managed-firewall reconciliation.
func netCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	switch args[0] {
	case "dns":
		if rc, ok := checkFlags(opts, cfg, args[1:], "net dns"); ok && rc != 0 {
			return rc
		}
		return netDNS(ctx, opts, cfg, args[1:])
	case "firewall":
		if len(args) < 2 {
			return usage(opts, cfg.lang, "help")
		}
		action := args[1]
		if rc, ok := checkFlags(opts, cfg, args[2:], "net firewall "+action); ok && rc != 0 {
			return rc
		}
		return netFirewall(ctx, opts, cfg, action, args[2:])
	default:
		return usage(opts, cfg.lang, "help")
	}
}

type dnsReport struct {
	Domain     string   `json:"domain"`
	Policy     string   `json:"policy"`
	ServerIPv4 string   `json:"serverIPv4"`
	ServerIPv6 string   `json:"serverIPv6"`
	Resolved4  []string `json:"resolved4"`
	Resolved6  []string `json:"resolved6"`
	Warnings   []string `json:"warnings,omitempty"`
	netcfg.DNSReport
}

func netDNS(ctx context.Context, opts Options, cfg config, args []string) int {
	cfg.json = cfg.json || hasFlag(args, "--json")
	domain := flagValue(args, "--domain")
	if strings.TrimSpace(domain) == "" {
		return fail(opts, cfg, &change.UsageError{Msg: "--domain is required"})
	}
	policy := flagValue(args, "--policy")
	if policy == "" {
		policy = "auto"
	}
	switch policy {
	case "auto", "ipv4", "ipv6":
	default:
		return fail(opts, cfg, &change.UsageError{Msg: "unknown --policy: " + policy})
	}
	server4 := flagValue(args, "--server-ipv4")
	server6 := flagValue(args, "--server-ipv6")
	if server4 == "" || server6 == "" {
		local4, local6 := netcfg.LocalPublicIPs()
		if server4 == "" {
			server4 = local4
		}
		if server6 == "" {
			server6 = local6
		}
	}

	report := dnsReport{
		Domain: domain, Policy: policy, ServerIPv4: server4, ServerIPv6: server6,
		Resolved4: []string{}, Resolved6: []string{},
	}
	records, lookupErr := netcfg.Lookup(ctx, domain, flagValue(args, "--resolver"))
	if lookupErr != nil {
		report.Mode = "none"
		report.Warnings = append(report.Warnings, lookupErr.Error())
	} else {
		v4, v6 := netcfg.Classify(records)
		if v4 == nil {
			v4 = []string{}
		}
		if v6 == nil {
			v6 = []string{}
		}
		report.Resolved4, report.Resolved6 = v4, v6
		var err error
		report.DNSReport, err = netcfg.Validate(server4, server6, records, policy)
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, report)
			}
			fmt.Fprint(opts.Err, err.Error()+"\n")
			if errors.Is(err, netcfg.ErrBadRecords) {
				return 2
			}
			return 1
		}
	}
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprintf(opts.Out, "domain=%s policy=%s server4=%s server6=%s\n",
		report.Domain, report.Policy, report.ServerIPv4, report.ServerIPv6)
	fmt.Fprintf(opts.Out, "mode=%s hasA=%t hasAAAA=%t aOK=%t aaaaOK=%t badA=%t badAAAA=%t\n",
		report.Mode, report.HasA, report.HasAAAA, report.AOK, report.AAAAOK, report.BadA, report.BadAAAA)
	for _, ip := range report.Resolved4 {
		fmt.Fprintf(opts.Out, "resolved4=%s\n", ip)
	}
	for _, ip := range report.Resolved6 {
		fmt.Fprintf(opts.Out, "resolved6=%s\n", ip)
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", warning)
	}
	if lookupErr != nil {
		return 1
	}
	return 0
}

func netFirewall(ctx context.Context, opts Options, cfg config, action string, args []string) int {
	cfg.json = cfg.json || hasFlag(args, "--json")
	switch action {
	case "status":
		report, err := netcfg.Status(ctx, cfg.root)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "state=%s installed=%t\n", report.StateFile, report.Installed)
		fmt.Fprintf(opts.Out, "ports: tcp=%s udp=%s\n",
			joinPorts(report.Ports.TCP), joinPorts(report.Ports.UDP))
		if len(report.Families) > 0 {
			fmt.Fprintf(opts.Out, "families=%s\n", strings.Join(report.Families, " "))
		}
		for _, check := range report.Checks {
			fmt.Fprintf(opts.Out, "check: %s %s %d input=%s output=%s\n",
				check.Family, check.Proto, check.Port, check.Input, check.Output)
		}
		for _, warning := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", warning)
		}
		return 0
	case "apply", "revert":
		dryRun := hasFlag(args, "--dry-run")
		mode := flagValue(args, "--family")
		if mode == "" {
			mode = "auto"
		}
		switch mode {
		case "auto", "ipv4", "ipv6", "dual", "manual":
		default:
			return fail(opts, cfg, &change.UsageError{Msg: "unknown --family: " + mode})
		}
		spec := netcfg.Spec{
			Root:                 cfg.root,
			Mode:                 mode,
			DryRun:               dryRun,
			AllowContainerWrites: hasFlag(args, "--container"),
		}
		var report netcfg.Report
		var err error
		if action == "revert" {
			report, err = netcfg.Revert(ctx, spec)
		} else {
			tcp, perr := netcfg.ParsePortList(flagValue(args, "--tcp"))
			if perr != nil {
				return fail(opts, cfg, &change.UsageError{Msg: perr.Error()})
			}
			udp, perr := netcfg.ParsePortList(flagValue(args, "--udp"))
			if perr != nil {
				return fail(opts, cfg, &change.UsageError{Msg: perr.Error()})
			}
			spec.New = netcfg.NewPorts(tcp, udp)
			report, err = netcfg.Apply(ctx, spec)
		}
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, report)
			}
			return netFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "old: tcp=%s udp=%s\n", joinPorts(report.Old.TCP), joinPorts(report.Old.UDP))
		fmt.Fprintf(opts.Out, "new: tcp=%s udp=%s\n", joinPorts(report.New.TCP), joinPorts(report.New.UDP))
		fmt.Fprintf(opts.Out, "families: %s -> %s\n",
			strings.Join(report.OldFamilies, " "), strings.Join(report.NewFamilies, " "))
		if report.DryRun {
			for _, c := range report.Commands {
				fmt.Fprintf(opts.Out, "command=%s\n", c.String())
			}
		}
		fmt.Fprintf(opts.Out, "persisted=%t rolledBack=%t dryRun=%t\n",
			report.Persisted, report.RolledBack, report.DryRun)
		for _, warning := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", warning)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func netFail(opts Options, cfg config, err error) int {
	switch {
	case errors.Is(err, netcfg.ErrBadRecords):
		return 2
	case errors.Is(err, netcfg.ErrNoMatch):
		return 1
	case errors.Is(err, netcfg.ErrRollback):
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 10
	default:
		return fail(opts, cfg, err)
	}
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, ",")
}
