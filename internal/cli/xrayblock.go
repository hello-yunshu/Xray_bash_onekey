package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
)

// xrayBlock owns `xray block ...`: traffic blocking at the Xray routing layer.
// Switch and list edits only touch traffic_blocker.json; apply/off are the only
// commands that rewrite the config and restart the service.
func xrayBlock(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	switch args[0] {
	case "status":
		rep, err := deploy.BlockStatus(cfg.root)
		if err != nil {
			return fail(opts, cfg, err)
		}
		cfg.json = cfg.json || hasFlag(args, "--json")
		if cfg.json {
			return writeJSON(opts, rep)
		}
		printBlockReport(opts, rep)
		return 0
	case "apply":
		return blockApply(ctx, opts, cfg, args[1:])
	case "off":
		return blockOff(ctx, opts, cfg, args[1:])
	case "ads":
		return blockToggle(opts, cfg, args[1:], "ads")
	case "private-ip":
		return blockToggle(opts, cfg, args[1:], "private-ip")
	case "bittorrent":
		return blockToggle(opts, cfg, args[1:], "bittorrent")
	case "country":
		return blockCountry(opts, cfg, args[1:])
	case "custom":
		return blockCustom(opts, cfg, args[1:])
	}
	return usage(opts, cfg.lang, "help")
}

func blockToggle(opts Options, cfg config, args []string, name string) int {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "disable") {
		return fail(opts, cfg, &change.UsageError{Msg: "usage: idleleo xray block " + name + " enable|disable"})
	}
	on := args[0] == "enable"
	var ads, privateIP, bittorrent *bool
	switch name {
	case "ads":
		ads = &on
	case "private-ip":
		privateIP = &on
	case "bittorrent":
		bittorrent = &on
	}
	rep, err := deploy.UpdateBlockSwitches(cfg.root, ads, privateIP, bittorrent, hasFlag(args, "--container"))
	if err != nil {
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, rep)
	}
	fmt.Fprintf(opts.Out, "%s=%t (run 'idleleo xray block apply' to take effect)\n", name, on)
	return 0
}

func blockCountry(opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return fail(opts, cfg, &change.UsageError{Msg: "usage: idleleo xray block country add|remove|list [cc ...]"})
	}
	switch args[0] {
	case "list":
		rep, err := deploy.BlockStatus(cfg.root)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, rep.Countries)
		}
		fmt.Fprintln(opts.Out, strings.Join(rep.Countries, ","))
		return 0
	case "add", "remove":
		values := blockValues(args[1:])
		if len(values) == 0 {
			return fail(opts, cfg, &change.UsageError{Msg: "country " + args[0] + " needs at least one two-letter code"})
		}
		var rep deploy.BlockReport
		var err error
		if args[0] == "add" {
			rep, err = deploy.UpdateBlockCountries(cfg.root, values, nil, hasFlag(args, "--container"))
		} else {
			rep, err = deploy.UpdateBlockCountries(cfg.root, nil, values, hasFlag(args, "--container"))
		}
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "countries=%s (run 'idleleo xray block apply' to take effect)\n", strings.Join(rep.Countries, ","))
		return 0
	}
	return fail(opts, cfg, &change.UsageError{Msg: "unknown country action " + args[0]})
}

func blockCustom(opts Options, cfg config, args []string) int {
	if len(args) < 2 {
		return fail(opts, cfg, &change.UsageError{
			Msg: "usage: idleleo xray block custom add|remove|enable|disable|list --kind domain|ip [--value v]",
		})
	}
	kind := flagValue(args, "--kind")
	if kind == "" {
		return fail(opts, cfg, &change.UsageError{Msg: "--kind domain|ip is required"})
	}
	switch args[0] {
	case "list":
		rep, err := deploy.BlockStatus(cfg.root)
		if err != nil {
			return fail(opts, cfg, err)
		}
		list := rep.CustomDomains
		if strings.HasPrefix(kind, "ip") {
			list = rep.CustomIPs
		}
		if cfg.json {
			return writeJSON(opts, list)
		}
		fmt.Fprintf(opts.Out, "enabled=%t\n", list.Enabled)
		for _, item := range list.Items {
			fmt.Fprintln(opts.Out, item)
		}
		return 0
	case "enable", "disable":
		on := args[0] == "enable"
		rep, err := deploy.UpdateBlockCustom(cfg.root, kind, nil, nil, &on, hasFlag(args, "--container"))
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "custom %s enabled=%t (run 'idleleo xray block apply' to take effect)\n", kind, on)
		return 0
	case "add", "remove":
		values := blockValues(args[1:])
		if len(values) == 0 {
			return fail(opts, cfg, &change.UsageError{Msg: "custom " + args[0] + " needs at least one --value"})
		}
		var rep deploy.BlockReport
		var err error
		if args[0] == "add" {
			rep, err = deploy.UpdateBlockCustom(cfg.root, kind, values, nil, nil, hasFlag(args, "--container"))
		} else {
			rep, err = deploy.UpdateBlockCustom(cfg.root, kind, nil, values, nil, hasFlag(args, "--container"))
		}
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		list := rep.CustomDomains
		if strings.HasPrefix(kind, "ip") {
			list = rep.CustomIPs
		}
		fmt.Fprintf(opts.Out, "custom %s items=%d (run 'idleleo xray block apply' to take effect)\n", kind, len(list.Items))
		return 0
	}
	return fail(opts, cfg, &change.UsageError{Msg: "unknown custom action " + args[0]})
}

// blockValues collects repeated --value flags and positional values, splitting
// comma-separated lists. Duplicates are left to the state layer (idempotent).
func blockValues(args []string) []string {
	out := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if v, ok := strings.CutPrefix(arg, "--value="); ok {
			out = append(out, strings.Split(v, ",")...)
			continue
		}
		if arg == "--value" && i+1 < len(args) {
			i++
			out = append(out, strings.Split(args[i], ",")...)
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Skip the flag values that belong to --kind etc.
		if i > 0 && (args[i-1] == "--kind" || args[i-1] == "--path" || args[i-1] == "--geodata-url") {
			continue
		}
		out = append(out, strings.Split(arg, ",")...)
	}
	values := make([]string, 0, len(out))
	for _, v := range out {
		if v = strings.TrimSpace(v); v != "" {
			values = append(values, v)
		}
	}
	return values
}

func blockApply(ctx context.Context, opts Options, cfg config, args []string) int {
	spec, rc, ok := blockSpecFromFlags(opts, cfg, args)
	if !ok {
		return rc
	}
	if !spec.DryRun {
		if rc, ok := confirmBlock(opts, cfg, args, "applying traffic blocking rewrites routing rules and restarts xray"); !ok {
			return rc
		}
	}
	rep, err := deploy.ApplyBlock(ctx, spec)
	if cfg.json {
		_ = writeJSON(opts, rep)
	}
	if err != nil {
		return fail(opts, cfg, err)
	}
	if !cfg.json {
		printBlockApplyReport(opts, rep)
	}
	return 0
}

func blockOff(ctx context.Context, opts Options, cfg config, args []string) int {
	spec, rc, ok := blockSpecFromFlags(opts, cfg, args)
	if !ok {
		return rc
	}
	if !spec.DryRun {
		if rc, ok := confirmBlock(opts, cfg, args, "removing traffic blocking rewrites routing rules and restarts xray"); !ok {
			return rc
		}
	}
	rep, err := deploy.OffBlock(ctx, spec)
	if cfg.json {
		_ = writeJSON(opts, rep)
	}
	if err != nil {
		return fail(opts, cfg, err)
	}
	if !cfg.json {
		printBlockApplyReport(opts, rep)
	}
	return 0
}

func blockSpecFromFlags(opts Options, cfg config, args []string) (deploy.BlockApplySpec, int, bool) {
	spec := deploy.BlockApplySpec{
		Root:                 cfg.root,
		ConfigPath:           flagValue(args, "--path"),
		DryRun:               hasFlag(args, "--dry-run"),
		NoRestart:            hasFlag(args, "--no-restart"),
		NoProbe:              hasFlag(args, "--no-probe"),
		AllowContainerWrites: hasFlag(args, "--container"),
		GeodataURL:           flagValue(args, "--geodata-url"),
	}
	if spec.NoRestart && !spec.DryRun {
		// Without a restart the live service keeps the old rules; allowing that
		// would report success for a change that never took effect.
		return spec, fail(opts, cfg, &change.UsageError{Msg: "--no-restart cannot be combined with a real block apply/off; use --dry-run to inspect"}), false
	}
	return spec, 0, true
}

// confirmBlock enforces the explicit gate: --yes, or an interactive y/N.
func confirmBlock(opts Options, cfg config, args []string, prompt string) (int, bool) {
	if hasFlag(args, "--yes") {
		return 0, true
	}
	if !opts.TTY {
		return fail(opts, cfg, &change.UsageError{Msg: prompt + "; re-run with --yes to confirm"}), false
	}
	fmt.Fprintln(opts.Out, prompt)
	if !confirmEdit(opts) {
		fmt.Fprintln(opts.Out, "aborted; nothing was changed")
		return 1, false
	}
	return 0, true
}

func printBlockApplyReport(opts Options, rep deploy.BlockReport) {
	fmt.Fprintf(opts.Out, "applied=%t ownedRules=%d\n", rep.Applied, rep.OwnedRuleCount)
	fmt.Fprintf(opts.Out, "countries=%s ads=%t privateIp=%t bittorrent=%t\n",
		strings.Join(rep.Countries, ","), rep.Ads, rep.PrivateIP, rep.BitTorrent)
	if rep.ConfigPath != "" {
		fmt.Fprintf(opts.Out, "config=%s\n", rep.ConfigPath)
	}
	if rep.BackupDir != "" {
		fmt.Fprintf(opts.Out, "backup=%s\n", rep.BackupDir)
	}
	if rep.AssetEnv != "" {
		fmt.Fprintf(opts.Out, "assetEnv=%s\n", rep.AssetEnv)
	}
	if rep.ControlProbe != "" {
		fmt.Fprintf(opts.Out, "controlProbe=%s\n", rep.ControlProbe)
	}
	if rep.FailurePoint != "" {
		fmt.Fprintf(opts.Out, "failurePoint=%s\n", rep.FailurePoint)
	}
	for _, warning := range rep.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", warning)
	}
}

func printBlockReport(opts Options, rep deploy.BlockReport) {
	fmt.Fprintf(opts.Out, "configured=%t applied=%t drift=%t\n", rep.Configured, rep.Applied, rep.Drift)
	fmt.Fprintf(opts.Out, "ads=%t privateIp=%t bittorrent=%t countries=%s\n",
		rep.Ads, rep.PrivateIP, rep.BitTorrent, strings.Join(rep.Countries, ","))
	fmt.Fprintf(opts.Out, "customDomains enabled=%t items=%d\n", rep.CustomDomains.Enabled, len(rep.CustomDomains.Items))
	fmt.Fprintf(opts.Out, "customIps enabled=%t items=%d\n", rep.CustomIPs.Enabled, len(rep.CustomIPs.Items))
	fmt.Fprintf(opts.Out, "ownedRules=%d domainStrategy=%s sniffing=%t\n",
		rep.OwnedRuleCount, rep.DomainStrategy, rep.SniffingEnabled)
	fmt.Fprintf(opts.Out, "geosite=%s mtime=%s\n", blockGeoLine(rep.Geosite), rep.Geosite.ModTime)
	fmt.Fprintf(opts.Out, "geoip=%s mtime=%s\n", blockGeoLine(rep.Geoip), rep.Geoip.ModTime)
	for _, warning := range rep.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", warning)
	}
}

func blockGeoLine(geo deploy.BlockGeoReport) string {
	switch {
	case geo.Missing:
		return "missing"
	case geo.Stale:
		return "stale"
	}
	return "ok"
}
