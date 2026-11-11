package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/app"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/i18n"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

func xrayCommand(ctx context.Context, opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "generate":
		return xrayGenerate(opts, cfg, rest)
	case "share":
		return xrayShare(opts, cfg, rest)
	case "relay":
		return xrayRelay(opts, cfg, rest)
	case "user":
		return xrayUser(ctx, opts, cfg, a, rest)
	case "install":
		return xrayInstall(ctx, opts, cfg, rest)
	case "uninstall":
		return xrayUninstall(ctx, opts, cfg, rest)
	case "recover":
		return xrayRecover(ctx, opts, cfg, rest)
	case "cert":
		return xrayCert(ctx, opts, cfg, rest)
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func xrayGenerate(opts Options, cfg config, args []string) int {
	if from := flagValue(args, "--from-config"); from != "" {
		return xrayAdopt(opts, cfg, args, from)
	}
	spec, err := specFromFlags(args)
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
	}
	g, err := xraycfg.Generate(spec)
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
	}
	out := flagValue(args, "--out")
	if out == "" {
		return usage(opts, cfg.lang, "help")
	}
	if _, statErr := os.Lstat(out); statErr == nil && !hasFlag(args, "--force") {
		return fail(opts, cfg, &change.UsageError{Msg: "refusing to overwrite existing file (use --force)"})
	}
	if err := os.WriteFile(out, g.Config, 0o600); err != nil {
		return fail(opts, cfg, err)
	}
	if err := os.Chmod(out, 0o600); err != nil {
		return fail(opts, cfg, err)
	}
	nginxOut := flagValue(args, "--nginx-out")
	if g.NginxConf != "" && nginxOut != "" {
		if err := os.WriteFile(nginxOut, []byte(g.NginxConf), 0o644); err != nil {
			return fail(opts, cfg, err)
		}
	}
	fragmentsOut := flagValue(args, "--fragments-out")
	names := make([]string, 0, len(g.NginxFragments))
	if fragmentsOut != "" && len(g.NginxFragments) > 0 {
		if err := os.MkdirAll(fragmentsOut, 0o755); err != nil {
			return fail(opts, cfg, err)
		}
		for name := range g.NginxFragments {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(fragmentsOut, name), []byte(g.NginxFragments[name]), 0o644); err != nil {
				return fail(opts, cfg, err)
			}
		}
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, g)
	}
	fmt.Fprintf(opts.Out, "mode=%s transport=%s port=%d listen=%s\n", g.Mode, g.Transport, g.Port, g.Listen)
	fmt.Fprintf(opts.Out, "uuid=%s shortId=%s\n", g.UUID, g.ShortID)
	fmt.Fprintf(opts.Out, "share: %s\n", g.ShareURI)
	if nginxOut != "" && g.NginxConf != "" {
		fmt.Fprintf(opts.Out, "nginx: %s\n", nginxOut)
	}
	for _, name := range names {
		fmt.Fprintf(opts.Out, "fragment: %s\n", filepath.Join(fragmentsOut, name))
	}
	for _, w := range g.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	fmt.Fprintf(opts.Out, "config: %s\n", out)
	return 0
}

// xrayAdopt copies an existing runtime config without changing any value. It is
// the only supported way to bring a Bash- or third-party-managed config under
// Go management; every regeneration path refuses to overwrite an existing
// config unless the operator explicitly opts in.
func xrayAdopt(opts Options, cfg config, args []string, from string) int {
	for _, flag := range []string{"--mode", "--transport", "--port", "--uuid", "--private-key", "--domain"} {
		if hasFlag(args, flag) || flagValue(args, flag) != "" {
			return fail(opts, cfg, &change.UsageError{
				Msg: "cannot combine --from-config with " + flag + "; adoption preserves the existing values",
			})
		}
	}
	out := flagValue(args, "--out")
	if out == "" {
		return usage(opts, cfg.lang, "help")
	}
	if _, statErr := os.Lstat(out); statErr == nil && !hasFlag(args, "--force") {
		return fail(opts, cfg, &change.UsageError{Msg: "refusing to overwrite existing file (use --force)"})
	}
	raw, err := os.ReadFile(from)
	if err != nil {
		return fail(opts, cfg, err)
	}
	adopted, err := xraycfg.AdoptRuntime(raw)
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
	}
	if err := os.WriteFile(out, adopted, 0o600); err != nil {
		return fail(opts, cfg, err)
	}
	if err := os.Chmod(out, 0o600); err != nil {
		return fail(opts, cfg, err)
	}
	info := map[string]any{
		"adopted":  true,
		"source":   from,
		"config":   out,
		"sha256":   store.HashBytes(adopted),
		"bytes":    len(adopted),
		"warnings": []string{"values preserved; use 'idleleo xray user add/remove' for edits"},
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, info)
	}
	fmt.Fprintf(opts.Out, "adopted: source=%s\n", from)
	fmt.Fprintf(opts.Out, "preserved sha256=%s bytes=%d\n", store.HashBytes(adopted), len(adopted))
	fmt.Fprintf(opts.Out, "config: %s\n", out)
	return 0
}

func xrayShare(opts Options, cfg config, args []string) int {
	path := flagValue(args, "--path")
	if path == "" {
		return usage(opts, cfg.lang, "help")
	}
	inbound := 0
	if raw := flagValue(args, "--inbound"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return usage(opts, cfg.lang, "help")
		}
		inbound = v
	}
	publicPort := 0
	if raw := flagValue(args, "--public-port"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return usage(opts, cfg.lang, "help")
		}
		publicPort = v
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(opts, cfg, err)
	}
	info, err := xraycfg.ShareConfig(raw, xraycfg.ShareOptions{
		InboundIndex:   inbound,
		Host:           flagValue(args, "--host"),
		PublicPort:     publicPort,
		PublicSecurity: flagValue(args, "--public-security"),
		User:           flagValue(args, "--user"),
	})
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, info)
	}
	fmt.Fprintf(opts.Out, "mode=%s transport=%s uuid=%s email=%s host=%s port=%d\n", info.Mode, info.Transport, info.UUID, info.Email, info.Host, info.Port)
	fmt.Fprintf(opts.Out, "share: %s\n", info.ShareURI)
	if info.ClashYAML != "" {
		fmt.Fprint(opts.Out, info.ClashYAML)
	}
	for _, w := range info.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}

func xrayRelay(opts Options, cfg config, args []string) int {
	target := flagValue(args, "--target")
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: "relay --target must be host:port"})
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return fail(opts, cfg, &change.UsageError{Msg: "relay --target port must be an integer"})
	}
	listenPort := 8443
	if raw := flagValue(args, "--listen-port"); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil {
			return fail(opts, cfg, &change.UsageError{Msg: "--listen-port must be an integer"})
		}
		listenPort = v
	}
	listenAddress := flagValue(args, "--listen-address")
	conf, err := xraycfg.RelayConf(xraycfg.RelaySpec{
		ListenAddress: listenAddress, ListenPort: listenPort, BackendHost: host, BackendPort: port,
	})
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
	}
	out := flagValue(args, "--out")
	if out == "" {
		return usage(opts, cfg.lang, "help")
	}
	if _, statErr := os.Lstat(out); statErr == nil && !hasFlag(args, "--force") {
		return fail(opts, cfg, &change.UsageError{Msg: "refusing to overwrite existing file (use --force)"})
	}
	if err := os.WriteFile(out, []byte(conf), 0o644); err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, map[string]any{"listenAddress": listenAddress, "listenPort": listenPort, "target": target, "conf": conf})
	}
	showAddr := listenAddress
	if showAddr == "" {
		showAddr = "0.0.0.0"
	}
	fmt.Fprintf(opts.Out, "relay: %s -> %s\n", net.JoinHostPort(showAddr, strconv.Itoa(listenPort)), target)
	fmt.Fprintf(opts.Out, "nginx: %s\n", out)
	return 0
}

func xrayUser(ctx context.Context, opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	action, rest := args[0], args[1:]
	inbound := 0
	if raw := flagValue(rest, "--inbound"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return usage(opts, cfg.lang, "help")
		}
		inbound = v
	}
	switch action {
	case "list":
		path := flagValue(rest, "--path")
		if path == "" {
			return usage(opts, cfg.lang, "help")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fail(opts, cfg, err)
		}
		users, err := xraycfg.ListUsers(raw, inbound)
		if err != nil {
			return fail(opts, cfg, err)
		}
		cfg.json = cfg.json || hasFlag(rest, "--json")
		if cfg.json {
			return writeJSON(opts, users)
		}
		for _, u := range users {
			fmt.Fprintf(opts.Out, "%d\t%s\t%s\t%s\tprimary=%t\n", u.Index, u.UUID, u.Email, u.Flow, u.Primary)
		}
		return 0
	case "add", "remove":
		sandbox := flagValue(rest, "--sandbox")
		if sandbox == "" {
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "sandbox_required"))
			return 2
		}
		if cfg.root != "/" && cfg.root != sandbox {
			return usage(opts, cfg.lang, "help")
		}
		paths, err := host.NewPaths(sandbox)
		if err != nil {
			return fail(opts, cfg, err)
		}
		a.Paths = paths
		validator := flagValue(rest, "--validator")
		if validator == "" {
			return usage(opts, cfg.lang, "help")
		}
		if paths.Root == "/" && flagValue(rest, "--service") == "" {
			return fail(opts, cfg, &change.UsageError{
				Msg: "real-root changes require --service so the service reloads the committed config",
			})
		}
		var spec xraycfg.AddUserSpec
		ident := ""
		if action == "add" {
			spec = xraycfg.AddUserSpec{
				UUID:    flagValue(rest, "--uuid"),
				Email:   flagValue(rest, "--email"),
				Flow:    flagValue(rest, "--flow"),
				ShortID: flagValue(rest, "--short-id"),
			}
			if raw := flagValue(rest, "--level"); raw != "" {
				v, convErr := strconv.Atoi(raw)
				if convErr != nil {
					return usage(opts, cfg.lang, "help")
				}
				spec.Level = v
			}
		} else {
			ident = flagValue(rest, "--email")
			if ident == "" {
				ident = flagValue(rest, "--uuid")
			}
			if ident == "" {
				return usage(opts, cfg.lang, "help")
			}
		}
		// Pre-check the business rules so obvious mistakes exit 2 without
		// touching the journal; the transaction re-checks under the lock.
		targetPath, pathErr := store.ResolveRuntimePath(paths, flagValue(rest, "--path"))
		if pathErr != nil {
			return fail(opts, cfg, pathErr)
		}
		raw, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			return fail(opts, cfg, readErr)
		}
		if action == "add" {
			if _, _, checkErr := xraycfg.AddUser(raw, inbound, spec); checkErr != nil {
				return fail(opts, cfg, &change.UsageError{Msg: checkErr.Error()})
			}
		} else {
			if _, _, checkErr := xraycfg.RemoveUser(raw, inbound, ident); checkErr != nil {
				return fail(opts, cfg, &change.UsageError{Msg: checkErr.Error()})
			}
		}
		entry, view, err := a.ChangeUser(ctx, flagValue(rest, "--path"), inbound, action == "add", ident, spec,
			validator, flagValue(rest, "--service"), flagValue(rest, "--fault"), hasFlag(rest, "--container"))
		cfg.json = cfg.json || hasFlag(rest, "--json")
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, entry)
			}
			return fail(opts, cfg, err)
		}
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, map[string]any{"entry": entry, "user": view})
			return 0
		}
		fmt.Fprintf(opts.Out, "%s: %s (%s)\n", entry.State, view.UUID, entry.ID)
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func xrayInstall(ctx context.Context, opts Options, cfg config, args []string) int {
	binary := flagValue(args, "--binary")
	if binary == "" {
		return usage(opts, cfg.lang, "help")
	}
	spec, err := specFromFlags(args)
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
	}
	if !hasFlag(args, "--keep-config") {
		if _, genErr := xraycfg.Generate(spec); genErr != nil {
			return fail(opts, cfg, &change.UsageError{Msg: genErr.Error()})
		}
	}
	report, err := deploy.Install(ctx, deploy.InstallSpec{
		Root:                 cfg.root,
		SourceBinary:         binary,
		Mode:                 spec.Mode,
		Transport:            spec.Transport,
		Port:                 spec.Port,
		Domain:               spec.Domain,
		Target:               spec.Target,
		Path:                 spec.Path,
		ServiceName:          spec.ServiceName,
		UUID:                 spec.UUID,
		Email:                spec.Email,
		Flow:                 spec.Flow,
		PrivateKey:           spec.PrivateKey,
		ShortID:              spec.ShortID,
		CertFile:             spec.CertFile,
		KeyFile:              spec.KeyFile,
		Listen:               spec.Listen,
		PublicPort:           spec.PublicPort,
		ServerNames:          spec.ServerNames,
		BalanceRole:          spec.BalanceRole,
		Backends:             spec.Backends,
		UnknownSNIPolicy:     spec.UnknownSNIPolicy,
		AllowNonLoopback:     spec.AllowNonLoopback,
		KeepConfig:           hasFlag(args, "--keep-config"),
		RewriteConfig:        hasFlag(args, "--rewrite-config"),
		ExternalNginxManaged: hasFlag(args, "--external-nginx-managed"),
		NginxBin:             flagValue(args, "--nginx-bin"),
		NoService:            hasFlag(args, "--no-service"),
		AllowContainerWrites: hasFlag(args, "--container"),
	})
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprintf(opts.Out, "installed: mode=%s transport=%s tls=%s\n", report.Mode, report.Transport, report.TLS)
	fmt.Fprintf(opts.Out, "config=%s sha256=%s\n", report.ConfigPath, report.ConfigSHA256)
	fmt.Fprintf(opts.Out, "service active=%s enabled=%s\n", report.ServiceActive, report.ServiceEnabled)
	if report.NginxManaged {
		fmt.Fprintf(opts.Out, "nginx managed=%t verified=%t dir=%s\n", report.NginxManaged, report.NginxVerified, report.NginxDir)
	}
	for _, w := range report.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}

func xrayUninstall(ctx context.Context, opts Options, cfg config, args []string) int {
	report, err := deploy.Uninstall(ctx, deploy.UninstallSpec{
		Root:                 cfg.root,
		Purge:                hasFlag(args, "--purge"),
		AllowContainerWrites: hasFlag(args, "--container"),
	})
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprintf(opts.Out, "removed: %s\n", strings.Join(report.Removed, ","))
	fmt.Fprintf(opts.Out, "configPreserved=%t\n", report.ConfigPreserved)
	return 0
}

func xrayRecover(ctx context.Context, opts Options, cfg config, args []string) int {
	report, err := deploy.Recover(ctx, deploy.RecoverSpec{
		Root:                 cfg.root,
		AllowContainerWrites: hasFlag(args, "--container"),
	})
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprintf(opts.Out, "recovery journal=%s action=%s converged=%t restored=%d\n",
		report.JournalState, report.Action, report.Converged, report.Restored)
	for _, w := range report.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}

func specFromFlags(args []string) (xraycfg.Spec, error) {
	spec := xraycfg.Spec{
		Mode:             flagValue(args, "--mode"),
		Transport:        flagValue(args, "--transport"),
		Domain:           flagValue(args, "--domain"),
		Target:           flagValue(args, "--target"),
		Path:             flagValue(args, "--path"),
		ServiceName:      flagValue(args, "--service-name"),
		UUID:             flagValue(args, "--uuid"),
		Email:            flagValue(args, "--email"),
		Flow:             flagValue(args, "--flow"),
		PrivateKey:       flagValue(args, "--private-key"),
		ShortID:          flagValue(args, "--short-id"),
		AllowNonLoopback: hasFlag(args, "--allow-non-loopback"),
		BalanceRole:      flagValue(args, "--role"),
		UnknownSNIPolicy: flagValue(args, "--unknown-sni-policy"),
	}
	for i, a := range args {
		if a == "--backend" && i+1 < len(args) {
			spec.Backends = append(spec.Backends, args[i+1])
		}
	}
	if raw := flagValue(args, "--listen"); raw != "" {
		spec.Listen = raw
	}
	if raw := flagValue(args, "--port"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return xraycfg.Spec{}, fmt.Errorf("--port must be an integer")
		}
		spec.Port = v
	}
	if raw := flagValue(args, "--public-port"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return xraycfg.Spec{}, fmt.Errorf("--public-port must be an integer")
		}
		spec.PublicPort = v
	}
	if raw := flagValue(args, "--server-names"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				spec.ServerNames = append(spec.ServerNames, s)
			}
		}
	}
	if raw := flagValue(args, "--cert"); raw != "" {
		spec.CertFile = raw
	}
	if raw := flagValue(args, "--cert-key"); raw != "" {
		spec.KeyFile = raw
	}
	return spec, nil
}
