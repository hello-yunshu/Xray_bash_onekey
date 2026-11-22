package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/app"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/deploy"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/hotuser"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/i18n"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

func xrayCommand(ctx context.Context, opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	// Nested commands (user/cert) own their own flag vocabulary; everything
	// else is validated against the two-word path.
	flagArgs, flagKey := rest, "xray "+sub
	if (sub == "user" || sub == "cert" || sub == "config" || sub == "logs" || sub == "balance" || sub == "guard" || sub == "api") && len(rest) > 0 {
		flagArgs, flagKey = rest[1:], flagKey+" "+rest[0]
	}
	if rc, ok := checkFlags(opts, cfg, flagArgs, flagKey); ok && rc != 0 {
		return rc
	}
	switch sub {
	case "generate":
		return xrayGenerate(opts, cfg, rest)
	case "share":
		return xrayShare(opts, cfg, rest)
	case "relay":
		return xrayRelay(opts, cfg, rest)
	case "user":
		return xrayUser(ctx, opts, cfg, a, rest)
	case "api":
		return xrayAPICommand(ctx, opts, cfg, a, rest)
	case "install":
		return xrayInstall(ctx, opts, cfg, rest)
	case "uninstall":
		return xrayUninstall(ctx, opts, cfg, rest)
	case "recover":
		return xrayRecover(ctx, opts, cfg, rest)
	case "cert":
		return xrayCert(ctx, opts, cfg, rest)
	case "config":
		return xrayConfig(ctx, opts, cfg, rest)
	case "logs":
		return xrayLogs(ctx, opts, cfg, rest)
	case "balance":
		return xrayBalance(ctx, opts, cfg, rest)
	case "guard":
		return xrayGuard(ctx, opts, cfg, rest)
	case "tls":
		return xrayTLS(ctx, opts, cfg, rest)
	case "block":
		return xrayBlock(ctx, opts, cfg, rest)
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
	shareOpts := xraycfg.ShareOptions{
		InboundIndex:   inbound,
		Host:           flagValue(args, "--host"),
		PublicPort:     publicPort,
		PublicSecurity: flagValue(args, "--public-security"),
		User:           flagValue(args, "--user"),
	}
	// Metadata carries the trusted public topology: Bash TLS nodes keep Xray on
	// loopback with stream security=none, so the runtime config alone cannot
	// tell an Nginx TLS front from a plain public port. It may only describe the
	// config it owns; metadata from another root or for different bytes is never
	// applied, because a stale public port/security would render a wrong link.
	meta, managed, stale := managedShareMetadata(cfg.root, path, raw)
	if managed {
		applyShareMetadataDefaults(&shareOpts, meta)
		// Link-only preferences persisted by `xray config edit --fp/--spx`.
		if meta.ShareLinkOnly != nil {
			shareOpts.Fingerprint = meta.ShareLinkOnly.Fingerprint
			shareOpts.SpiderX = meta.ShareLinkOnly.SpiderX
		}
	}
	info, err := xraycfg.ShareConfig(raw, shareOpts)
	if err != nil {
		return fail(opts, cfg, err)
	}
	// A direct edit of config.json leaves the metadata hash behind. The runtime
	// config is still authoritative for everything that can be derived from it,
	// so share keeps working; the caller is told the public-side defaults were
	// skipped instead of silently rendering a link from stale facts.
	if stale != "" {
		info.Warnings = append(info.Warnings, stale)
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	if cfg.json {
		if hasFlag(args, "--qr") {
			return fail(opts, cfg, &change.UsageError{Msg: "--qr prints a terminal QR code and cannot be combined with --json"})
		}
		return writeJSON(opts, info)
	}
	// Render before the first byte of output so a missing or failing
	// qrencode cannot leave a half-printed report behind.
	var qr string
	if hasFlag(args, "--qr") {
		qr, err = terminalQR(info.ShareURI)
		if err != nil {
			return fail(opts, cfg, err)
		}
	}
	fmt.Fprintf(opts.Out, "mode=%s transport=%s uuid=%s email=%s host=%s port=%d\n", info.Mode, info.Transport, info.UUID, info.Email, info.Host, info.Port)
	fmt.Fprintf(opts.Out, "share: %s\n", info.ShareURI)
	if qr != "" {
		fmt.Fprintln(opts.Out, "qr:")
		fmt.Fprint(opts.Out, qr)
	}
	if info.ClashYAML != "" {
		fmt.Fprint(opts.Out, info.ClashYAML)
	}
	for _, w := range info.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}

// managedShareMetadata returns the manager metadata under root only when the
// selected config is provably the one it describes: the canonical selected path
// must equal root + runtimeConfigPath, and a recorded runtimeSha256 must match
// the bytes about to be shared. Metadata from another root or another config is
// never applied. A matching path with a different hash means the file was edited
// outside the manager: the runtime config still wins, the defaults are skipped,
// and the returned warning explains why the link may lack persisted preferences.
func managedShareMetadata(root, selected string, raw []byte) (store.Metadata, bool, string) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return store.Metadata{}, false, ""
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return store.Metadata{}, false, ""
	}
	if err := store.ValidateManagerPath(meta.RuntimeConfigPath); err != nil {
		return store.Metadata{}, false, ""
	}
	managed, err := paths.Join(meta.RuntimeConfigPath, false)
	if err != nil {
		return store.Metadata{}, false, ""
	}
	if canonicalPath(managed) != canonicalPath(selected) {
		return store.Metadata{}, false, ""
	}
	if meta.RuntimeSHA256 != "" && meta.RuntimeSHA256 != store.HashBytes(raw) {
		return store.Metadata{}, false, "runtime metadata is stale (runtimeSha256 does not match the shared config, usually a direct edit): public-side defaults were not applied; re-run a managed change or pass --host/--public-port/--public-security explicitly"
	}
	return meta, true, ""
}

// canonicalPath resolves a path for ownership comparison. Missing files still
// get an absolute, cleaned form so a path that does not exist cannot compare
// equal by accident.
func canonicalPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return filepath.Clean(abs)
}

// applyShareMetadataDefaults fills the public-side fields that the runtime
// config cannot prove when Nginx terminates TLS in front of a loopback Xray
// backend. Explicit flags always win. Install.ServerNames is deliberately not
// used: for Reality it is the SNI/camouflage identity, not the address clients
// dial, so a connection host must be supplied explicitly.
func applyShareMetadataDefaults(opts *xraycfg.ShareOptions, meta store.Metadata) {
	if strings.TrimSpace(opts.PublicSecurity) == "" {
		switch meta.TLS {
		case "TLS":
			opts.PublicSecurity = xraycfg.ModeTLS
		case "Reality":
			opts.PublicSecurity = xraycfg.ModeReality
		case "None":
			opts.PublicSecurity = xraycfg.ModeNone
		}
	}
	if meta.Install == nil {
		return
	}
	if opts.PublicPort == 0 && meta.Install.Port > 0 {
		opts.PublicPort = meta.Install.Port
	}
}

// terminalQR renders link as the same UTF-8 matrix Bash prints with
// `echo -n "$link" | qrencode -o - -t utf8`. Shelling out to qrencode keeps
// the two managers byte-identical and avoids a new Go dependency; the flag is
// opt-in so the text and JSON contracts stay unchanged.
func terminalQR(link string) (string, error) {
	if _, err := exec.LookPath("qrencode"); err != nil {
		return "", fmt.Errorf("qrencode is not installed; --qr needs it (Debian/Ubuntu: apt-get install qrencode, RHEL: dnf install qrencode, Alpine: apk add libqrencode-tools)")
	}
	cmd := exec.Command("qrencode", "-o", "-", "-t", "utf8")
	cmd.Stdin = strings.NewReader(link)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("qrencode failed: %v: %s", err, msg)
		}
		return "", fmt.Errorf("qrencode failed: %w", err)
	}
	return out.String(), nil
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
	case "uuid":
		if sandbox := flagValue(rest, "--sandbox"); sandbox != "" {
			if cfg.root != "/" && cfg.root != sandbox {
				return usage(opts, cfg.lang, "help")
			}
			paths, err := host.NewPaths(sandbox)
			if err != nil {
				return fail(opts, cfg, err)
			}
			a.Paths = paths
		}
		validator := flagValue(rest, "--validator")
		if validator == "" {
			return usage(opts, cfg.lang, "help")
		}
		service := flagValue(rest, "--service")
		if a.Paths.Root == "/" && service == "" {
			return fail(opts, cfg, &change.UsageError{
				Msg: "real-root changes require --service so the service reloads the committed config",
			})
		}
		ident := flagValue(rest, "--email")
		if ident == "" {
			ident = flagValue(rest, "--uuid")
		}
		newUUID := flagValue(rest, "--new-uuid")
		if ident == "" || newUUID == "" {
			return usage(opts, cfg.lang, "help")
		}
		restrict := hasFlag(rest, "--inbound")
		targetPath, pathErr := store.ResolveRuntimePath(a.Paths, flagValue(rest, "--path"))
		if pathErr != nil {
			return fail(opts, cfg, pathErr)
		}
		raw, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			return fail(opts, cfg, readErr)
		}
		// Dry-run and the real run share one preview so the operator sees the
		// exact inbound list - and the restart warning - before anything moves.
		_, preview, err := xraycfg.SetUserUUID(raw, ident, newUUID, inbound, restrict)
		if err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
		}
		skipped := []xraycfg.UserRef{}
		if restrict {
			// The operator narrowed the blast radius; list what keeps the old
			// credential so a half-rotated user is visible before the write.
			if _, all, allErr := xraycfg.SetUserUUID(raw, ident, newUUID, 0, false); allErr == nil {
				for _, ref := range all.Previous {
					if ref.Inbound != inbound {
						skipped = append(skipped, ref)
					}
				}
			}
		}
		cfg.json = cfg.json || hasFlag(rest, "--json")
		renderPreview := func() {
			if cfg.json {
				return
			}
			fmt.Fprintf(opts.Out, "target: %s\n", preview.Ident)
			for _, ref := range preview.Previous {
				fmt.Fprintf(opts.Out, "inbound %d client %d: %s  %s -> %s\n",
					ref.Inbound, ref.User.Index, ref.User.Email, ref.User.UUID, preview.NewUUID)
			}
			for _, ref := range skipped {
				fmt.Fprintf(opts.Out, "unchanged: inbound %d client %d (%s) keeps the old uuid %s\n",
					ref.Inbound, ref.User.Index, ref.User.Email, ref.User.UUID)
			}
			fmt.Fprintf(opts.Out, "warning: this restarts the Xray service; every live connection drops for a few seconds (all users, not only %s)\n", preview.Ident)
		}
		if preview.NoChanges {
			if cfg.json {
				return writeJSON(opts, map[string]any{"change": preview, "noChanges": true})
			}
			fmt.Fprintf(opts.Out, "no changes: %s already uses %s\n", preview.Ident, newUUID)
			return 0
		}
		if hasFlag(rest, "--dry-run") {
			if cfg.json {
				return writeJSON(opts, map[string]any{"dryRun": true, "change": preview})
			}
			renderPreview()
			return 0
		}
		renderPreview()
		entry, result, err := a.ChangeUserUUID(ctx, flagValue(rest, "--path"), ident, newUUID, inbound, restrict,
			validator, service, flagValue(rest, "--fault"), hasFlag(rest, "--container"))
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, entry)
			}
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, map[string]any{"entry": entry, "change": result})
		}
		fmt.Fprintf(opts.Out, "state: %s (%s)\n", entry.State, entry.ID)
		for _, ref := range result.Previous {
			fmt.Fprintf(opts.Out, "rollback: idleleo xray user uuid --email %s --new-uuid %s --validator %s",
				ref.User.Email, ref.User.UUID, validator)
			if service != "" {
				fmt.Fprintf(opts.Out, " --service %s", service)
			}
			fmt.Fprintln(opts.Out)
			break
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
		hot := hasFlag(rest, "--experimental-hot")
		service := flagValue(rest, "--service")
		if paths.Root == "/" && service == "" && !hot {
			return fail(opts, cfg, &change.UsageError{
				Msg: "real-root changes require --service, or --experimental-hot for a running API",
			})
		}
		if hot {
			// Serialize hot operations so config order and runtime order cannot
			// invert, and so an enable/apply pair is never interleaved.
			lock, lockErr := host.AcquireUpdateWait(filepath.Join(paths.Root, "run/lock/idleleo-hot.lock"), 15*time.Second)
			if lockErr != nil {
				return fail(opts, cfg, lockErr)
			}
			defer lock.Release()
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
		skipPersist := false
		var existing xraycfg.UserView
		if action == "add" {
			if _, _, checkErr := xraycfg.AddUser(raw, inbound, spec); checkErr != nil {
				if !hot {
					return fail(opts, cfg, &change.UsageError{Msg: checkErr.Error()})
				}
				views, listErr := xraycfg.ListUsers(raw, inbound)
				if listErr != nil {
					return fail(opts, cfg, listErr)
				}
				found := false
				for _, v := range views {
					if v.Email == spec.Email && (spec.UUID == "" || v.UUID == spec.UUID) {
						existing, found = v, true
					}
				}
				if !found {
					return fail(opts, cfg, &change.UsageError{Msg: checkErr.Error()})
				}
				// Retry after a half-failed hot apply: the commit already happened.
				skipPersist = true
			}
		} else {
			if _, _, checkErr := xraycfg.RemoveUser(raw, inbound, ident); checkErr != nil {
				if !hot {
					return fail(opts, cfg, &change.UsageError{Msg: checkErr.Error()})
				}
				skipPersist = true
			}
		}
		cfg.json = cfg.json || hasFlag(rest, "--json")
		changeService := service
		if hot {
			changeService = ""
		}
		var entry change.Entry
		var view xraycfg.UserView
		if skipPersist {
			view = existing
			if action == "remove" {
				view = xraycfg.UserView{UUID: ident, Email: ident}
			}
		} else {
			entry, view, err = a.ChangeUser(ctx, flagValue(rest, "--path"), inbound, action == "add", ident, spec,
				validator, changeService, flagValue(rest, "--fault"), hasFlag(rest, "--container"))
			if err != nil {
				if cfg.json {
					_ = writeJSONNoExit(opts.Out, entry)
				}
				return fail(opts, cfg, err)
			}
		}
		var hotReport map[string]any
		var endpoint hotuser.Endpoint
		if hot {
			fresh, readErr := os.ReadFile(targetPath)
			if readErr != nil {
				return hotApplyFailure(opts, cfg, entry, view, !skipPersist, readErr)
			}
			xrayBin := flagValue(rest, "--xray")
			if xrayBin == "" {
				xrayBin = filepath.Join(paths.Root, "usr/local/bin/xray")
			}
			endpoint, err = hotuser.Locate(fresh, flagValue(rest, "--api-server"))
			if err == nil {
				if action == "add" {
					err = hotuser.Add(ctx, xrayBin, endpoint, spec.Email, view.UUID, view.Flow, view.Level)
				} else {
					err = hotuser.Remove(ctx, xrayBin, endpoint, ident)
				}
			}
			if err != nil {
				return hotApplyFailure(opts, cfg, entry, view, !skipPersist, err)
			}
			hotReport = map[string]any{
				"persisted": !skipPersist, "applied": true,
				"server": endpoint.Server, "inbound": endpoint.InboundTag,
			}
		}
		notice := ""
		if action == "remove" {
			notice = xraycfg.ShortIDRemovalNotice(raw, inbound)
		}
		if cfg.json {
			payload := map[string]any{"entry": entry, "user": view}
			if hot {
				payload["hot"] = hotReport
			}
			if notice != "" {
				payload["notice"] = notice
			}
			return writeJSON(opts, payload)
		}
		fmt.Fprintf(opts.Out, "%s: %s (%s)\n", entry.State, view.UUID, entry.ID)
		if notice != "" {
			fmt.Fprintln(opts.Out, notice)
		}
		if hot {
			fmt.Fprintf(opts.Out, "hot: applied to %s without restart\n", endpoint.Server)
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func xrayInstall(ctx context.Context, opts Options, cfg config, args []string) int {
	if strings.EqualFold(flagValue(args, "--role"), "relay") {
		return xrayInstallRelay(ctx, opts, cfg, args)
	}
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
		WSPort:               spec.WSPort,
		GRPCPort:             spec.GRPCPort,
		XHTTPPort:            spec.XHTTPPort,
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
		LocalIP:              flagValue(args, "--local-ip"),
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

// xrayInstallRelay installs a standalone relay: a managed Nginx stream{}
// forwarder without Xray. It shares the install vocabulary but needs a target
// instead of a runtime mode.
func xrayInstallRelay(ctx context.Context, opts Options, cfg config, args []string) int {
	target := flagValue(args, "--target")
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: "relay --target must be host:port"})
	}
	backendPort, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return fail(opts, cfg, &change.UsageError{Msg: "relay --target must be host:port"})
	}
	listenPort := 443
	if raw := flagValue(args, "--listen-port"); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil {
			return fail(opts, cfg, &change.UsageError{Msg: "--listen-port must be an integer"})
		}
		listenPort = v
	}
	listenAddress := flagValue(args, "--listen")
	if listenAddress == "" {
		listenAddress = "0.0.0.0"
	}
	report, err := deploy.InstallRelay(ctx, deploy.RelayInstallSpec{
		Root:                 cfg.root,
		BackendHost:          host,
		BackendPort:          backendPort,
		ListenPort:           listenPort,
		ListenAddress:        listenAddress,
		LocalIP:              flagValue(args, "--local-ip"),
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
	fmt.Fprintf(opts.Out, "relay: listen=%s target=%s\n", report.Listen, report.Backend)
	fmt.Fprintf(opts.Out, "config=%s\n", report.ConfigPath)
	fmt.Fprintf(opts.Out, "nginx managed=%t verified=%t dir=%s\n", report.NginxManaged, report.NginxVerified, report.NginxDir)
	for _, w := range report.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}

func xrayUninstall(ctx context.Context, opts Options, cfg config, args []string) int {
	report, err := deploy.Uninstall(ctx, deploy.UninstallSpec{
		Root:                 cfg.root,
		Purge:                hasFlag(args, "--purge"),
		KeepNginxConf:        hasFlag(args, "--keep-nginx-conf"),
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
	// A private key passed on argv is visible in the process list. The file
	// form keeps the legacy flag working while giving operators a controlled
	// way to avoid exposing the material for the lifetime of the process.
	if keyFile := flagValue(args, "--private-key-file"); keyFile != "" {
		if spec.PrivateKey != "" {
			return xraycfg.Spec{}, fmt.Errorf("--private-key and --private-key-file are mutually exclusive")
		}
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return xraycfg.Spec{}, fmt.Errorf("--private-key-file: %w", err)
		}
		if len(raw) > 4096 {
			return xraycfg.Spec{}, fmt.Errorf("--private-key-file: file exceeds 4096 bytes")
		}
		spec.PrivateKey = strings.TrimSpace(string(raw))
		if spec.PrivateKey == "" {
			return xraycfg.Spec{}, fmt.Errorf("--private-key-file: file is empty")
		}
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
	for _, port := range []struct {
		flag string
		dst  *int
	}{
		{"--ws-port", &spec.WSPort},
		{"--grpc-port", &spec.GRPCPort},
		{"--xhttp-port", &spec.XHTTPPort},
	} {
		if raw := flagValue(args, port.flag); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				return xraycfg.Spec{}, fmt.Errorf("%s must be an integer", port.flag)
			}
			*port.dst = v
		}
	}
	// Bash treats "Reality with an Nginx front" as its own install branch, while
	// the Go CLI names it --mode reality-nginx. Accept the Bash-shaped
	// combination as an alias so operators migrating argv do not have to learn a
	// second spelling; the artifacts are identical.
	if spec.Mode == xraycfg.ModeReality && flagValue(args, "--nginx-bin") != "" {
		spec.Mode = xraycfg.ModeRealityNginx
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

// xrayAPICommand enables or inspects the loopback API that hot user changes use.
func xrayAPICommand(ctx context.Context, opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	action, rest := args[0], args[1:]
	root := flagValue(rest, "--sandbox")
	if root == "" {
		root = cfg.root
	}
	if cfg.root != "/" && cfg.root != root {
		return usage(opts, cfg.lang, "help")
	}
	paths, err := host.NewPaths(root)
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")
	xrayBin := flagValue(rest, "--xray")
	if xrayBin == "" {
		xrayBin = filepath.Join(paths.Root, "usr/local/bin/xray")
	}
	targetPath := filepath.Join(paths.Root, paths.RuntimeConfig())
	if override := flagValue(rest, "--path"); override != "" {
		if targetPath, err = store.ResolveRuntimePath(paths, override); err != nil {
			return fail(opts, cfg, err)
		}
	}

	switch action {
	case "status":
		raw, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			return fail(opts, cfg, readErr)
		}
		endpoint, locErr := hotuser.Locate(raw, flagValue(rest, "--api-server"))
		status := map[string]any{"configured": locErr == nil, "server": "", "inboundTag": "", "reachable": false}
		if locErr == nil {
			status["server"] = endpoint.Server
			status["inboundTag"] = endpoint.InboundTag
			status["reachable"] = hotuser.Reachable(ctx, xrayBin, endpoint.Server) == nil
		}
		if cfg.json {
			return writeJSON(opts, status)
		}
		fmt.Fprintf(opts.Out, "configured=%t server=%v inbound=%v reachable=%t\n",
			status["configured"], status["server"], status["inboundTag"], status["reachable"])
		return 0
	case "enable":
		validator := flagValue(rest, "--validator")
		if validator == "" {
			return usage(opts, cfg.lang, "help")
		}
		service := flagValue(rest, "--service")
		if paths.Root == "/" && service == "" {
			return fail(opts, cfg, &change.UsageError{
				Msg: "enabling the API on a real root requires --service so the service loads it",
			})
		}
		port := 10085
		if raw := flagValue(rest, "--api-port"); raw != "" {
			v, convErr := strconv.Atoi(raw)
			if convErr != nil || v < 1 || v > 65535 {
				return usage(opts, cfg.lang, "help")
			}
			port = v
		}
		a.Paths = paths
		entry, changed, err := a.EnableXrayAPI(ctx, flagValue(rest, "--path"), port, validator, service,
			flagValue(rest, "--fault"), hasFlag(rest, "--container"))
		if err != nil {
			if cfg.json {
				_ = writeJSONNoExit(opts.Out, entry)
			}
			return fail(opts, cfg, err)
		}
		endpoint, locErr := hotuser.Locate(readFileOrNil(targetPath), flagValue(rest, "--api-server"))
		reachable := false
		if changed && locErr == nil {
			if waitErr := hotuser.WaitReachable(ctx, xrayBin, endpoint.Server, 5*time.Second); waitErr == nil {
				reachable = true
			} else {
				err = waitErr
			}
		}
		report := map[string]any{
			"entry": entry, "changed": changed, "port": port,
			"server": endpoint.Server, "reachable": reachable,
		}
		if err != nil {
			report["error"] = err.Error()
		}
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, report)
		}
		if err != nil {
			fmt.Fprintf(opts.Err, "API config committed but not reachable: %v\n", err)
			return 1
		}
		if cfg.json {
			return 0
		}
		if !changed {
			fmt.Fprintln(opts.Out, "API already enabled")
			return 0
		}
		fmt.Fprintf(opts.Out, "API enabled at %s (inbound %s)\n", endpoint.Server, endpoint.InboundTag)
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func readFileOrNil(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return raw
}

// hotApplyFailure reports a committed config that the running service did not
// receive. Exit 8 tells the caller "persisted, runtime pending".
func hotApplyFailure(opts Options, cfg config, entry change.Entry, view xraycfg.UserView, persisted bool, err error) int {
	if cfg.json {
		_ = writeJSONNoExit(opts.Out, map[string]any{
			"entry": entry, "user": view,
			"hot": map[string]any{"persisted": persisted, "applied": false, "error": err.Error()},
		})
	}
	fmt.Fprintf(opts.Err, "persisted=%t applied=false: %v\n", persisted, err)
	if persisted {
		fmt.Fprint(opts.Err, "the committed config is the source of truth; run `idleleo xray api enable` if needed, then retry\n")
	}
	return 8
}
