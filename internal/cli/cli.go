// Package cli implements the idleleo command surface.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/app"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/i18n"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// Version is the Phase 04 release-candidate version, deliberately not the
// Bash 3.3.4 release string and not a published Go release. It is a variable
// so release qualification can build fixtures with distinct versions via
// -ldflags -X, which is how the update channel is exercised end to end.
var Version = "0.2.0-phase04"

// Options injects streams and TTY detection for tests.
type Options struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
	TTY bool
}

type config struct {
	root string
	lang string
	json bool
}

// Run returns a stable Phase 01 exit code.
func Run(ctx context.Context, args []string, opts Options) int {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.Err == nil {
		opts.Err = os.Stderr
	}
	cfg := config{root: "/", lang: "zh"}
	var cmd string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--root":
			if i+1 >= len(args) {
				return usage(opts, cfg.lang, "help")
			}
			i++
			cfg.root = args[i]
		case "--lang":
			if i+1 >= len(args) {
				return usage(opts, cfg.lang, "help")
			}
			i++
			cfg.lang = args[i]
		case "--json":
			cfg.json = true
		case "--help", "-h":
			announceFallback(opts, cfg.lang)
			printHelp(opts, cfg.lang)
			return 0
		case "--version":
			announceFallback(opts, cfg.lang)
			fmt.Fprintf(opts.Out, i18n.T(cfg.lang, "version"), Version)
			return 0
		default:
			cmd, rest = args[i], args[i+1:]
			i = len(args)
		}
	}
	if !i18n.Supported(cfg.lang) {
		return usage(opts, "en", "help")
	}
	if notice := i18n.FallbackNotice(cfg.lang); notice != "" {
		fmt.Fprint(opts.Err, notice)
	}
	if cmd == "" {
		if opts.TTY {
			return menu(ctx, opts, cfg)
		}
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "no_tty"))
		printHelp(opts, cfg.lang)
		return 2
	}
	// Subcommand help must never fall through to command execution; without
	// this, `xray generate --help` was parsed as a generation request.
	for _, arg := range rest {
		if arg == "--help" || arg == "-h" {
			printHelp(opts, cfg.lang)
			return 0
		}
	}
	return dispatch(ctx, opts, cfg, cmd, rest)
}

func dispatch(ctx context.Context, opts Options, cfg config, cmd string, args []string) int {
	paths, err := host.NewPaths(cfg.root)
	if err != nil {
		return fail(opts, cfg, err)
	}
	a := &app.App{Paths: paths, Lang: cfg.lang}
	switch cmd {
	case "help":
		printHelp(opts, cfg.lang)
		return 0
	case "version":
		fmt.Fprintf(opts.Out, i18n.T(cfg.lang, "version"), Version)
		return 0
	case "status":
		cfg.json = cfg.json || hasFlag(args, "--json")
		report, err := a.Status(ctx)
		if err != nil {
			return fail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		printStatus(opts.Out, report)
		return 0
	case "show", "-s", "--show":
		if paths.Root == "/" && os.Geteuid() != 0 {
			return fail(opts, cfg, &store.Error{Kind: store.KindPermission, Msg: "root required"})
		}
		override := flagValue(args, "--path")
		report, err := a.Show(override)
		if err != nil {
			return fail(opts, cfg, err)
		}
		cfg.json = cfg.json || hasFlag(args, "--json")
		if cfg.json {
			return writeJSON(opts, report)
		}
		printShow(opts.Out, report)
		return 0
	case "config":
		return configCommand(opts, cfg, a, args)
	case "change":
		return changeCommand(ctx, opts, cfg, a, args)
	case "xray":
		return xrayCommand(ctx, opts, cfg, a, args)
	case "bridge":
		return bridgeCommand(ctx, opts, cfg, args)
	case "metadata":
		return metadataCommand(opts, cfg, args)
	case "schedule":
		return scheduleCommand(ctx, opts, cfg, args)
	case "update":
		return updateCommand(ctx, opts, cfg, args)
	case "stats":
		return statsCommand(ctx, opts, cfg, args)
	case "service":
		return serviceCommand(ctx, opts, cfg, args)
	case "tcp":
		return tcpCommand(ctx, opts, cfg, args)
	case "rill":
		return rillCommand(opts, cfg, args)
	case "recover":
		return recoverCommand(opts, cfg, args)
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func configCommand(opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 || args[0] != "inspect" {
		return usage(opts, cfg.lang, "help")
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	view, err := a.Inspect(flagValue(args, "--path"))
	if err != nil {
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, view)
	}
	fmt.Fprintf(opts.Out, "path: %s\nsha256: %s\nbytes: %d\n", view.Path, view.SHA256, view.Bytes)
	for _, in := range view.Inbounds {
		fmt.Fprintf(opts.Out, "inbound[%d]: protocol=%s port=%s network=%s security=%s\n",
			in.Index, in.Protocol, in.Port, in.Network, in.Security)
	}
	fmt.Fprintf(opts.Out, "custom: dns=%t routing=%t outbounds=%t other=%v\n",
		view.Custom.DNS, view.Custom.Routing, view.Custom.Outbounds, view.Custom.OtherTopLevelKeys)
	return 0
}

func changeCommand(ctx context.Context, opts Options, cfg config, a *app.App, args []string) int {
	if len(args) == 0 || args[0] != "set-inbound-port" {
		return usage(opts, cfg.lang, "help")
	}
	args = args[1:]
	sandbox := flagValue(args, "--sandbox")
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
	portRaw := flagValue(args, "--port")
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return usage(opts, cfg.lang, "help")
	}
	inbound := 0
	if raw := flagValue(args, "--inbound"); raw != "" {
		inbound, err = strconv.Atoi(raw)
		if err != nil {
			return usage(opts, cfg.lang, "help")
		}
	}
	validator := flagValue(args, "--validator")
	if validator == "" {
		return usage(opts, cfg.lang, "help")
	}
	service := flagValue(args, "--service")
	fault := flagValue(args, "--fault")
	cfg.json = cfg.json || hasFlag(args, "--json")
	entry, err := a.ChangePort(ctx, flagValue(args, "--path"), inbound, port, validator, service, fault)
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, entry)
		}
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, entry)
	}
	fmt.Fprintf(opts.Out, "%s: %s -> %s (%s)\n", entry.State, entry.OldSHA256[:12], entry.NewSHA256[:12], entry.ID)
	return 0
}

func menu(ctx context.Context, opts Options, cfg config) int {
	sc := bufio.NewScanner(opts.In)
	for {
		fmt.Fprint(opts.Out, "\n1) status  2) show  3) config inspect  4) help  0) exit\n> ")
		if !sc.Scan() {
			return 0
		}
		switch strings.TrimSpace(sc.Text()) {
		case "0", "q", "quit", "exit":
			return 0
		case "1":
			_ = dispatch(ctx, opts, cfg, "status", nil)
		case "2":
			_ = dispatch(ctx, opts, cfg, "show", nil)
		case "3":
			_ = dispatch(ctx, opts, cfg, "config", []string{"inspect"})
		case "4":
			printHelp(opts, cfg.lang)
		default:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "usage"))
		}
	}
}

func printStatus(out io.Writer, r app.StatusReport) {
	fmt.Fprintf(out, "installed: %t\nengine: %s\nrole: %s\ntls: %s\ntransport: %s\n",
		r.Installed, r.Engine, r.Role, r.TLS, r.Transport)
	fmt.Fprintf(out, "config: %s\nsha256: %s\nmatchesMetadata: %t\n", r.Config.Path, r.Config.SHA256, r.Config.MatchesMetadata)
	fmt.Fprintf(out, "service: xray=%s nginx=%s enabled=%s source=%s\n", r.Service.Xray, r.Service.Nginx, r.Service.Enabled, r.Service.Source)
	if len(r.Drift) > 0 {
		fmt.Fprintf(out, "drift: %s\n", strings.Join(r.Drift, ","))
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(out, "warnings: %s\n", strings.Join(r.Warnings, ","))
	}
}

func printShow(out io.Writer, r app.ShowReport) {
	for k, v := range r.Info {
		fmt.Fprintf(out, "%s=%s\n", k, v)
	}
	if r.Authority != "" {
		fmt.Fprintf(out, "authority: %s\n", r.Authority)
	}
	for _, in := range r.Inbounds {
		fmt.Fprintf(out, "inbound[%d]: protocol=%s port=%s network=%s security=%s\n",
			in.Index, in.Protocol, in.Port, in.Network, in.Security)
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintf(out, "warnings: %s\n", strings.Join(r.Warnings, ","))
	}
}

func writeJSON(opts Options, v any) int {
	if err := writeJSONNoExit(opts.Out, v); err != nil {
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 1
	}
	return 0
}

func writeJSONNoExit(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func fail(opts Options, cfg config, err error) int {
	switch {
	case errors.As(err, new(*store.Error)):
		var se *store.Error
		_ = errors.As(err, &se)
		switch se.Kind {
		case store.KindNotFound:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "not_installed"))
		case store.KindCorrupt:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "corrupt", se.Msg))
		case store.KindSchemaHigh:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "schema_high", se.Msg))
		case store.KindUnsupported:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "unsupported", se.Msg))
		case store.KindPermission:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "permission", se.Msg))
		case store.KindDrift:
			fmt.Fprint(opts.Err, i18n.T(cfg.lang, "drift", se.Msg))
		}
		return store.ExitCode(err)
	case errors.As(err, new(*change.UsageError)):
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 2
	case errors.As(err, new(*change.ConflictError)):
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "locked"))
		return 7
	case errors.As(err, new(*change.IOError)):
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "io_error", err.Error()))
		return 13
	case errors.As(err, new(*change.RecoveryError)):
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "recovery", err.Error()))
		return 10
	case errors.As(err, new(*runtime.ValidationError)):
		var ve *runtime.ValidationError
		_ = errors.As(err, &ve)
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "validation", ve.ExitCode, ve.Output))
		return 8
	case errors.As(err, new(*runtime.ServiceError)):
		var se *runtime.ServiceError
		_ = errors.As(err, &se)
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "service_failed", se.ExitCode, se.Output))
		return 9
	case errors.Is(err, host.ErrLocked):
		fmt.Fprint(opts.Err, i18n.T(cfg.lang, "locked"))
		return 7
	default:
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 1
	}
}

func usage(opts Options, lang, key string) int {
	if key == "help" {
		printHelp(opts, lang)
	} else {
		fmt.Fprint(opts.Err, i18n.T(lang, key))
	}
	return 2
}

// printHelp renders the help text with the same version string that
// `idleleo version` prints, so the help header cannot drift from the binary.
func printHelp(opts Options, lang string) {
	fmt.Fprint(opts.Out, i18n.T(lang, "help", Version))
}

// announceFallback tells the operator that the requested language has no Go
// catalog yet. Silence would look like a broken translation.
func announceFallback(opts Options, lang string) {
	if notice := i18n.FallbackNotice(lang); notice != "" {
		fmt.Fprint(opts.Err, notice)
	}
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
