package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/release"
)

// updateCommand is the native replacement for the legacy auto_update.sh cron.
func updateCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	if rc, ok := checkFlags(opts, cfg, rest, "update "+sub); ok && rc != 0 {
		return rc
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")

	switch sub {
	case "status":
		rep, err := release.Status(cfg.root)
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "configured=%t channel=%s manifest=%s\n", rep.Configured, rep.Channel, rep.ManifestURL)
		fmt.Fprintf(opts.Out, "installPath=%s current=%s sha256=%s appliedAt=%s\n",
			rep.InstallPath, rep.CurrentVersion, rep.CurrentSHA256, rep.AppliedAt)
		return 0
	case "check":
		rep, err := release.Check(ctx, cfg.root, flagValue(rest, "--manifest-url"))
		if err != nil {
			return updateFail(opts, cfg, rep, err)
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "state=%s platform=%s current=%s latest=%s verified=%t\n",
			rep.State, rep.Platform, rep.CurrentVersion, rep.LatestVersion, rep.Verified)
		fmt.Fprintf(opts.Out, "asset=%s size=%d sha256=%s\n", rep.Asset.Name, rep.Asset.Size, rep.Asset.SHA256)
		if rep.Detail != "" {
			fmt.Fprintf(opts.Out, "detail=%s\n", rep.Detail)
		}
		return 0
	case "configure":
		if err := host.RequireSystemWrite(cfg.root, hasFlag(rest, "--container")); err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		ch, err := release.Configure(ctx, cfg.root, flagValue(rest, "--manifest-url"), flagValue(rest, "--install-path"))
		if err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 1
		}
		if cfg.json {
			return writeJSON(opts, ch)
		}
		fmt.Fprintf(opts.Out, "channel=%s manifest=%s installPath=%s\n", ch.Channel, ch.ManifestURL, ch.InstallPath)
		return 0
	case "apply":
		if err := host.RequireSystemWrite(cfg.root, hasFlag(rest, "--container")); err != nil {
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 2
		}
		rep, err := release.Apply(ctx, cfg.root, flagValue(rest, "--manifest-url"), nil)
		if err != nil {
			return updateFail(opts, cfg, rep, err)
		}
		if cfg.json {
			return writeJSON(opts, rep)
		}
		fmt.Fprintf(opts.Out, "action=%s previous=%s new=%s\n",
			rep.Action, rep.PreviousVersion, rep.NewVersion)
		fmt.Fprintf(opts.Out, "installPath=%s sha256=%s backup=%s health=%s\n",
			rep.InstallPath, rep.NewSHA256, rep.BackupPath, rep.HealthOutput)
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}

// updateFail maps the release error classes to stable exit codes.
func updateFail(opts Options, cfg config, rep any, err error) int {
	if cfg.json {
		_ = writeJSONNoExit(opts.Out, rep)
	}
	switch {
	case errors.Is(err, release.ErrNotConfigured):
		fmt.Fprint(opts.Err, "no Go release channel configured; run `idleleo update configure --manifest-url URL`\n")
		return 3
	case errors.Is(err, release.ErrDowngrade):
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 4
	case errors.Is(err, release.ErrRecoveryRequired):
		fmt.Fprint(opts.Err, strings.ToUpper(err.Error())+"\n")
		return 10
	default:
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 1
	}
}
