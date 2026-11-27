package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/componentupdate"
)

// componentUpdateCommand upgrades the managed Xray or Nginx artifact.
func componentUpdateCommand(ctx context.Context, opts Options, cfg config, component string, rest []string) int {
	manifest := flagValue(rest, "--manifest")
	if manifest == "" {
		fmt.Fprint(opts.Err, "--manifest <path|http(s) URL> is required\n")
		return 2
	}
	report, err := componentupdate.Apply(ctx, componentupdate.Spec{
		Root:                 cfg.root,
		Component:            component,
		ManifestSource:       manifest,
		AllowContainerWrites: hasFlag(rest, "--container"),
		NoRestart:            hasFlag(rest, "--no-restart"),
	})
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, report)
		}
		switch {
		case errors.Is(err, componentupdate.ErrDowngrade):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 4
		case errors.Is(err, componentupdate.ErrDigestMismatch):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 5
		case errors.Is(err, componentupdate.ErrHealth):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 6
		case errors.Is(err, componentupdate.ErrRollback):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 10
		case errors.Is(err, componentupdate.ErrManifest), errors.Is(err, componentupdate.ErrComponentMismatch):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 3
		default:
			return fail(opts, cfg, err)
		}
	}
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprintf(opts.Out, "component=%s action=%s %s -> %s\n",
		report.Component, report.Action, report.PreviousVersion, report.NewVersion)
	fmt.Fprintf(opts.Out, "sha256=%s size=%d verified=%t health=%t restarted=%t rolledBack=%t\n",
		report.SHA256, report.SizeBytes, report.Verified, report.Health, report.Restarted, report.RolledBack)
	if report.BackupPath != "" {
		fmt.Fprintf(opts.Out, "backup=%s\n", report.BackupPath)
	}
	for _, w := range report.Warnings {
		fmt.Fprintf(opts.Out, "warning=%s\n", w)
	}
	return 0
}

// updatePreflightCommand qualifies a candidate without activating it.
func updatePreflightCommand(ctx context.Context, opts Options, cfg config, rest []string) int {
	component := strings.ToLower(flagValue(rest, "--component"))
	manifest := flagValue(rest, "--manifest")
	if (component != componentupdate.KindXray && component != componentupdate.KindNginx) || manifest == "" {
		fmt.Fprint(opts.Err, "--component xray|nginx and --manifest <path|http(s) URL> are required\n")
		return 2
	}
	report, err := componentupdate.Preflight(ctx, componentupdate.Spec{
		Root:           cfg.root,
		Component:      component,
		ManifestSource: manifest,
	})
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, report)
		}
		switch {
		case errors.Is(err, componentupdate.ErrDowngrade):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 4
		case errors.Is(err, componentupdate.ErrDigestMismatch):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 5
		case errors.Is(err, componentupdate.ErrArtifact), errors.Is(err, componentupdate.ErrConfig):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 7
		case errors.Is(err, componentupdate.ErrManifest), errors.Is(err, componentupdate.ErrComponentMismatch):
			fmt.Fprint(opts.Err, err.Error()+"\n")
			return 3
		default:
			return fail(opts, cfg, err)
		}
	}
	if cfg.json {
		return writeJSON(opts, report)
	}
	fmt.Fprintf(opts.Out, "component=%s action=%s %s -> %s compatible=%t readiness=%s\n",
		report.Component, report.Action, report.PreviousVersion, report.CandidateVersion,
		report.Compatible, report.Readiness)
	fmt.Fprintf(opts.Out, "sha256=%s size=%d verified=%t\n",
		report.SHA256, report.SizeBytes, report.DigestVerified)
	for _, level := range report.Levels {
		fmt.Fprintf(opts.Out, "%-15s %-9s %s\n", level.Name, strings.ToUpper(level.Status), level.Detail)
	}
	return 0
}
