package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/backup"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
)

// backupCommand owns create/verify/restore. Create and restore are gated like
// any other write because archives carry private keys and restore replaces
// live files; verify is read-only and may run anywhere.
func backupCommand(ctx context.Context, opts Options, cfg config, paths host.Paths, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	switch args[0] {
	case "create":
		if rc, ok := checkFlags(opts, cfg, args[1:], "backup create"); ok && rc != 0 {
			return rc
		}
		return backupCreate(ctx, opts, cfg, paths, args[1:])
	case "verify":
		if rc, ok := checkFlags(opts, cfg, args[1:], "backup verify"); ok && rc != 0 {
			return rc
		}
		return backupVerify(opts, cfg, args[1:])
	case "restore":
		if rc, ok := checkFlags(opts, cfg, args[1:], "backup restore"); ok && rc != 0 {
			return rc
		}
		return backupRestore(ctx, opts, cfg, paths, args[1:])
	default:
		return usage(opts, cfg.lang, "help")
	}
}

func backupCreate(ctx context.Context, opts Options, cfg config, paths host.Paths, args []string) int {
	if err := host.RequireSystemWrite(paths.Root, hasFlag(args, "--container")); err != nil {
		return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
	}
	out := flagValue(args, "--out")
	if out == "" {
		out = filepath.Join(paths.Root, "etc/idleleo/backup",
			"manual-"+time.Now().UTC().Format("20060102T150405Z")+".tar.gz")
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	rep, err := backup.Create(ctx, paths.Root, out, backup.CreateOptions{
		IncludeGeodata: hasFlag(args, "--include-geodata"),
		SourceVersion:  Version,
	})
	if err != nil {
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, rep)
	}
	fmt.Fprintf(opts.Out, "archive=%s sha256=%s files=%d bytes=%d\n",
		rep.Archive, rep.ArchiveSHA256, rep.Files, rep.Bytes)
	return 0
}

func backupVerify(opts Options, cfg config, args []string) int {
	archive := flagValue(args, "--archive")
	if archive == "" {
		return usage(opts, cfg.lang, "help")
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	manifest, err := backup.Verify(archive)
	if err != nil {
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, manifest)
	}
	fmt.Fprintf(opts.Out, "archive=%s files=%d createdAt=%s geodata=%t\n",
		archive, len(manifest.Entries), manifest.CreatedAt, manifest.IncludeGeo)
	return 0
}

func backupRestore(ctx context.Context, opts Options, cfg config, paths host.Paths, args []string) int {
	archive := flagValue(args, "--archive")
	if archive == "" {
		return usage(opts, cfg.lang, "help")
	}
	dryRun := hasFlag(args, "--dry-run")
	if !dryRun {
		if err := host.RequireSystemWrite(paths.Root, hasFlag(args, "--container")); err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
		}
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	rep, err := backup.Restore(ctx, paths.Root, archive, backup.RestoreOptions{
		NoPreBackup: hasFlag(args, "--no-pre-backup"),
		DryRun:      dryRun,
		Validate:    managedValidator(paths),
	})
	if err != nil {
		if cfg.json {
			_ = writeJSONNoExit(opts.Out, rep)
		}
		return fail(opts, cfg, err)
	}
	if cfg.json {
		return writeJSON(opts, rep)
	}
	if rep.DryRun {
		for _, c := range rep.Changes {
			fmt.Fprintf(opts.Out, "%s %s\n", c.Action, c.Path)
		}
		fmt.Fprintf(opts.Out, "dry-run: files=%d archive=%s\n", rep.Files, rep.Archive)
		return 0
	}
	fmt.Fprintf(opts.Out, "restored=%d archive=%s preBackup=%s\n",
		len(rep.Restored), rep.Archive, rep.PreBackup)
	return 0
}

// managedValidator returns the real Xray validator when the managed binary is
// present. A missing binary yields nil so restore still works on a host where
// Xray is not installed yet.
func managedValidator(paths host.Paths) func(context.Context, string) error {
	bin := ""
	if paths.Root == "/" {
		if _, err := os.Stat("/usr/local/bin/xray"); err == nil {
			bin = "/usr/local/bin/xray"
		}
	} else if p := filepath.Join(paths.Root, "usr/local/bin/xray"); fileExists(p) {
		bin = p
	}
	if bin == "" {
		return nil
	}
	v := runtime.XrayValidator{Path: bin, AssetDir: paths.GeodataDir()}
	return v.Validate
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
