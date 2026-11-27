package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	case "recover":
		if rc, ok := checkFlags(opts, cfg, args[1:], "backup recover"); ok && rc != 0 {
			return rc
		}
		return backupRecover(ctx, opts, cfg, paths, args[1:])
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
		Apply:       restoreServiceApply(paths),
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
	if paths.Root != "/" {
		rep.Warnings = append(rep.Warnings, "service restart and unit rebuild are skipped for a sandbox root")
	}
	fmt.Fprintf(opts.Out, "restored=%d archive=%s preBackup=%s\n",
		len(rep.Restored), rep.Archive, rep.PreBackup)
	for _, w := range rep.Warnings {
		fmt.Fprintf(opts.Err, "warning: %s\n", w)
	}
	return 0
}

// backupRecover converges an interrupted restore. It is deliberately explicit:
// a second destructive restore is refused until the journal is terminal.
func backupRecover(ctx context.Context, opts Options, cfg config, paths host.Paths, args []string) int {
	if !hasFlag(args, "--dry-run") {
		if err := host.RequireSystemWrite(paths.Root, hasFlag(args, "--container")); err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: err.Error()})
		}
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	rep, err := backup.Recover(ctx, paths.Root, backup.RecoverOptions{
		DryRun: hasFlag(args, "--dry-run"),
		Apply:  restoreServiceApply(paths),
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
	fmt.Fprintf(opts.Out, "recover action=%s state=%s converged=%t\n", rep.Action, rep.State, rep.Converged)
	for _, w := range rep.Warnings {
		fmt.Fprintf(opts.Err, "warning: %s\n", w)
	}
	return 0
}

// restoreServiceApply rebuilds and verifies the live service only on a real
// root. It runs inside the restore transaction, so a failing restart rolls the
// files back instead of leaving a half-applied host.
func restoreServiceApply(paths host.Paths) func(context.Context) error {
	if paths.Root != "/" {
		return nil
	}
	return func(ctx context.Context) error {
		if _, err := os.Stat("/usr/sbin/nginx"); err == nil {
			res, err := host.Run(ctx, host.ExecSpec{Path: "/usr/sbin/nginx", Args: []string{"-t"}, Timeout: 30 * time.Second})
			if err != nil {
				return err
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("nginx -t exited %d: %s", res.ExitCode, firstLine(res.Stderr))
			}
		}
		// A relay node runs Nginx only, while every Xray node (Reality, TLS,
		// multi-transport) runs both. The restored state must reload whichever
		// units actually exist instead of assuming one layout.
		restarted := false
		for _, unit := range []string{"xray", "nginx"} {
			if !unitExists(ctx, unit) {
				continue
			}
			if unit == "nginx" && !nginxOwned(ctx, paths) {
				continue
			}
			res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"restart", unit}, Timeout: 90 * time.Second})
			if err != nil {
				return err
			}
			if res.ExitCode != 0 {
				return fmt.Errorf("systemctl restart %s exited %d: %s", unit, res.ExitCode, firstLine(res.Stderr))
			}
			active, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-active", "--quiet", unit}, Timeout: 15 * time.Second})
			if err != nil {
				return err
			}
			if active.ExitCode != 0 {
				return fmt.Errorf("%s service is not active after restore (exit %d)", unit, active.ExitCode)
			}
			restarted = true
		}
		if !restarted {
			return fmt.Errorf("the restored state has no xray or nginx service unit")
		}
		return nil
	}
}

// unitExists reports whether systemd knows the unit, so a relay host without an
// Xray unit restores cleanly and an Xray-only host without Nginx keeps working.
func unitExists(ctx context.Context, unit string) bool {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"cat", unit}, Timeout: 15 * time.Second})
	return err == nil && res.ExitCode == 0
}

// nginxOwned avoids restarting an unrelated Nginx that merely happens to be
// installed. The managed tree records its own metadata, and the Bash layout
// leaves the service running.
func nginxOwned(ctx context.Context, paths host.Paths) bool {
	if _, err := os.Stat(filepath.Join(paths.Root, "etc/idleleo/v1/nginx.json")); err == nil {
		return true
	}
	active, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"is-active", "--quiet", "nginx"}, Timeout: 15 * time.Second})
	return err == nil && active.ExitCode == 0
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
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
