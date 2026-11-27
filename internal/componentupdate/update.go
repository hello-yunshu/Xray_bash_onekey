package componentupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
)

// Spec is one component upgrade request.
type Spec struct {
	Root                 string
	Component            string
	ManifestSource       string
	AllowContainerWrites bool
	NoRestart            bool
}

// Report is the JSON contract for `update xray|nginx`.
type Report struct {
	SchemaVersion   int      `json:"schemaVersion"`
	Component       string   `json:"component"`
	PreviousVersion string   `json:"previousVersion"`
	NewVersion      string   `json:"newVersion"`
	Action          string   `json:"action"`
	SHA256          string   `json:"sha256"`
	SizeBytes       int64    `json:"sizeBytes"`
	BackupPath      string   `json:"backupPath,omitempty"`
	Verified        bool     `json:"verified"`
	Health          bool     `json:"health"`
	Restarted       bool     `json:"restarted"`
	RolledBack      bool     `json:"rolledBack"`
	Warnings        []string `json:"warnings,omitempty"`
}

var versionToken = regexp.MustCompile(`[vV]?[0-9]+(?:\.[0-9]+)+`)
var nginxVersion = regexp.MustCompile(`nginx version:\s*nginx/([0-9]+(?:\.[0-9]+)*)`)

// Apply runs manifest validation, download, backup, activation, health and
// rollback as one transaction. A downgrade or digest failure touches nothing.
func Apply(ctx context.Context, spec Spec) (Report, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return Report{}, &change.UsageError{Msg: err.Error()}
	}
	if err := host.RequireSystemWrite(paths.Root, spec.AllowContainerWrites); err != nil {
		return Report{}, &change.UsageError{Msg: err.Error()}
	}
	if spec.Component != KindXray && spec.Component != KindNginx {
		return Report{}, &change.UsageError{Msg: "component must be xray or nginx"}
	}
	m, err := LoadManifest(ctx, spec.ManifestSource)
	if err != nil {
		return Report{}, err
	}
	if m.Component != spec.Component {
		return Report{}, fmt.Errorf("%w: manifest is for %s, command is %s",
			ErrComponentMismatch, m.Component, spec.Component)
	}
	report := Report{
		SchemaVersion: 1,
		Component:     spec.Component,
		NewVersion:    m.Version,
		SHA256:        m.SHA256,
		SizeBytes:     m.SizeBytes,
	}
	previous, err := installedVersion(ctx, paths.Root, spec.Component)
	if err != nil {
		return report, err
	}
	report.PreviousVersion = previous
	report.Action = "install"
	if previous != "" {
		cmp, err := CompareVersions(m.Version, previous)
		if err != nil {
			return report, err
		}
		switch {
		case cmp < 0:
			return report, fmt.Errorf("%w: installed %s, manifest %s",
				ErrDowngrade, previous, m.Version)
		case cmp == 0:
			report.Action = "reinstall"
		default:
			report.Action = "update"
		}
	}

	data, err := FetchAsset(ctx, m)
	if err != nil {
		return report, err
	}
	report.Verified = true
	// The Nginx distribution archive contains a stock nginx.conf. Keep the
	// installed main config across upgrades: it is the entry point for the
	// managed site fragments under /etc/idleleo/conf/nginx. Without this,
	// replacing the installation tree silently disables the public front while
	// the stock config still passes `nginx -t`.
	var nginxConfig []byte
	var nginxConfigMode os.FileMode
	if spec.Component == KindNginx && previous != "" {
		configPath := filepath.Join(nginxDir(paths.Root), "conf/nginx.conf")
		if info, statErr := os.Stat(configPath); statErr == nil && info.Mode().IsRegular() {
			nginxConfig, err = os.ReadFile(configPath)
			if err != nil {
				return report, fmt.Errorf("read installed nginx config: %w", err)
			}
			nginxConfigMode = info.Mode().Perm()
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return report, fmt.Errorf("inspect installed nginx config: %w", statErr)
		}
	}

	backup, err := backup(ctx, paths.Root, spec.Component, previous)
	if err != nil {
		return report, err
	}
	report.BackupPath = backup

	var healthErr error
	switch spec.Component {
	case KindXray:
		healthErr = installXray(paths.Root, data)
	case KindNginx:
		healthErr = installNginx(paths.Root, data, nginxConfig, nginxConfigMode)
	}
	if healthErr == nil {
		healthErr = verifyVersion(ctx, paths.Root, spec.Component, m.Version)
	}
	if healthErr == nil {
		healthErr = healthCheck(ctx, paths.Root, spec.Component)
	}
	if healthErr != nil {
		report.RolledBack = true
		if err := restore(paths.Root, spec.Component, backup); err != nil {
			return report, fmt.Errorf("%w: %v (rollback: %v)", ErrRollback, healthErr, err)
		}
		return report, fmt.Errorf("%w: %v", ErrHealth, healthErr)
	}
	report.Health = true

	if spec.NoRestart {
		report.Warnings = append(report.Warnings, "restart disabled by --no-restart")
	} else if paths.Root == "/" && systemdAvailable() {
		if err := restart(ctx, spec.Component); err != nil {
			report.Warnings = append(report.Warnings, err.Error())
		} else {
			report.Restarted = true
		}
	} else {
		report.Warnings = append(report.Warnings,
			"service reload skipped for a sandbox root; restart xray/nginx on the target host")
	}
	return report, nil
}

func systemdAvailable() bool {
	fi, err := os.Stat("/run/systemd/system")
	if err != nil || !fi.IsDir() {
		return false
	}
	_, err = host.ResolveBinary("systemctl")
	return err == nil
}

func restart(ctx context.Context, component string) error {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"restart", component}})
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w", component, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl restart %s failed: %s", component,
			strings.TrimSpace(res.Stderr+res.Stdout))
	}
	return nil
}

func xrayBinary(root string) string { return filepath.Join(root, "usr/local/bin/xray") }
func nginxDir(root string) string   { return filepath.Join(root, "usr/local/nginx") }

func installedVersion(ctx context.Context, root, component string) (string, error) {
	switch component {
	case KindXray:
		bin := xrayBinary(root)
		if !regular(bin) {
			return "", nil
		}
		res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"version"}})
		if err != nil {
			return "", fmt.Errorf("read installed xray version: %w", err)
		}
		if res.ExitCode != 0 {
			return "", fmt.Errorf("read installed xray version: exit %d: %s", res.ExitCode, res.Stderr)
		}
		line := firstLine(res.Stdout + res.Stderr)
		if v := versionToken.FindString(line); v != "" {
			return normalizeVersion(v), nil
		}
		return "", fmt.Errorf("%w: cannot parse installed xray version from %q", ErrManifest, line)
	case KindNginx:
		bin := filepath.Join(nginxDir(root), "sbin/nginx")
		if !regular(bin) {
			return "", nil
		}
		res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"-v"}})
		if err != nil {
			return "", fmt.Errorf("read installed nginx version: %w", err)
		}
		match := nginxVersion.FindStringSubmatch(res.Stdout + res.Stderr)
		if len(match) != 2 {
			return "", fmt.Errorf("%w: cannot parse installed nginx version", ErrManifest)
		}
		return match[1], nil
	}
	return "", &change.UsageError{Msg: "unknown component"}
}

// healthCheck exercises the activated artifact without starting a service.
func healthCheck(ctx context.Context, root, component string) error {
	switch component {
	case KindXray:
		bin := xrayBinary(root)
		conf := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
		if !regular(conf) {
			return nil
		}
		res, err := host.Run(ctx, host.ExecSpec{
			Path: bin, Args: []string{"run", "-test", "-config", conf}, Timeout: 30 * time.Second,
		})
		if err != nil {
			return fmt.Errorf("xray health check: %w", err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("xray health check failed: %s", strings.TrimSpace(res.Stderr+res.Stdout))
		}
	case KindNginx:
		conf := filepath.Join(nginxDir(root), "conf/nginx.conf")
		if !regular(conf) {
			return nil
		}
		res, err := host.Run(ctx, host.ExecSpec{
			Path: filepath.Join(nginxDir(root), "sbin/nginx"),
			Args: []string{"-t", "-p", nginxDir(root) + "/", "-c", conf},
		})
		if err != nil {
			return fmt.Errorf("nginx health check: %w", err)
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("nginx health check failed: %s", strings.TrimSpace(res.Stderr+res.Stdout))
		}
	}
	return nil
}

func verifyVersion(ctx context.Context, root, component, want string) error {
	got, err := installedVersion(ctx, root, component)
	if err != nil {
		return err
	}
	if got != normalizeVersion(want) {
		return fmt.Errorf("installed version reads %q, want %q", got, want)
	}
	return nil
}

func backup(ctx context.Context, root, component, previous string) (string, error) {
	dir := filepath.Join(root, "etc/idleleo/backup")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", &change.IOError{Msg: "create backup directory: " + err.Error()}
	}
	label := previous
	if label == "" {
		label = "none"
	}
	target := filepath.Join(dir, fmt.Sprintf("%s-%s-%d", component, label, time.Now().UnixNano()))
	switch component {
	case KindXray:
		bin := xrayBinary(root)
		if !regular(bin) {
			return "", nil
		}
		if err := copyFile(bin, target, 0o755); err != nil {
			return "", &change.IOError{Msg: "back up xray: " + err.Error()}
		}
	case KindNginx:
		src := nginxDir(root)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			return "", nil
		}
		if err := os.Rename(src, target); err != nil {
			return "", &change.IOError{Msg: "back up nginx directory: " + err.Error()}
		}
	}
	return target, nil
}

func installXray(root string, data []byte) error {
	bin := xrayBinary(root)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		return err
	}
	tmp := bin + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, bin)
}

func installNginx(root string, data, preservedConfig []byte, configMode os.FileMode) error {
	stageParent := filepath.Join(root, "usr/local/.nginx-stage")
	_ = os.RemoveAll(stageParent)
	if err := os.MkdirAll(stageParent, 0o755); err != nil {
		return err
	}
	if err := nginx.Extract(data, stageParent); err != nil {
		_ = os.RemoveAll(stageParent)
		return err
	}
	staged := filepath.Join(stageParent, "nginx")
	bin := filepath.Join(staged, "sbin/nginx")
	if !executable(bin) {
		_ = os.RemoveAll(stageParent)
		return errors.New("artifact does not contain an executable nginx/sbin/nginx")
	}
	if preservedConfig != nil {
		conf := filepath.Join(staged, "conf/nginx.conf")
		if err := os.WriteFile(conf, preservedConfig, configMode.Perm()); err != nil {
			_ = os.RemoveAll(stageParent)
			return fmt.Errorf("preserve installed nginx config: %w", err)
		}
		if err := os.Chmod(conf, configMode.Perm()); err != nil {
			_ = os.RemoveAll(stageParent)
			return fmt.Errorf("preserve installed nginx config permissions: %w", err)
		}
	}
	target := nginxDir(root)
	if err := os.Rename(staged, target); err != nil {
		_ = os.RemoveAll(stageParent)
		return err
	}
	_ = os.RemoveAll(stageParent)
	return nil
}

func restore(root, component, backup string) error {
	switch component {
	case KindXray:
		bin := xrayBinary(root)
		if backup == "" {
			return os.Remove(bin)
		}
		return copyFile(backup, bin, 0o755)
	case KindNginx:
		target := nginxDir(root)
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		if backup == "" {
			return nil
		}
		return os.Rename(backup, target)
	}
	return errors.New("unknown component")
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func regular(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func executable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
