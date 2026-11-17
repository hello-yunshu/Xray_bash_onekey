package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
)

const (
	logrotateConfRel   = "etc/logrotate.d/xray_log_cleanup"
	logrotateDropinRel = "etc/systemd/system/logrotate.service.d/10-idleleo-readwrite.conf"
	logrotateTimer     = "logrotate.timer"
)

// LogsSpec is one `xray logs` request. Both operations mutate the host, so a
// real root needs the same container acknowledgement as an install.
type LogsSpec struct {
	Root                 string
	AllowContainerWrites bool
}

// LogsFailure records one log file that could not be truncated.
type LogsFailure struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// LogsReport is the machine-readable result of `xray logs clean`.
type LogsReport struct {
	Truncated []string      `json:"truncated"`
	Failed    []LogsFailure `json:"failed,omitempty"`
	Freed     int64         `json:"freedBytes"`
}

// RotationReport is the machine-readable result of `xray logs rotate`.
type RotationReport struct {
	Enabled     bool     `json:"enabled"`
	ConfigPath  string   `json:"configPath,omitempty"`
	DropinPath  string   `json:"dropinPath,omitempty"`
	TimerActive bool     `json:"timerActive"`
	Removed     []string `json:"removed,omitempty"`
	Warnings    []string `json:"warnings"`
}

// Seams for tests: the generated config is validated by the real logrotate
// binary, which a sandbox run must not require, and the Nginx worker account
// only exists on a host with a managed front.
var (
	lookPathLogrotate = func() (string, error) { return exec.LookPath("logrotate") }
	checkLogrotate    = func(ctx context.Context, bin, conf string) error {
		res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"--debug", conf}, Timeout: 30 * time.Second})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("logrotate --debug failed with exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		return nil
	}
	nginxLogAccount = func() (string, string) {
		if u, err := user.Lookup(nginx.WorkerUser); err == nil {
			if g, gerr := user.LookupGroup(nginx.WorkerGroup); gerr == nil {
				return u.Username, g.Name
			}
		}
		// Bash falls back to nobody's account when the managed worker is absent.
		if u, err := user.Lookup("nobody"); err == nil {
			if g, gerr := user.LookupGroupId(u.Gid); gerr == nil {
				return "nobody", g.Name
			}
			return "nobody", "nogroup"
		}
		return "nobody", "nogroup"
	}
)

// CleanLogs truncates every regular *.log file under the Xray and Nginx log
// directories. It mirrors Bash's clean_logs: the inode, owner and mode stay
// untouched so a running Xray keeps writing through the same descriptor.
func CleanLogs(ctx context.Context, spec LogsSpec) (LogsReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return LogsReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return LogsReport{}, err
	}
	rep := LogsReport{Truncated: []string{}}
	for _, rel := range []string{logDirRel, nginx.InstallDirRel + "/logs"} {
		dir, err := paths.Join(rel, false)
		if err != nil {
			// A missing log directory is not a failure: there is nothing to clean.
			continue
		}
		if walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".log") {
				return nil
			}
			info, statErr := d.Info()
			if statErr != nil {
				rep.Failed = append(rep.Failed, LogsFailure{Path: path, Error: statErr.Error()})
				return nil
			}
			if truncErr := truncateLogFile(path); truncErr != nil {
				rep.Failed = append(rep.Failed, LogsFailure{Path: path, Error: truncErr.Error()})
				return nil
			}
			rep.Truncated = append(rep.Truncated, path)
			rep.Freed += info.Size()
			return nil
		}); walkErr != nil {
			return LogsReport{}, walkErr
		}
	}
	sort.Strings(rep.Truncated)
	sort.Slice(rep.Failed, func(i, j int) bool { return rep.Failed[i].Path < rep.Failed[j].Path })
	return rep, nil
}

func truncateLogFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// EnableLogRotation installs the same logrotate block and systemd drop-in that
// Bash writes, then enables logrotate.timer. It is idempotent: re-running
// rewrites the artifacts instead of prompting (the CLI has no menu loop).
func EnableLogRotation(ctx context.Context, spec LogsSpec) (RotationReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return RotationReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return RotationReport{}, err
	}
	bin, err := lookPathLogrotate()
	if err != nil {
		return RotationReport{}, fmt.Errorf("logrotate is not installed; install it first, then re-run:\n" +
			"  Debian/Ubuntu: apt-get update && apt-get install -y logrotate\n" +
			"  RHEL/Fedora:   dnf install -y logrotate\n" +
			"  Alpine:        apk add logrotate\n" +
			"the Go manager never runs the OS package manager (Bash installs it automatically), so nothing was written")
	}
	rep := RotationReport{Warnings: []string{}}
	// Bash enables the timer before writing the config, so a host without the
	// timer unit fails before anything is replaced.
	if !serviceManaged(paths.Root) {
		rep.Warnings = append(rep.Warnings, "sandbox root: systemd timer not touched")
	} else if err := serviceCommand(ctx, "enable", "--now", logrotateTimer); err != nil {
		return RotationReport{}, fmt.Errorf("enable %s failed: %w", logrotateTimer, err)
	} else {
		rep.TimerActive = true
	}

	nginxDir := filepath.Join(paths.Root, filepath.FromSlash(nginx.InstallDirRel))
	logDir := filepath.Join(paths.Root, filepath.FromSlash(logDirRel))
	worker, group := nginxLogAccount()
	conf := logrotateConfig(logDir, nginxDir, worker, group)

	confPath, err := paths.Join(logrotateConfRel, true)
	if err != nil {
		return RotationReport{}, err
	}
	if err := writeLogrotateConfig(ctx, bin, confPath, conf); err != nil {
		return RotationReport{}, err
	}
	dropinPath, err := paths.Join(logrotateDropinRel, true)
	if err != nil {
		return RotationReport{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dropinPath), 0o755); err != nil {
		return RotationReport{}, err
	}
	dropin := fmt.Sprintf("[Service]\nReadWritePaths=-%s\n", filepath.Join(nginxDir, "logs"))
	if err := writeFileAtomic(dropinPath, []byte(dropin), 0o644); err != nil {
		return RotationReport{}, err
	}
	if serviceManaged(paths.Root) {
		// Bash ignores a daemon-reload failure: the drop-in still applies on the
		// next boot, so a non-systemd host keeps working.
		_ = serviceCommand(ctx, "daemon-reload")
	}
	rep.Enabled = true
	rep.ConfigPath = confPath
	rep.DropinPath = dropinPath
	return rep, nil
}

// writeLogrotateConfig validates the generated block with `logrotate --debug`
// before replacing the live file, exactly like Bash.
func writeLogrotateConfig(ctx context.Context, bin, confPath, conf string) error {
	dir := filepath.Dir(confPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".xray_log_cleanup.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(conf); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := checkLogrotate(ctx, bin, tmpName); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, confPath)
}

// DisableLogRotation removes the managed config and drop-in. It never touches
// other logrotate files, and it leaves the timer enabled just like Bash.
func DisableLogRotation(ctx context.Context, spec LogsSpec) (RotationReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return RotationReport{}, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return RotationReport{}, err
	}
	rep := RotationReport{Warnings: []string{}, Removed: []string{}}
	for _, rel := range []string{logrotateConfRel, logrotateDropinRel} {
		path, err := paths.Join(rel, false)
		if err != nil {
			continue
		}
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return RotationReport{}, err
		}
		rep.Removed = append(rep.Removed, path)
	}
	if len(rep.Removed) > 0 && serviceManaged(paths.Root) {
		_ = serviceCommand(ctx, "daemon-reload")
	}
	return rep, nil
}

// logrotateConfig mirrors the Bash block field for field, with the sandbox root
// prefixed so a test tree can be rotated without touching the host.
func logrotateConfig(logDir, nginxDir, workerUser, workerGroup string) string {
	return fmt.Sprintf(`%[1]s/*.log {
    weekly
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
%[2]s/logs/*.log {
    weekly
    rotate 3
    compress
    missingok
    notifempty
    create 640 %[3]s %[4]s
    sharedscripts
    postrotate
        if pgrep -x nginx >/dev/null 2>&1; then
            %[2]s/sbin/nginx -s reopen -c %[2]s/conf/nginx.conf
        fi
    endscript
}
`, logDir, nginxDir, workerUser, workerGroup)
}
