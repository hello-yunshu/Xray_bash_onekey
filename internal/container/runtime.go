// Package container owns the systemd-free runtime used by the product image.
//
// The image keeps the Bash manager and fake-systemctl for compatibility, but
// service activation must not pretend a container has systemd. When systemd is
// genuinely available the package delegates to it; otherwise it starts the
// managed binaries as direct children, records their pids and appends their
// output to one log file.
package container

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// Mode is how this process activates the managed services.
type Mode string

const (
	ModeSystemd Mode = "systemd"
	ModeDirect  Mode = "direct"

	pidDirRel  = "run/idleleo"
	logDirRel  = "var/log/idleleo"
	logFileRel = "var/log/idleleo/container.log"
)

// ServiceState is the read-only view of one managed process.
type ServiceState struct {
	Required bool   `json:"required"`
	Config   bool   `json:"config"`
	PidFile  string `json:"pidFile"`
	Pid      int    `json:"pid"`
	Alive    bool   `json:"alive"`
	Source   string `json:"source"`
}

// StatusReport is the JSON contract for `container status`.
type StatusReport struct {
	SchemaVersion int          `json:"schemaVersion"`
	Root          string       `json:"root"`
	InContainer   bool         `json:"inContainer"`
	Mode          Mode         `json:"mode"`
	Xray          ServiceState `json:"xray"`
	Nginx         ServiceState `json:"nginx"`
	Warnings      []string     `json:"warnings,omitempty"`
}

// Spec controls an activation or shutdown.
type Spec struct {
	Root                 string
	AllowContainerWrites bool
	DryRun               bool
}

// UpReport is the JSON contract for `container up`.
type UpReport struct {
	SchemaVersion int            `json:"schemaVersion"`
	Root          string         `json:"root"`
	Mode          Mode           `json:"mode"`
	DryRun        bool           `json:"dryRun"`
	Started       []string       `json:"started"`
	Skipped       []string       `json:"skipped"`
	Pids          map[string]int `json:"pids,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`
}

// DownReport is the JSON contract for `container down`.
type DownReport struct {
	SchemaVersion int      `json:"schemaVersion"`
	Root          string   `json:"root"`
	Mode          Mode     `json:"mode"`
	Stopped       []string `json:"stopped"`
	Warnings      []string `json:"warnings,omitempty"`
}

type service struct {
	name   string
	binary string
	config string
}

func (s service) args() []string {
	if s.name == "nginx" {
		return []string{"-c", s.config, "-g", "daemon off;"}
	}
	return []string{"run", "-config", s.config}
}

// DetectMode prefers real systemd and otherwise reports direct process mode.
func DetectMode() Mode {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		if _, err := host.ResolveBinary("systemctl"); err == nil {
			return ModeSystemd
		}
	}
	return ModeDirect
}

func rootJoin(root, rel string) string { return filepath.Join(root, rel) }

func pidFile(root, name string) string {
	return rootJoin(root, filepath.Join(pidDirRel, "container-"+name+".pid"))
}

func binaryPath(root, name string) string {
	if name == "nginx" {
		return rootJoin(root, "usr/local/nginx/sbin/nginx")
	}
	return rootJoin(root, "usr/local/bin/xray")
}

func services(root string, m store.Metadata, metaErr error) ([]service, []string) {
	var warnings []string
	xray := service{
		name:   "xray",
		binary: rootJoin(root, "usr/local/bin/xray"),
		config: rootJoin(root, "etc/idleleo/conf/xray/config.json"),
	}
	nginx := service{
		name:   "nginx",
		binary: rootJoin(root, "usr/local/nginx/sbin/nginx"),
		config: rootJoin(root, "usr/local/nginx/conf/nginx.conf"),
	}
	if metaErr != nil {
		warnings = append(warnings, "metadata unreadable: "+metaErr.Error())
	}
	out := []service{xray}
	if metaErr == nil && m.TLS != "None" {
		out = append(out, nginx)
	} else if metaErr != nil {
		// Without metadata the safe assumption is the TLS front may exist.
		out = append(out, nginx)
	}
	return out, warnings
}

// Status never writes, creates, or starts anything.
func Status(root string) (StatusReport, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return StatusReport{}, &change.UsageError{Msg: err.Error()}
	}
	report := StatusReport{
		SchemaVersion: 1,
		Root:          paths.Root,
		InContainer:   host.InContainer(),
		Mode:          DetectMode(),
	}
	meta, _, metaErr := store.LoadMetadata(paths)
	if metaErr != nil {
		report.Warnings = append(report.Warnings, metaErr.Error())
	}
	list, warnings := services(paths.Root, meta, metaErr)
	report.Warnings = append(report.Warnings, warnings...)
	for _, svc := range list {
		st := ServiceState{
			Required: svc.name == "xray" || (metaErr == nil && meta.TLS != "None"),
			PidFile:  pidFile(paths.Root, svc.name),
			Source:   string(report.Mode),
		}
		st.Config = regular(svc.config) && executable(svc.binary)
		st.Pid = readPid(st.PidFile)
		if report.Mode == ModeSystemd {
			st.Alive = systemdActive(svc.name)
		} else {
			st.Alive = st.Pid > 0 && alive(st.Pid)
		}
		if st.Pid > 0 && !st.Alive {
			report.Warnings = append(report.Warnings, svc.name+" pid file is stale")
		}
		if svc.name == "xray" {
			report.Xray = st
		} else {
			report.Nginx = st
		}
	}
	return report, nil
}

// Up activates the managed services. It is idempotent: an alive pid that owns
// this root is left alone, and a dry run performs no writes or starts.
func Up(ctx context.Context, spec Spec) (UpReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return UpReport{}, &change.UsageError{Msg: err.Error()}
	}
	if err := host.RequireSystemWrite(paths.Root, spec.AllowContainerWrites); err != nil {
		return UpReport{}, &change.UsageError{Msg: err.Error()}
	}
	meta, _, metaErr := store.LoadMetadata(paths)
	if metaErr != nil {
		return UpReport{}, metaErr
	}
	list, warnings := services(paths.Root, meta, metaErr)
	report := UpReport{
		SchemaVersion: 1,
		Root:          paths.Root,
		Mode:          DetectMode(),
		DryRun:        spec.DryRun,
		Started:       []string{},
		Skipped:       []string{},
		Pids:          map[string]int{},
		Warnings:      append([]string{}, warnings...),
	}
	if spec.DryRun {
		for _, svc := range list {
			if regular(svc.config) && executable(svc.binary) {
				report.Started = append(report.Started, svc.name)
			} else {
				report.Skipped = append(report.Skipped, svc.name)
			}
		}
		return report, nil
	}
	if report.Mode == ModeSystemd {
		return upSystemd(ctx, report, list)
	}
	return upDirect(ctx, report, list)
}

func upSystemd(ctx context.Context, report UpReport, list []service) (UpReport, error) {
	for _, svc := range list {
		if !regular(svc.config) || !executable(svc.binary) {
			report.Skipped = append(report.Skipped, svc.name)
			continue
		}
		res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"start", svc.name}})
		if err != nil {
			return report, err
		}
		if res.ExitCode != 0 {
			return report, fmt.Errorf("systemctl start %s failed: %s", svc.name, strings.TrimSpace(res.Stderr+res.Stdout))
		}
		report.Started = append(report.Started, svc.name)
	}
	return report, nil
}

func upDirect(ctx context.Context, report UpReport, list []service) (UpReport, error) {
	logPath := rootJoin(report.Root, logFileRel)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return report, &change.IOError{Msg: "create log directory: " + err.Error()}
	}
	if err := os.MkdirAll(rootJoin(report.Root, pidDirRel), 0o755); err != nil {
		return report, &change.IOError{Msg: "create pid directory: " + err.Error()}
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return report, &change.IOError{Msg: "open container log: " + err.Error()}
	}
	defer logFile.Close()
	for _, svc := range list {
		if !regular(svc.config) || !executable(svc.binary) {
			report.Skipped = append(report.Skipped, svc.name)
			report.Warnings = append(report.Warnings, svc.name+" is not configured")
			continue
		}
		pf := pidFile(report.Root, svc.name)
		if pid := readPid(pf); pid > 0 && alive(pid) && ownedBy(pid, svc.binary) {
			report.Skipped = append(report.Skipped, svc.name)
			report.Pids[svc.name] = pid
			continue
		}
		cmd := exec.Command(svc.binary, svc.args()...)
		cmd.Dir = report.Root
		cmd.Env = append([]string{
			"PATH=" + host.FixedPATH,
			"HOME=/",
			"LANG=C.UTF-8",
			"LC_ALL=C.UTF-8",
			"XRAY_LOCATION_ASSET=" + rootJoin(report.Root, "etc/idleleo/share/xray"),
		}, "IDLELEO_CONTAINER=1")
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		if err := cmd.Start(); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s start failed: %s", svc.name, err))
			continue
		}
		pid := cmd.Process.Pid
		if err := writePid(pf, pid); err != nil {
			_ = cmd.Process.Kill()
			return report, &change.IOError{Msg: "write pid file: " + err.Error()}
		}
		time.Sleep(120 * time.Millisecond)
		if !alive(pid) {
			_ = os.Remove(pf)
			report.Warnings = append(report.Warnings, svc.name+" exited during startup; see "+logPath)
			continue
		}
		report.Started = append(report.Started, svc.name)
		report.Pids[svc.name] = pid
		// Reap the child if it exits while this manager is still alive; when the
		// manager exits first the normal init process takes over reaping.
		go func(c *exec.Cmd) { _ = c.Wait() }(cmd)
	}
	if len(report.Started) == 0 && len(report.Pids) == 0 {
		return report, errors.New("no managed service started")
	}
	return report, nil
}

// Down is idempotent: stale or missing pid files are cleaned without error.
func Down(ctx context.Context, spec Spec) (DownReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return DownReport{}, &change.UsageError{Msg: err.Error()}
	}
	if err := host.RequireSystemWrite(paths.Root, spec.AllowContainerWrites); err != nil {
		return DownReport{}, &change.UsageError{Msg: err.Error()}
	}
	report := DownReport{
		SchemaVersion: 1,
		Root:          paths.Root,
		Mode:          DetectMode(),
		Stopped:       []string{},
	}
	if report.Mode == ModeSystemd {
		for _, name := range []string{"xray", "nginx"} {
			res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: []string{"stop", name}})
			if err != nil {
				return report, err
			}
			if res.ExitCode == 0 {
				report.Stopped = append(report.Stopped, name)
			}
			_ = os.Remove(pidFile(paths.Root, name))
		}
		return report, nil
	}
	for _, name := range []string{"xray", "nginx"} {
		pf := pidFile(paths.Root, name)
		pid := readPid(pf)
		if pid > 0 && alive(pid) && ownedBy(pid, binaryPath(paths.Root, name)) {
			if err := terminate(pid); err != nil {
				report.Warnings = append(report.Warnings, fmt.Sprintf("%s pid %d: %s", name, pid, err))
			} else {
				report.Stopped = append(report.Stopped, name)
			}
		}
		_ = os.Remove(pf)
	}
	return report, nil
}

func terminate(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		if !alive(pid) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("process did not exit after SIGKILL")
}

func systemdActive(name string) bool {
	res, err := host.Run(context.Background(), host.ExecSpec{Path: "systemctl", Args: []string{"is-active", name}})
	if err != nil {
		return false
	}
	return strings.TrimSpace(res.Stdout) == "active"
}

func alive(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err == nil {
		// A zombie has exited; signal 0 would still succeed until it is reaped.
		fields := strings.Fields(string(b))
		if len(fields) > 2 && fields[2] == "Z" {
			return false
		}
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// ownedBy reports whether pid runs the managed binary. /proc is authoritative on
// Linux; elsewhere (a developer machine running the unit tests) ps is asked, and
// a process that cannot be inspected counts as foreign so a stale pid file never
// signals an unrelated process.
func ownedBy(pid int, binary string) bool {
	if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")); err == nil {
		return strings.Contains(strings.ReplaceAll(string(b), "\x00", " "), binary)
	}
	res, err := host.Run(context.Background(), host.ExecSpec{
		Path: "ps", Args: []string{"-o", "command=", "-p", strconv.Itoa(pid)},
	})
	if err != nil || res.ExitCode != 0 {
		return false
	}
	return strings.Contains(res.Stdout, binary)
}

func readPid(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

func writePid(path string, pid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func regular(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func executable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}
