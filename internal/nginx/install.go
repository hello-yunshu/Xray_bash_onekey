package nginx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// Managed layout. These paths are fixed so a Go deployment and a Bash
// deployment share the same Nginx tree and fragments.
const (
	InstallDirRel = "usr/local/nginx"
	ConfDirRel    = "etc/idleleo/conf/nginx"
	CertDirRel    = "etc/idleleo/cert"
	UnitRel       = "etc/systemd/system/nginx.service"
	MetadataRel   = "etc/idleleo/v1/nginx.json"

	WorkerUser  = "idleleo-nginx"
	WorkerGroup = "idleleo-nginx"
	ServiceName = "nginx"

	// MainConf marks the project fragment included by the managed main config.
	MainConf = "00-xray.conf"

	MetadataSchemaVersion = 1
)

// Metadata records the installed managed Nginx build. It never stores secrets.
type Metadata struct {
	SchemaVersion int      `json:"schemaVersion"`
	Build         string   `json:"build"`
	Version       Versions `json:"versions"`
	InstallDir    string   `json:"installDir"`
	BinarySHA256  string   `json:"binarySha256"`
	InstalledAt   string   `json:"installedAt"`
}

// InstallSpec is one managed Nginx installation request.
type InstallSpec struct {
	Root      string
	Artifact  Artifact
	Stream    bool
	LocalIP   string
	NoService bool
}

// InstallReport is the machine-readable result.
type InstallReport struct {
	Build            string   `json:"build"`
	Version          Versions `json:"versions"`
	BinaryPath       string   `json:"binaryPath"`
	BinarySHA256     string   `json:"binarySha256"`
	ConfDir          string   `json:"confDir"`
	UnitPath         string   `json:"unitPath"`
	MetadataPath     string   `json:"metadataPath"`
	Verified         bool     `json:"verified"`
	AlreadyInstalled bool     `json:"alreadyInstalled"`
	ServiceEnabled   string   `json:"serviceEnabled,omitempty"`
	ServiceActive    string   `json:"serviceActive,omitempty"`
	Warnings         []string `json:"warnings"`
}

// FinalizeSpec applies the last step after the Xray fragments were written.
type FinalizeSpec struct {
	Root      string
	NoService bool
}

// UninstallSpec is one managed Nginx removal request.
type UninstallSpec struct {
	Root string
	// KeepConf preserves the project fragment directory. The default is to
	// remove it so a reinstall starts from a clean tree (Bash parity).
	KeepConf  bool
	NoService bool
}

// UninstallReport lists what was removed.
type UninstallReport struct {
	Installed       bool     `json:"installed"`
	Removed         []string `json:"removed"`
	ServiceStopped  bool     `json:"serviceStopped"`
	ServiceDisabled bool     `json:"serviceDisabled"`
	ConfigPreserved bool     `json:"configPreserved"`
	Warnings        []string `json:"warnings"`
}

// ConfigOptions controls the managed main-config rewrite.
type ConfigOptions struct {
	User    string
	Group   string
	LocalIP string
	// Stream includes MainConf at the top level instead of the *.conf glob
	// inside the http block. Reality front modes render a stream{} block.
	Stream bool
}

var (
	userLine    = regexp.MustCompile(`^\s*#?\s*user\s+`)
	workerProcs = regexp.MustCompile(`^(\s*)worker_processes\s+1\s*;\s*$`)
	workerConns = regexp.MustCompile(`^(\s*)worker_connections\s+1024\s*;\s*$`)
	includeMain = regexp.MustCompile(`^\s*include\s+/etc/idleleo/conf/nginx/` + regexp.QuoteMeta(MainConf) + `\s*;\s*$`)
	includeGlob = regexp.MustCompile(`^\s*include\s+/etc/idleleo/conf/nginx/\*\.conf\s*;\s*$`)
	errorPage   = regexp.MustCompile(`^\s*error_page\b.*\b504\b`)
	httpOpen    = regexp.MustCompile(`^\s*http\s*\{\s*$`)
)

// runService and queryService are seams for the service transaction. Production
// uses host.Run.
var runService = func(ctx context.Context, args ...string) error {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: args, Timeout: 15 * time.Second})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl %s failed (exit %d): %s", strings.Join(args, " "), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

var queryService = func(ctx context.Context, args ...string) string {
	res, err := host.Run(ctx, host.ExecSpec{Path: "systemctl", Args: args, Timeout: 10 * time.Second})
	if err != nil {
		return "unknown"
	}
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		return fmt.Sprintf("exit-%d", res.ExitCode)
	}
	return out
}

// runConfigTest runs the installed binary's syntax check. It is a variable so
// sandbox tests can inject a fake runner without a Linux binary.
var runConfigTest = func(ctx context.Context, bin, prefix, conf string) error {
	res, err := host.Run(ctx, host.ExecSpec{
		Path: bin,
		Args: []string{"-t", "-p", strings.TrimRight(prefix, "/") + "/", "-c", conf},
		// Nginx writes to logs on -t; allow a little more than the default.
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("nginx -t rejected the configuration (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// runVersion captures `nginx -v` for the report. Failure is not fatal: the
// authoritative version assertion happens in the container harness.
var runVersion = func(ctx context.Context, bin string) string {
	res, err := host.Run(ctx, host.ExecSpec{Path: bin, Args: []string{"-v"}, Timeout: host.DefaultTimeout})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(res.Stdout + res.Stderr)
}

// runAsWorker executes a command as the unprivileged worker account. The Bash
// harness proves certificate readability with `runuser -u idleleo-nginx --
// test -r ...`; the same assertion runs here after permissions are applied.
var runAsWorker = func(ctx context.Context, args ...string) error {
	res, err := host.Run(ctx, host.ExecSpec{
		Path:    "runuser",
		Args:    append([]string{"-u", WorkerUser, "--"}, args...),
		Timeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("runuser %s failed (exit %d): %s", WorkerUser, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// Install unpacks the verified artifact into a staging directory on the same
// filesystem, backs up the current tree, swaps it atomically, rewrites the main
// configuration, applies layered permissions, validates with nginx -t, writes
// the unit, and enables/starts the service. Nothing is mutated before the
// artifact is verified.
//
// The caller must hold the update lock; Install never acquires it.
func Install(ctx context.Context, spec InstallSpec) (InstallReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return InstallReport{}, err
	}
	if spec.Artifact.Build == "" || len(spec.Artifact.Data) == 0 {
		return InstallReport{}, errors.New("managed Nginx install requires a resolved artifact")
	}
	installDir, err := dirAt(paths, InstallDirRel)
	if err != nil {
		return InstallReport{}, err
	}
	confDir, err := dirAt(paths, ConfDirRel)
	if err != nil {
		return InstallReport{}, err
	}
	unitPath, err := paths.Join(UnitRel, true)
	if err != nil {
		return InstallReport{}, err
	}
	metaPath, err := paths.Join(MetadataRel, true)
	if err != nil {
		return InstallReport{}, err
	}

	rep := InstallReport{
		Build: spec.Artifact.Build, Version: spec.Artifact.Version,
		BinaryPath: filepath.Join(installDir, "sbin", "nginx"),
		ConfDir:    confDir, UnitPath: unitPath, MetadataPath: metaPath,
		Warnings: []string{},
	}

	if meta, ok := installedSameBuild(metaPath, rep.BinaryPath, spec.Artifact.Build); ok {
		rep.AlreadyInstalled = true
		rep.BinarySHA256 = meta.BinarySHA256
		// A reinstall of the same build must not churn the live tree, but an
		// operator edit or a permission reset can leave the managed surface
		// broken. Repair drift, then only restart when something changed.
		drifted, err := repairManagedState(ctx, paths, installDir, spec, &rep)
		if err != nil {
			return rep, err
		}
		if err := ensureService(ctx, paths.Root, spec.NoService, drifted, &rep); err != nil {
			return rep, err
		}
		return rep, nil
	}

	// Snapshot the files outside the install tree that this transaction may
	// change, so a failure returns the host to exactly the prior state.
	snapshots, err := captureFiles([]string{filepath.Join(confDir, "nginx.default"), unitPath, metaPath})
	if err != nil {
		return rep, err
	}
	svc := captureService(ctx, paths.Root, spec.NoService)

	parent := filepath.Dir(installDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return rep, err
	}
	staging, err := os.MkdirTemp(parent, ".nginx.new.")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(staging)

	swap := swapState{installDir: installDir}
	fail := func(cause error) (InstallReport, error) {
		if rbErr := restore(ctx, svc, snapshots, &swap); rbErr != nil {
			return rep, fmt.Errorf("%w; Nginx rollback failed: %v", cause, rbErr)
		}
		return rep, fmt.Errorf("%w; Nginx installation rolled back to the previous state", cause)
	}

	if err := Extract(spec.Artifact.Data, staging); err != nil {
		return rep, err
	}
	stagedBin := filepath.Join(staging, "nginx", "sbin", "nginx")
	if err := VerifyBinary(stagedBin, spec.Artifact.Asset.BinarySHA256, spec.Artifact.Asset.Arch); err != nil {
		return fail(err)
	}
	sum, err := fileSHA256(stagedBin)
	if err != nil {
		return fail(err)
	}

	if _, statErr := os.Lstat(installDir); statErr == nil {
		backup := fmt.Sprintf("%s.pre-install.%d", installDir, time.Now().UnixNano())
		if err := os.Rename(installDir, backup); err != nil {
			return fail(fmt.Errorf("backup existing Nginx tree: %w", err))
		}
		swap.backupDir = backup
	}
	if err := os.Rename(filepath.Join(staging, "nginx"), installDir); err != nil {
		if swap.backupDir != "" {
			_ = os.Rename(swap.backupDir, installDir)
			swap.backupDir = ""
		}
		return fail(fmt.Errorf("activate staged Nginx tree: %w", err))
	}
	swap.swapped = true
	_ = os.RemoveAll(staging)

	if err := os.MkdirAll(confDir, 0o755); err != nil {
		return fail(err)
	}
	rawMain, err := os.ReadFile(filepath.Join(installDir, "conf", "nginx.conf"))
	if err != nil {
		return fail(err)
	}
	if err := writeAtomic(filepath.Join(confDir, "nginx.default"), rawMain, 0o644); err != nil {
		return fail(err)
	}
	if spec.Stream {
		// Bash touches the include targets so nginx -t passes before the
		// fragments are written by the Xray step. 03-isolate.conf is included
		// from the http block, so it needs a placeholder too.
		for _, name := range []string{MainConf, "03-isolate.conf"} {
			placeholder := filepath.Join(confDir, name)
			if _, statErr := os.Lstat(placeholder); os.IsNotExist(statErr) {
				if err := writeAtomic(placeholder, nil, 0o644); err != nil {
					return fail(err)
				}
			}
		}
	}
	if paths.Root == "/" {
		if err := ensureWorker(ctx); err != nil {
			return fail(err)
		}
	}
	opts := ConfigOptions{User: WorkerUser, Group: WorkerGroup, LocalIP: spec.LocalIP, Stream: spec.Stream}
	rewritten, warnings := RewriteMainConfigWithWarnings(string(rawMain), opts)
	rep.Warnings = append(rep.Warnings, warnings...)
	if err := writeAtomic(filepath.Join(installDir, "conf", "nginx.conf"), []byte(rewritten), 0o644); err != nil {
		return fail(err)
	}
	permWarnings, err := ApplyLayeredPermissions(paths.Root)
	rep.Warnings = append(rep.Warnings, permWarnings...)
	if err != nil {
		return fail(err)
	}
	if err := VerifyLayeredPermissions(ctx, paths.Root); err != nil {
		return fail(err)
	}
	if err := runConfigTest(ctx, rep.BinaryPath, installDir, filepath.Join(installDir, "conf", "nginx.conf")); err != nil {
		return fail(err)
	}
	rep.Verified = true
	rep.BinarySHA256 = sum

	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return fail(err)
	}
	if err := writeAtomic(unitPath, []byte(UnitContent(installDir)), 0o644); err != nil {
		return fail(err)
	}
	meta := Metadata{
		SchemaVersion: MetadataSchemaVersion, Build: spec.Artifact.Build, Version: spec.Artifact.Version,
		InstallDir: installDir, BinarySHA256: sum, InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fail(err)
	}
	metaBytes = append(metaBytes, '\n')
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		return fail(err)
	}
	if err := writeAtomic(metaPath, metaBytes, 0o644); err != nil {
		return fail(err)
	}
	if err := ensureService(ctx, paths.Root, spec.NoService, true, &rep); err != nil {
		return fail(err)
	}
	if backupDir := swap.backupDir; backupDir != "" {
		if err := os.RemoveAll(backupDir); err != nil {
			rep.Warnings = append(rep.Warnings, "managed nginx: previous tree backup kept at "+backupDir+": "+err.Error())
		}
	}
	return rep, nil
}

// Finalize applies permissions to the newly written Xray fragments, revalidates
// the managed configuration and reloads the service.
func Finalize(ctx context.Context, spec FinalizeSpec) error {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return err
	}
	installDir, err := dirAt(paths, InstallDirRel)
	if err != nil {
		return err
	}
	if _, err := ApplyLayeredPermissions(spec.Root); err != nil {
		return err
	}
	if err := VerifyLayeredPermissions(ctx, spec.Root); err != nil {
		return err
	}
	bin := filepath.Join(installDir, "sbin", "nginx")
	if err := runConfigTest(ctx, bin, installDir, filepath.Join(installDir, "conf", "nginx.conf")); err != nil {
		return err
	}
	if spec.NoService || spec.Root != "/" {
		return nil
	}
	if queryService(ctx, "is-active", ServiceName) == "active" {
		return runService(ctx, "reload", ServiceName)
	}
	return runService(ctx, "start", ServiceName)
}

// Uninstall stops and removes the managed Nginx tree. The project fragment
// directory is preserved unless purge is requested so a reinstall can adopt it.
func Uninstall(ctx context.Context, spec UninstallSpec) (UninstallReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return UninstallReport{}, err
	}
	rep := UninstallReport{Removed: []string{}, Warnings: []string{}}
	metaPath, _ := paths.Join(MetadataRel, false)
	installDir, _ := paths.Join(InstallDirRel, false)
	if _, statErr := os.Lstat(metaPath); statErr != nil {
		if _, dirErr := os.Lstat(installDir); dirErr != nil {
			return rep, nil
		}
	}
	rep.Installed = true
	unitPath, _ := paths.Join(UnitRel, false)
	if paths.Root == "/" && !spec.NoService {
		if _, statErr := os.Lstat(unitPath); statErr == nil {
			if err := runService(ctx, "stop", ServiceName); err != nil {
				// Deleting the tree under a live process leaves an
				// unmanageable runtime; refuse instead of pretending success.
				if queryService(ctx, "is-active", ServiceName) == "active" {
					return rep, fmt.Errorf("stop nginx.service failed: %w", err)
				}
			} else {
				rep.ServiceStopped = true
			}
			if err := runService(ctx, "disable", ServiceName); err == nil {
				rep.ServiceDisabled = true
			}
		}
	}
	confDir, _ := paths.Join(ConfDirRel, false)
	targets := []struct {
		rel  string
		path string
		dir  bool
	}{
		{UnitRel, unitPath, false},
		{InstallDirRel, installDir, true},
		{MetadataRel, metaPath, false},
	}
	if spec.KeepConf {
		if _, statErr := os.Lstat(confDir); statErr == nil {
			rep.ConfigPreserved = true
		}
	} else {
		targets = append(targets, struct {
			rel  string
			path string
			dir  bool
		}{ConfDirRel, confDir, true})
	}
	var cleanupErr error
	for _, t := range targets {
		if t.path == "" {
			continue
		}
		if _, statErr := os.Lstat(t.path); statErr != nil {
			continue
		}
		var rmErr error
		if t.dir {
			rmErr = os.RemoveAll(t.path)
		} else {
			rmErr = os.Remove(t.path)
		}
		if rmErr != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("remove %s: %v", t.rel, rmErr))
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove %s: %w", t.rel, rmErr))
			continue
		}
		rep.Removed = append(rep.Removed, t.rel)
	}
	if paths.Root == "/" && !spec.NoService && len(rep.Removed) > 0 {
		if err := runService(ctx, "daemon-reload"); err != nil {
			rep.Warnings = append(rep.Warnings, err.Error())
		}
	}
	return rep, cleanupErr
}

// RewriteMainConfig applies the Bash modify_nginx_origin_conf transformations:
// worker identity, process/connection sizing, a single project include, and
// server_tokens/local-IP hardening. It keeps the historical string-only
// signature; callers that surface warnings use RewriteMainConfigWithWarnings.
func RewriteMainConfig(conf string, opts ConfigOptions) string {
	out, _ := RewriteMainConfigWithWarnings(conf, opts)
	return out
}

// RewriteMainConfigWithWarnings is RewriteMainConfig plus diagnostics for
// anchors it could not find. A missing hardening anchor must never be silent.
func RewriteMainConfigWithWarnings(conf string, opts ConfigOptions) (string, []string) {
	if opts.User == "" {
		opts.User = WorkerUser
	}
	if opts.Group == "" {
		opts.Group = WorkerGroup
	}
	warnings := []string{}
	hadTrailingNewline := strings.HasSuffix(conf, "\n")
	lines := strings.Split(strings.TrimSuffix(conf, "\n"), "\n")
	out := make([]string, 0, len(lines)+8)
	userDone := false
	for _, line := range lines {
		if userLine.MatchString(line) {
			if !userDone {
				out = append(out, "user "+opts.User+" "+opts.Group+";")
				userDone = true
			}
			continue
		}
		if includeMain.MatchString(line) || includeGlob.MatchString(line) {
			continue
		}
		if m := workerProcs.FindStringSubmatch(line); m != nil {
			out = append(out, m[1]+"worker_processes  auto;")
			continue
		}
		if m := workerConns.FindStringSubmatch(line); m != nil {
			out = append(out, m[1]+"worker_connections  4096;")
			continue
		}
		out = append(out, line)
	}
	if !userDone {
		out = append([]string{"user " + opts.User + " " + opts.Group + ";"}, out...)
	}

	// server_tokens off immediately after the http block opener.
	if !containsLine(out, "server_tokens off;") {
		inserted := false
		for i, line := range out {
			if httpOpen.MatchString(line) {
				out = append(out[:i+1], append([]string{"    server_tokens off;"}, out[i+1:]...)...)
				inserted = true
				break
			}
		}
		if !inserted {
			warnings = append(warnings, "nginx main config has no http { block; server_tokens off not applied")
		}
	}
	// Refuse requests addressed to the host's own IP (Bash parity).
	if opts.LocalIP != "" && !containsLine(out, "if ($host = '"+opts.LocalIP+"') {") {
		inserted := false
		for i, line := range out {
			if errorPage.MatchString(line) {
				block := []string{
					"\t\tif ($host = '" + opts.LocalIP + "') {",
					"\t\t\treturn 403;",
					"\t\t}",
				}
				out = append(out[:i], append(block, out[i:]...)...)
				inserted = true
				break
			}
		}
		if !inserted {
			warnings = append(warnings, "nginx main config has no error_page ... 504 anchor; local-IP 403 guard not applied")
		}
	}

	if opts.Stream {
		out = append(out, "include /etc/idleleo/conf/nginx/"+MainConf+";")
		// The isolate site is an http{} server block, so it cannot be reached
		// through the stream include. Bash inserts this include explicitly.
		if !containsLine(out, "include /etc/idleleo/conf/nginx/03-isolate.conf;") {
			inserted := false
			for i, line := range out {
				if httpOpen.MatchString(line) {
					out = append(out[:i+1], append([]string{"    include /etc/idleleo/conf/nginx/03-isolate.conf;"}, out[i+1:]...)...)
					inserted = true
					break
				}
			}
			if !inserted {
				warnings = append(warnings, "nginx main config has no http { block; 03-isolate.conf not included")
			}
		}
	} else {
		// Insert the http include before the final closing brace.
		inserted := false
		for i := len(out) - 1; i >= 0; i-- {
			if strings.TrimSpace(out[i]) == "}" {
				out = append(out[:i], append([]string{"    include /etc/idleleo/conf/nginx/*.conf;"}, out[i:]...)...)
				inserted = true
				break
			}
		}
		if !inserted {
			warnings = append(warnings, "nginx main config has no closing brace; *.conf include not applied")
		}
	}
	joined := strings.Join(out, "\n")
	if hadTrailingNewline {
		joined += "\n"
	}
	return joined, warnings
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// UnitContent renders the systemd unit; it matches the Bash unit so a Go and
// Bash deployment are interchangeable.
func UnitContent(installDir string) string {
	return fmt.Sprintf(`[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=%[1]s/logs/nginx.pid
ExecStartPre=%[1]s/sbin/nginx -t
ExecStart=%[1]s/sbin/nginx -c %[1]s/conf/nginx.conf
ExecReload=%[1]s/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, installDir)
}

// ApplyLayeredPermissions enforces the documented ownership model. It skips
// chown for a sandbox root because the test process is not root; mode changes
// still apply so the model is exercised. Symlinks are skipped with a warning:
// the Bash implementation uses `find -type f`, so an unrelated symlink must not
// abort an otherwise valid install.
func ApplyLayeredPermissions(root string) ([]string, error) {
	paths, err := host.NewPaths(root)
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	installDir, err := dirAt(paths, InstallDirRel)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(installDir); err != nil {
		if os.IsNotExist(err) {
			return warnings, nil
		}
		return nil, err
	}
	confDir, err := dirAt(paths, ConfDirRel)
	if err != nil {
		return nil, err
	}
	if warning := certDirWarning(paths); warning != "" {
		warnings = append(warnings, warning)
	}
	certDir, _ := paths.Join(CertDirRel, false)
	chown := paths.Root == "/"
	uid, gid := workerIDs()
	if chown && (uid < 0 || gid < 0) {
		return nil, fmt.Errorf("worker account %s is not resolvable", WorkerUser)
	}

	if err := chmodChown(installDir, 0o755, 0, 0, chown); err != nil {
		return nil, err
	}
	if err := chmodChown(filepath.Join(installDir, "sbin", "nginx"), 0o755, 0, 0, chown); err != nil {
		return nil, err
	}
	for _, name := range []string{"conf", "html"} {
		dir := filepath.Join(installDir, name)
		if _, err := os.Lstat(dir); err != nil {
			continue
		}
		if err := chmodChown(dir, 0o750, 0, gid, chown); err != nil {
			return nil, err
		}
		if err := walkFiles(dir, 0o640, 0o750, 0, gid, chown, &warnings); err != nil {
			return nil, err
		}
	}
	if _, err := os.Lstat(confDir); err == nil {
		if err := chmodChown(confDir, 0o750, 0, gid, chown); err != nil {
			return nil, err
		}
		if err := walkFiles(confDir, 0o640, 0o750, 0, gid, chown, &warnings); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"logs", "client_body_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"} {
		dir := filepath.Join(installDir, name)
		if _, err := os.Lstat(dir); err != nil {
			continue
		}
		if err := chmodChown(dir, 0o750, uid, gid, chown); err != nil {
			return nil, err
		}
		if err := walkFiles(dir, 0o640, 0o750, uid, gid, chown, &warnings); err != nil {
			return nil, err
		}
	}
	if certDir != "" {
		if _, err := os.Lstat(certDir); err == nil {
			if err := chmodChown(certDir, 0o750, 0, gid, chown); err != nil {
				return nil, err
			}
			if err := walkFiles(certDir, 0o640, 0o750, 0, gid, chown, &warnings); err != nil {
				return nil, err
			}
		}
	}
	return warnings, nil
}

func walkFiles(dir string, fileMode, dirMode, uid, gid int, chown bool, warnings *[]string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			*warnings = append(*warnings, "managed nginx: skipped symlink "+path)
			return nil
		}
		if d.IsDir() {
			return chmodChown(path, dirMode, uid, gid, chown)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("refusing to chmod non-regular %s", path)
		}
		return chmodChown(path, fileMode, uid, gid, chown)
	})
}

// certDirWarning reports a managed certificate directory that host.Paths
// refuses to resolve, for example an operator symlink to a certbot live/ tree.
// Callers surface it as a warning instead of skipping the directory silently.
func certDirWarning(paths host.Paths) string {
	if _, err := paths.Join(CertDirRel, false); err != nil && !os.IsNotExist(err) {
		return "managed nginx: certificate directory unavailable: " + err.Error()
	}
	return ""
}

// certDirForWorkerAssertion resolves the certificate directory through a
// symlink so the worker readability assertion still runs. Bash dereferences
// the same path when it proves `idleleo-nginx` can read the key, so skipping
// the check here would hide a broken TLS front.
func certDirForWorkerAssertion(paths host.Paths) string {
	literal := filepath.Join(paths.Root, CertDirRel)
	if _, err := os.Lstat(literal); err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(literal)
	if err != nil {
		return ""
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return ""
	}
	return resolved
}

// VerifyLayeredPermissions asserts the effective ownership and mode of the
// managed tree. Bash fails the install when these drift; without this check a
// partially applied chown/chmod still reports success and the worker may be
// unable to read certificates.
func VerifyLayeredPermissions(ctx context.Context, root string) error {
	paths, err := host.NewPaths(root)
	if err != nil {
		return err
	}
	installDir, err := dirAt(paths, InstallDirRel)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(installDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	confDir, err := dirAt(paths, ConfDirRel)
	if err != nil {
		return err
	}
	certDir, certErr := paths.Join(CertDirRel, false)
	assertDir := certDir
	if certErr != nil {
		// ApplyLayeredPermissions reports an unresolvable certificate
		// directory as a warning, so verification must not hard-fail on the
		// same condition (for example an operator-managed symlink). The
		// readability assertion below still resolves and checks it.
		certDir = ""
		assertDir = certDirForWorkerAssertion(paths)
	}
	chown := paths.Root == "/"
	uid, gid := workerIDs()
	if chown && (uid < 0 || gid < 0) {
		return fmt.Errorf("worker account %s is not resolvable", WorkerUser)
	}

	check := func(path string, want os.FileMode, wantUID, wantGID int) error {
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode().Perm() != want {
			return fmt.Errorf("%s mode %04o, want %04o", path, info.Mode().Perm(), want)
		}
		if chown {
			if gotUID, gotGID, ok := statOwner(info); ok && (gotUID != wantUID || gotGID != wantGID) {
				return fmt.Errorf("%s owner %d:%d, want %d:%d", path, gotUID, gotGID, wantUID, wantGID)
			}
		}
		return nil
	}
	verifyTree := func(dir string, fileMode, dirMode os.FileMode, wantUID, wantGID int) error {
		return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == dir || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			want := fileMode
			if d.IsDir() {
				want = dirMode
			}
			return check(path, want, wantUID, wantGID)
		})
	}

	if err := check(installDir, 0o755, 0, 0); err != nil {
		return err
	}
	if err := check(filepath.Join(installDir, "sbin", "nginx"), 0o755, 0, 0); err != nil {
		return err
	}
	for _, name := range []string{"conf", "html"} {
		dir := filepath.Join(installDir, name)
		if _, statErr := os.Lstat(dir); statErr != nil {
			continue
		}
		if err := check(dir, 0o750, 0, gid); err != nil {
			return err
		}
		if err := verifyTree(dir, 0o640, 0o750, 0, gid); err != nil {
			return err
		}
	}
	if _, statErr := os.Lstat(confDir); statErr == nil {
		if err := check(confDir, 0o750, 0, gid); err != nil {
			return err
		}
		if err := verifyTree(confDir, 0o640, 0o750, 0, gid); err != nil {
			return err
		}
	}
	for _, name := range []string{"logs", "client_body_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"} {
		dir := filepath.Join(installDir, name)
		if _, statErr := os.Lstat(dir); statErr != nil {
			continue
		}
		if err := check(dir, 0o750, uid, gid); err != nil {
			return err
		}
		if err := verifyTree(dir, 0o640, 0o750, uid, gid); err != nil {
			return err
		}
	}
	if certDir != "" {
		if _, statErr := os.Lstat(certDir); statErr == nil {
			if err := check(certDir, 0o750, 0, gid); err != nil {
				return err
			}
			if err := verifyTree(certDir, 0o640, 0o750, 0, gid); err != nil {
				return err
			}
		}
	}
	// The worker must be able to read the TLS key and must not be able to
	// rewrite it. This is the Bash runuser assertion. assertDir follows a
	// symlinked certificate directory so the check is never skipped.
	if chown && assertDir != "" {
		key := filepath.Join(assertDir, "xray.key")
		if _, statErr := os.Lstat(key); statErr == nil {
			if err := runAsWorker(ctx, "test", "-r", key); err != nil {
				return fmt.Errorf("%s cannot read %s: %w", WorkerUser, key, err)
			}
			if err := runAsWorker(ctx, "test", "!", "-w", key); err != nil {
				return fmt.Errorf("%s can write %s: %w", WorkerUser, key, err)
			}
		}
	}
	return nil
}

func statOwner(info os.FileInfo) (int, int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func chmodChown(path string, mode int, uid, gid int, chown bool) error {
	if chown {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, os.FileMode(mode))
}

func workerIDs() (int, int) {
	u, err := user.Lookup(WorkerUser)
	if err != nil {
		return -1, -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, -1
	}
	g, err := user.LookupGroup(WorkerGroup)
	if err != nil {
		return -1, -1
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, -1
	}
	return uid, gid
}

func ensureWorker(ctx context.Context) error {
	if res, err := host.Run(ctx, host.ExecSpec{Path: "id", Args: []string{"-u", WorkerUser}}); err == nil && res.ExitCode == 0 {
		return nil
	}
	if res, err := host.Run(ctx, host.ExecSpec{Path: "groupadd", Args: []string{"--system", WorkerGroup}}); err != nil || res.ExitCode != 0 {
		if res2, err2 := host.Run(ctx, host.ExecSpec{Path: "addgroup", Args: []string{"--system", WorkerGroup}}); err2 != nil || res2.ExitCode != 0 {
			return fmt.Errorf("create %s group failed: %s", WorkerGroup, strings.TrimSpace(res.Stderr))
		}
	}
	if res, err := host.Run(ctx, host.ExecSpec{Path: "useradd", Args: []string{
		"--system", "--gid", WorkerGroup, "--shell", "/usr/sbin/nologin", "--no-create-home", WorkerUser,
	}}); err != nil || res.ExitCode != 0 {
		if res2, err2 := host.Run(ctx, host.ExecSpec{Path: "adduser", Args: []string{
			"--system", "--ingroup", WorkerGroup, "--shell", "/usr/sbin/nologin", "--no-create-home", WorkerUser,
		}}); err2 != nil || res2.ExitCode != 0 {
			return fmt.Errorf("create %s user failed: %s", WorkerUser, strings.TrimSpace(res.Stderr))
		}
	}
	return nil
}

// repairManagedState re-applies the managed surface when a same-build install
// finds the main config, the unit file or the layered permissions drifted. It
// returns true when anything had to be fixed, which tells the caller whether a
// restart is warranted.
func repairManagedState(ctx context.Context, paths host.Paths, installDir string, spec InstallSpec, rep *InstallReport) (bool, error) {
	changed := false
	mainPath := filepath.Join(installDir, "conf", "nginx.conf")
	rawMain, err := os.ReadFile(mainPath)
	if err != nil {
		return false, err
	}
	opts := ConfigOptions{User: WorkerUser, Group: WorkerGroup, LocalIP: spec.LocalIP, Stream: spec.Stream}
	rewritten, warnings := RewriteMainConfigWithWarnings(string(rawMain), opts)
	if rewritten != string(rawMain) {
		// Validate the repaired file before it replaces the live config.
		tmp := mainPath + ".repair"
		if err := os.WriteFile(tmp, []byte(rewritten), 0o644); err != nil {
			return false, err
		}
		checkErr := runConfigTest(ctx, filepath.Join(installDir, "sbin", "nginx"), installDir, tmp)
		_ = os.Remove(tmp)
		if checkErr != nil {
			return false, checkErr
		}
		if err := writeAtomic(mainPath, []byte(rewritten), 0o644); err != nil {
			return false, err
		}
		rep.Warnings = append(rep.Warnings, warnings...)
		changed = true
	}
	if unitPath, err := paths.Join(UnitRel, true); err == nil {
		want := UnitContent(installDir)
		if cur, readErr := os.ReadFile(unitPath); readErr != nil || string(cur) != want {
			if err := writeAtomic(unitPath, []byte(want), 0o644); err != nil {
				return false, err
			}
			changed = true
		}
	}
	if err := VerifyLayeredPermissions(ctx, paths.Root); err != nil {
		permWarnings, applyErr := ApplyLayeredPermissions(paths.Root)
		rep.Warnings = append(rep.Warnings, permWarnings...)
		if applyErr != nil {
			return false, applyErr
		}
		if err := VerifyLayeredPermissions(ctx, paths.Root); err != nil {
			return false, err
		}
		changed = true
	}
	// A same-build reinstall skips the apply step above when nothing drifted,
	// so the symlinked-certificate warning must be reported here as well.
	if warning := certDirWarning(paths); warning != "" && !slices.Contains(rep.Warnings, warning) {
		rep.Warnings = append(rep.Warnings, warning)
	}
	return changed, nil
}

func ensureService(ctx context.Context, root string, noService, changed bool, rep *InstallReport) error {
	if noService || root != "/" {
		return nil
	}
	if err := runService(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := runService(ctx, "enable", ServiceName); err != nil {
		return err
	}
	active := queryService(ctx, "is-active", ServiceName) == "active"
	if active && changed {
		if err := runService(ctx, "restart", ServiceName); err != nil {
			return err
		}
	} else if !active {
		if err := runService(ctx, "start", ServiceName); err != nil {
			return err
		}
	}
	rep.ServiceEnabled = queryService(ctx, "is-enabled", ServiceName)
	rep.ServiceActive = waitActive(ctx)
	if rep.ServiceActive != "active" {
		return fmt.Errorf("nginx.service is %q after start", rep.ServiceActive)
	}
	if out := runVersion(ctx, filepath.Join(root, InstallDirRel, "sbin", "nginx")); out != "" {
		rep.Warnings = append(rep.Warnings, "nginx version: "+out)
	}
	return nil
}

func waitActive(ctx context.Context) string {
	for i := 0; i < 20; i++ {
		state := queryService(ctx, "is-active", ServiceName)
		if state == "active" || state == "failed" {
			return state
		}
		time.Sleep(250 * time.Millisecond)
	}
	return queryService(ctx, "is-active", ServiceName)
}

func installedSameBuild(metaPath, binPath, build string) (Metadata, bool) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return Metadata{}, false
	}
	var meta Metadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return Metadata{}, false
	}
	if meta.SchemaVersion != MetadataSchemaVersion || meta.Build != build || meta.BinarySHA256 == "" {
		return Metadata{}, false
	}
	sum, err := fileSHA256(binPath)
	if err != nil || sum != meta.BinarySHA256 {
		return Metadata{}, false
	}
	return meta, true
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type fileSnapshot struct {
	path   string
	data   []byte
	mode   os.FileMode
	uid    int
	gid    int
	exists bool
}

func captureFiles(paths []string) ([]fileSnapshot, error) {
	out := make([]fileSnapshot, 0, len(paths))
	for _, p := range paths {
		s := fileSnapshot{path: p, uid: -1, gid: -1}
		info, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				out = append(out, s)
				continue
			}
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; refusing to manage it", p)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		s.data, s.mode, s.exists = b, info.Mode().Perm(), true
		if raw, ok := info.Sys().(*syscall.Stat_t); ok {
			s.uid, s.gid = int(raw.Uid), int(raw.Gid)
		}
		out = append(out, s)
	}
	return out, nil
}

func (s fileSnapshot) restore() error {
	if !s.exists {
		if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := writeAtomic(s.path, s.data, s.mode); err != nil {
		return err
	}
	if s.uid >= 0 && s.gid >= 0 && os.Geteuid() == 0 {
		if err := os.Chown(s.path, s.uid, s.gid); err != nil {
			return err
		}
	}
	return os.Chmod(s.path, s.mode)
}

type serviceSnapshot struct {
	managed     bool
	unitExisted bool
	enabled     string
	active      string
}

func captureService(ctx context.Context, root string, noService bool) serviceSnapshot {
	if noService || root != "/" {
		return serviceSnapshot{}
	}
	snap := serviceSnapshot{managed: true}
	if unitPath, err := host.NewPaths(root); err == nil {
		if p, joinErr := unitPath.Join(UnitRel, false); joinErr == nil {
			if _, statErr := os.Lstat(p); statErr == nil {
				snap.unitExisted = true
			}
		}
	}
	snap.enabled = queryService(ctx, "is-enabled", ServiceName)
	snap.active = queryService(ctx, "is-active", ServiceName)
	return snap
}

type swapState struct {
	installDir string
	backupDir  string
	swapped    bool
}

// restore returns the host to the captured state. Every step runs even when an
// earlier one fails: a failed daemon-reload must not leave nginx.service
// enabled/started, otherwise a retry sees a half-restored host and refuses to
// proceed. All failures are joined and returned together.
func restore(ctx context.Context, snap serviceSnapshot, files []fileSnapshot, swap *swapState) error {
	var errs error
	if snap.managed && !snap.unitExisted {
		_ = runService(ctx, "stop", ServiceName)
		_ = runService(ctx, "disable", ServiceName)
	}
	// Only undo the directory swap when it actually happened; a failure during
	// extraction or verification must leave the live tree untouched.
	if swap.swapped {
		if err := os.RemoveAll(swap.installDir); err != nil {
			errs = errors.Join(errs, fmt.Errorf("restore: remove new tree %s: %w", swap.installDir, err))
		} else if swap.backupDir != "" {
			if err := os.Rename(swap.backupDir, swap.installDir); err != nil {
				errs = errors.Join(errs, fmt.Errorf("restore: reinstate %s: %w", swap.backupDir, err))
			}
		}
	}
	for i := len(files) - 1; i >= 0; i-- {
		if err := files[i].restore(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("restore %s: %w", files[i].path, err))
		}
	}
	if !snap.managed {
		return errs
	}
	if err := runService(ctx, "daemon-reload"); err != nil {
		errs = errors.Join(errs, fmt.Errorf("restore: daemon-reload: %w", err))
	}
	if !snap.unitExisted {
		if got := queryService(ctx, "is-enabled", ServiceName); strings.Contains(got, "enabled") {
			errs = errors.Join(errs, fmt.Errorf("nginx.service is still enabled (%q)", got))
		}
		return errs
	}
	wantEnabled := strings.Contains(snap.enabled, "enabled")
	if wantEnabled {
		if err := runService(ctx, "enable", ServiceName); err != nil {
			errs = errors.Join(errs, fmt.Errorf("restore: enable: %w", err))
		}
	} else if err := runService(ctx, "disable", ServiceName); err != nil {
		errs = errors.Join(errs, fmt.Errorf("restore: disable: %w", err))
	}
	wantActive := snap.active == "active"
	if wantActive {
		if err := runService(ctx, "restart", ServiceName); err != nil {
			errs = errors.Join(errs, fmt.Errorf("restore: restart: %w", err))
		}
	} else if err := runService(ctx, "stop", ServiceName); err != nil {
		errs = errors.Join(errs, fmt.Errorf("restore: stop: %w", err))
	}
	return errs
}

func dirAt(paths host.Paths, rel string) (string, error) {
	p, err := paths.Join(rel, false)
	if err == nil {
		return p, nil
	}
	if os.IsNotExist(err) {
		return paths.Join(rel, true)
	}
	return "", err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
