// Package doctor runs read-only health checks over a managed root. It never
// writes, restarts a unit or changes a permission; it only reports what a
// repair or an operator should look at.
package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/clientprobe"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/service"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

const SchemaVersion = 1

// Connectivity evidence levels. They are ordered from weakest to strongest so
// an operator never reads a TCP connect as a working user session.
const (
	EvidenceFileAndService = "FILE_AND_SERVICE"
	EvidenceTCP            = "TCP_REACHABLE"
	EvidenceTLS            = "TLS_HANDSHAKE"
	EvidenceRealClient     = "REAL_CLIENT_PASS"
	EvidenceNotRun         = "NOT_RUN"
)

// Status is the severity of one check.
type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusSkip    Status = "skip"
	StatusUnknown Status = "unknown"
)

// Check is one diagnostic result with a short operator-facing message.
type Check struct {
	ID         string `json:"id"`
	Status     Status `json:"status"`
	Message    string `json:"message"`
	Detail     string `json:"detail,omitempty"`
	Method     string `json:"method,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Cause      string `json:"cause,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// Summary counts the severities so a caller can gate on fail without walking
// the list.
type Summary struct {
	OK      int `json:"ok"`
	Warn    int `json:"warn"`
	Fail    int `json:"fail"`
	Skip    int `json:"skip"`
	Unknown int `json:"unknown"`
}

// Report is the complete read-only view.
type Report struct {
	SchemaVersion int     `json:"schemaVersion"`
	Root          string  `json:"root"`
	GeneratedAt   string  `json:"generatedAt"`
	Checks        []Check `json:"checks"`
	Summary       Summary `json:"summary"`
	Healthy       bool    `json:"healthy"`
	// EvidenceLevel is the strongest thing this run actually proved. Healthy
	// only means "no check failed"; it is not an end-to-end claim.
	EvidenceLevel string   `json:"evidenceLevel"`
	Limitations   []string `json:"limitations"`
}

// Options injects the seams a test needs. A zero Options still performs every
// file-level check.
type Options struct {
	Now      time.Time
	Deep     bool
	Services func(ctx context.Context, root string) (service.StatusReport, error)
	Validate func(ctx context.Context, configPath string) error
	// ClientProbe runs a real Xray client through one user-bearing inbound.
	// It is opt-in because it needs a reachable HTTP origin and an installed
	// xray binary.
	ClientProbe bool
	ProbeURL    string
	ProbeExpect string
	Probe       func(ctx context.Context, xrayBin string, link clientprobe.Link, addr, origin, marker string) (clientprobe.Result, error)
}

// Run is RunWith with production defaults.
func Run(ctx context.Context, root string) Report {
	return RunWith(ctx, root, Options{})
}

// RunWith performs the checks in a fixed order so output is reproducible.
func RunWith(ctx context.Context, root string, opts Options) Report {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	rep := Report{SchemaVersion: SchemaVersion, Root: root, GeneratedAt: opts.Now.Format(time.RFC3339), Checks: []Check{}}
	paths, err := host.NewPaths(root)
	if err != nil {
		rep.add(Check{ID: "root", Status: StatusFail, Message: "root cannot be resolved", Detail: err.Error()})
		return rep.finish()
	}

	rep.add(checkLayout(paths))
	meta, _, metaErr := store.LoadMetadata(paths)
	rep.add(checkMetadata(metaErr))
	cfg, _ := checkConfig(paths, meta, opts, ctx)
	rep.add(cfg)
	rep.add(checkModes(paths))
	rep.add(checkServiceAccess(ctx, paths))
	rep.add(checkCertificate(paths, meta))
	rep.add(checkNginx(paths))
	rep.add(checkServices(ctx, root, opts))
	rep.add(checkBackup(paths, opts.Now))
	rep.add(checkDisk(paths))
	rep.add(checkLock(paths, opts.Now))
	rep.add(checkGeodata(paths))
	if opts.Deep {
		rep.add(checkConnectivity(ctx, paths))
	}
	if opts.ClientProbe {
		rep.add(checkClientProbe(ctx, paths, opts))
	}
	return rep.finish()
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

func (r *Report) finish() Report {
	for i := range r.Checks {
		c := &r.Checks[i]
		if c.Method == "" {
			c.Method = defaultMethod(c.ID)
		}
		if c.Evidence == "" {
			c.Evidence = string(c.Status)
		}
		if c.Suggestion == "" && (c.Status == StatusFail || c.Status == StatusWarn || c.Status == StatusUnknown) {
			c.Suggestion = defaultSuggestion(c.ID)
		}
		switch c.Status {
		case StatusOK:
			r.Summary.OK++
		case StatusWarn:
			r.Summary.Warn++
		case StatusFail:
			r.Summary.Fail++
		case StatusSkip:
			r.Summary.Skip++
		case StatusUnknown:
			r.Summary.Unknown++
		}
	}
	r.Healthy = r.Summary.Fail == 0
	r.EvidenceLevel = EvidenceFileAndService
	for _, c := range r.Checks {
		if c.ID == "client-probe" && c.Status == StatusOK {
			r.EvidenceLevel = EvidenceRealClient
		}
	}
	if r.EvidenceLevel == EvidenceFileAndService {
		for _, c := range r.Checks {
			if c.ID != "connectivity" {
				continue
			}
			switch c.Evidence {
			case EvidenceTLS:
				r.EvidenceLevel = EvidenceTLS
			case EvidenceTCP:
				r.EvidenceLevel = EvidenceTCP
			case EvidenceNotRun:
				r.EvidenceLevel = EvidenceNotRun
			}
		}
	}
	r.Limitations = []string{
		"certificate chain, SAN matching and expiry are read from the managed PEM; no public CA trust store is consulted",
		"an external origin, DNS and cloud security groups are outside this process; only what this host can reach is tested",
		"a TCP connect or TLS handshake through a Reality inbound is not a user session; only --client-probe proves one",
		"a TLS listener probe proves the tunnel, not the public certificate chain",
	}
	return *r
}

func defaultMethod(id string) string {
	switch id {
	case "validator":
		return "xray run -test"
	case "services":
		return "systemctl is-active"
	case "disk":
		return "statfs"
	case "certificate":
		return "x509 parse"
	case "nginx":
		return "nginx -t"
	case "connectivity":
		return "tcp/tls dial"
	case "permissions":
		return "mode bits"
	case "lock":
		return "lstat"
	default:
		return "read-only inspection"
	}
}

func defaultSuggestion(id string) string {
	switch id {
	case "layout", "permissions", "lock":
		return "run idleleo repair --dry-run to preview the reversible fix"
	case "backup":
		return "run idleleo backup create"
	case "connectivity":
		return "check the unit state and the listener; this check never restarts anything"
	default:
		return "inspect the detail; this check never writes"
	}
}

func checkLayout(paths host.Paths) Check {
	required := []string{"etc/idleleo/conf", "etc/idleleo/v1"}
	for _, rel := range required {
		p, err := paths.Join(rel, false)
		if err != nil {
			return Check{ID: "layout", Status: StatusFail, Message: "managed layout is missing", Detail: rel + ": " + err.Error()}
		}
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			return Check{ID: "layout", Status: StatusFail, Message: "managed layout is missing", Detail: rel}
		}
	}
	return Check{ID: "layout", Status: StatusOK, Message: "managed directories are present"}
}

func checkMetadata(err error) Check {
	if err != nil {
		detail := err.Error()
		if st, ok := err.(*store.Error); ok {
			detail = st.Msg
		}
		return Check{ID: "metadata", Status: StatusFail, Message: "manager metadata is not readable", Detail: detail}
	}
	return Check{ID: "metadata", Status: StatusOK, Message: "manager metadata is readable"}
}

// checkConfig parses the runtime JSON and optionally runs the real validator.
func checkConfig(paths host.Paths, meta store.Metadata, opts Options, ctx context.Context) (Check, error) {
	configPath, err := paths.Join(paths.RuntimeConfig(), false)
	if err != nil {
		return Check{ID: "runtime-config", Status: StatusFail, Message: "runtime config is missing", Detail: paths.RuntimeConfig()}, err
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		return Check{ID: "runtime-config", Status: StatusFail, Message: "runtime config is not readable", Detail: err.Error()}, err
	}
	var cfg struct {
		Inbounds []struct {
			Port  int    `json:"port"`
			Tag   string `json:"tag"`
			Proto string `json:"protocol"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Check{ID: "runtime-config", Status: StatusFail, Message: "runtime config is not valid JSON", Detail: err.Error()}, err
	}
	seen := map[int]string{}
	for _, in := range cfg.Inbounds {
		if in.Port < 1 || in.Port > 65535 {
			return Check{ID: "runtime-config", Status: StatusFail, Message: "inbound port is out of range", Detail: fmt.Sprintf("tag=%s port=%d", in.Tag, in.Port)}, nil
		}
		if prev, dup := seen[in.Port]; dup && prev != in.Tag {
			return Check{ID: "runtime-config", Status: StatusWarn, Message: "two inbounds share a port", Detail: fmt.Sprintf("%s and %s on %d", prev, in.Tag, in.Port)}, nil
		}
		seen[in.Port] = in.Tag
	}
	if meta.RuntimeSHA256 != "" && store.HashBytes(body) != meta.RuntimeSHA256 {
		return Check{ID: "runtime-config", Status: StatusWarn, Message: "runtime config differs from the last recorded hash"}, nil
	}
	validator := opts.Validate
	if validator == nil {
		if bin := xrayBinary(paths.Root); bin != "" {
			v := runtime.XrayValidator{Path: bin, AssetDir: paths.GeodataDir()}
			validator = v.Validate
		}
	}
	if validator == nil {
		return Check{ID: "runtime-config", Status: StatusOK, Message: "runtime config parses; validator not installed"}, nil
	}
	if err := validator(ctx, configPath); err != nil {
		return Check{ID: "validator", Status: StatusFail, Message: "xray rejected the runtime config", Detail: err.Error()}, err
	}
	return Check{ID: "validator", Status: StatusOK, Message: "xray accepted the runtime config"}, nil
}

func xrayBinary(root string) string {
	if root == "/" {
		if _, err := os.Stat("/usr/local/bin/xray"); err == nil {
			return "/usr/local/bin/xray"
		}
		return ""
	}
	p := filepath.Join(root, "usr/local/bin/xray")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func checkModes(paths host.Paths) Check {
	configPath, err := paths.Join(paths.RuntimeConfig(), false)
	if err != nil {
		return Check{ID: "permissions", Status: StatusSkip, Message: "runtime config missing, permissions not checked"}
	}
	fi, err := os.Stat(configPath)
	if err != nil {
		return Check{ID: "permissions", Status: StatusWarn, Message: "runtime config stat failed", Detail: err.Error()}
	}
	if fi.Mode().Perm()&0o007 != 0 {
		return Check{ID: "permissions", Status: StatusFail, Message: "runtime config is world-accessible", Detail: fmt.Sprintf("mode %04o", fi.Mode().Perm())}
	}
	key := filepath.Join(paths.Root, "etc/idleleo/cert/xray.key")
	if fi, err := os.Stat(key); err == nil {
		if fi.Mode().Perm()&0o077 != 0 {
			return Check{ID: "permissions", Status: StatusFail, Message: "private key is accessible beyond its owner", Detail: fmt.Sprintf("mode %04o", fi.Mode().Perm())}
		}
	}
	return Check{ID: "permissions", Status: StatusOK, Message: "config and key permissions are restrictive"}
}

// checkServiceAccess proves that the service account can still read the
// config after a restart. Checking only that the service is active hides a
// permission change that would fail the next start.
func checkServiceAccess(ctx context.Context, paths host.Paths) Check {
	const id = "service-access"
	if _, err := user.Lookup("xray"); err != nil {
		return Check{ID: id, Status: StatusSkip, Message: "service account xray is not present"}
	}
	su, err := host.ResolveBinary("su")
	if err != nil {
		return Check{ID: id, Status: StatusSkip, Message: "su is unavailable, readability not proven"}
	}
	cfg := filepath.Join(paths.Root, paths.RuntimeConfig())
	if _, err := os.Stat(cfg); err != nil {
		return Check{ID: id, Status: StatusSkip, Message: "no runtime config to read"}
	}
	cmd := "test -r " + strconv.Quote(cfg) + " && test -x " + strconv.Quote(filepath.Join(paths.Root, "etc/idleleo/conf"))
	res, err := host.Run(ctx, host.ExecSpec{
		Path: su, Args: []string{"-s", "/bin/sh", "xray", "-c", cmd}, Timeout: 5 * time.Second,
	})
	if err != nil {
		return Check{ID: id, Status: StatusUnknown, Message: "could not test readability as the service account", Detail: err.Error()}
	}
	if res.ExitCode != 0 {
		return Check{ID: id, Status: StatusFail,
			Message:  "service account cannot read the runtime config",
			Detail:   "a restart would take xray down",
			Evidence: "su-read-test"}
	}
	return Check{ID: id, Status: StatusOK, Message: "service account can read the committed config"}
}

func checkCertificate(paths host.Paths, meta store.Metadata) Check {
	certPath := filepath.Join(paths.Root, "etc/idleleo/cert/xray.crt")
	body, err := os.ReadFile(certPath)
	if err != nil {
		return Check{ID: "certificate", Status: StatusSkip, Message: "no managed certificate to check"}
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return Check{ID: "certificate", Status: StatusFail, Message: "managed certificate is not PEM"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Check{ID: "certificate", Status: StatusFail, Message: "managed certificate cannot be parsed", Detail: err.Error()}
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return Check{ID: "certificate", Status: StatusFail, Message: "managed certificate has expired", Detail: cert.NotAfter.UTC().Format(time.RFC3339)}
	}
	if meta.Install != nil && len(meta.Install.ServerNames) > 0 && !certCoversAny(cert, meta.Install.ServerNames) {
		return Check{ID: "certificate", Status: StatusWarn,
			Message: "certificate does not cover the recorded server name(s)",
			Detail:  fmt.Sprintf("%v", meta.Install.ServerNames)}
	}
	if cert.NotAfter.Sub(now) < 30*24*time.Hour {
		return Check{ID: "certificate", Status: StatusWarn, Message: "managed certificate expires within 30 days", Detail: cert.NotAfter.UTC().Format(time.RFC3339)}
	}
	return Check{ID: "certificate", Status: StatusOK, Message: "managed certificate is valid", Detail: cert.NotAfter.UTC().Format(time.RFC3339)}
}

func certCoversAny(cert *x509.Certificate, names []string) bool {
	for _, want := range names {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		if cert.VerifyHostname(want) == nil {
			return true
		}
	}
	return false
}

// checkNginx runs the managed binary's own parser; it never reloads nginx.
func checkNginx(paths host.Paths) Check {
	bin := filepath.Join(paths.Root, "usr/local/nginx/sbin/nginx")
	if fi, err := os.Stat(bin); err != nil || fi.IsDir() {
		return Check{ID: "nginx", Status: StatusSkip, Message: "managed nginx is not installed"}
	}
	conf := filepath.Join(paths.Root, "usr/local/nginx/conf/nginx.conf")
	if _, err := os.Stat(conf); err != nil {
		return Check{ID: "nginx", Status: StatusWarn, Message: "managed nginx config is missing", Detail: conf}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-t", "-p", filepath.Dir(filepath.Dir(conf)), "-c", conf).CombinedOutput()
	if err != nil {
		return Check{ID: "nginx", Status: StatusFail, Message: "nginx rejected the managed config",
			Detail: trimOutput(out)}
	}
	return Check{ID: "nginx", Status: StatusOK, Message: "nginx accepted the managed config"}
}

func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = s[len(s)-400:]
	}
	return s
}

// checkConnectivity is the --deep layer. It proves what is provable without a
// client: TCP reachability, and a TLS handshake when the inbound is TLS. A
// Reality inbound degrades to unknown instead of pretending a plain connect
// is a user-level success.
func checkConnectivity(ctx context.Context, paths host.Paths) Check {
	configPath, err := paths.Join(paths.RuntimeConfig(), false)
	if err != nil {
		return Check{ID: "connectivity", Status: StatusSkip, Message: "runtime config missing, connectivity not probed"}
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		return Check{ID: "connectivity", Status: StatusSkip, Message: "runtime config unreadable, connectivity not probed"}
	}
	var cfg struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
			Tag    string `json:"tag"`
			Stream struct {
				Security string `json:"security"`
				TLS      struct {
					ServerName string `json:"serverName"`
				} `json:"tlsSettings"`
				Reality struct {
					ServerNames []string `json:"serverNames"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Check{ID: "connectivity", Status: StatusSkip, Message: "runtime config is not valid JSON, connectivity not probed"}
	}
	if len(cfg.Inbounds) == 0 {
		return Check{ID: "connectivity", Status: StatusUnknown, Message: "no inbound to probe", Evidence: EvidenceNotRun}
	}
	probed := 0
	evidence := EvidenceTCP
	for _, in := range cfg.Inbounds {
		if probed == 3 {
			break
		}
		if in.Port < 1 || in.Port > 65535 {
			continue
		}
		probed++
		host := in.Listen
		switch host {
		case "", "0.0.0.0", "::", "[::]":
			host = "127.0.0.1"
		}
		addr := net.JoinHostPort(host, strconv.Itoa(in.Port))
		dialer := net.Dialer{Timeout: 2 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return Check{ID: "connectivity", Status: StatusFail,
				Message:  fmt.Sprintf("inbound %s is not reachable", in.Tag),
				Detail:   addr + ": " + err.Error(),
				Evidence: EvidenceTCP,
				Cause:    "the process is not listening or a firewall drops the probe",
			}
		}
		switch in.Stream.Security {
		case "tls":
			serverName := in.Stream.TLS.ServerName
			if serverName == "" && len(in.Stream.Reality.ServerNames) > 0 {
				serverName = in.Stream.Reality.ServerNames[0]
			}
			tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = tlsConn.Close()
				return Check{ID: "connectivity", Status: StatusFail,
					Message:  fmt.Sprintf("inbound %s accepted TCP but not TLS", in.Tag),
					Detail:   err.Error(),
					Evidence: EvidenceTLS,
					Cause:    "the listener is not the expected TLS inbound",
				}
			}
			_ = tlsConn.Close()
			evidence = EvidenceTLS
		case "reality":
			_ = conn.Close()
			return Check{ID: "connectivity", Status: StatusUnknown,
				Message:  fmt.Sprintf("inbound %s is TCP-reachable; Reality handshake needs a client", in.Tag),
				Evidence: EvidenceTCP,
				Cause:    "doctor has no Xray client and must not fake a user-level success",
			}
		default:
			_ = conn.Close()
		}
	}
	return Check{ID: "connectivity", Status: StatusOK,
		Message:  fmt.Sprintf("%d inbound(s) probed", probed),
		Evidence: evidence}
}

func checkServices(ctx context.Context, root string, opts Options) Check {
	if root != "/" {
		return Check{ID: "services", Status: StatusSkip, Message: "sandbox root: host units are not queried"}
	}
	var st service.StatusReport
	var err error
	if opts.Services != nil {
		st, err = opts.Services(ctx, root)
	} else {
		st, err = service.Status(ctx, root)
	}
	if err != nil {
		return Check{ID: "services", Status: StatusWarn, Message: "unit state is unavailable", Detail: err.Error()}
	}
	for _, u := range st.Units {
		if u.Name == "xray" && u.Active != "active" {
			return Check{ID: "services", Status: StatusFail, Message: "xray unit is not active", Detail: u.Active}
		}
	}
	return Check{ID: "services", Status: StatusOK, Message: "owned units are active"}
}

func checkBackup(paths host.Paths, now time.Time) Check {
	dir := filepath.Join(paths.Root, "etc/idleleo/backup")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return Check{ID: "backup", Status: StatusWarn, Message: "no backup is available"}
	}
	var newest time.Time
	count := 0
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		count++
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if count == 0 {
		return Check{ID: "backup", Status: StatusWarn, Message: "no backup is available"}
	}
	age := now.Sub(newest)
	if age > 30*24*time.Hour {
		return Check{ID: "backup", Status: StatusWarn, Message: "the newest backup is older than 30 days", Detail: newest.UTC().Format(time.RFC3339)}
	}
	return Check{ID: "backup", Status: StatusOK, Message: fmt.Sprintf("%d backup entr(ies) found; newest %s", count, newest.UTC().Format(time.RFC3339))}
}

func checkDisk(paths host.Paths) Check {
	var st syscall.Statfs_t
	if err := syscall.Statfs(paths.Root, &st); err != nil {
		return Check{ID: "disk", Status: StatusSkip, Message: "disk usage is unavailable", Detail: err.Error()}
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	switch {
	case free < 512<<20:
		return Check{ID: "disk", Status: StatusFail, Message: "less than 512 MiB free", Detail: fmt.Sprintf("%d MiB", free>>20)}
	case free < 1<<30:
		return Check{ID: "disk", Status: StatusWarn, Message: "less than 1 GiB free", Detail: fmt.Sprintf("%d MiB", free>>20)}
	}
	return Check{ID: "disk", Status: StatusOK, Message: "enough free disk space", Detail: fmt.Sprintf("%d MiB", free>>20)}
}

func checkLock(paths host.Paths, now time.Time) Check {
	fi, err := os.Stat(paths.LockFile())
	if err != nil {
		return Check{ID: "lock", Status: StatusOK, Message: "no update lock is held"}
	}
	held, heldErr := host.LockHeld(paths.LockFile())
	if heldErr != nil {
		return Check{ID: "lock", Status: StatusSkip, Message: "cannot test the update lock", Detail: heldErr.Error()}
	}
	if !held {
		if age := now.Sub(fi.ModTime()); age > 30*time.Minute {
			return Check{ID: "lock", Status: StatusWarn, Message: "a stale update lock file exists", Detail: fi.ModTime().UTC().Format(time.RFC3339)}
		}
		return Check{ID: "lock", Status: StatusOK, Message: "no update lock is held"}
	}
	if age := now.Sub(fi.ModTime()); age > 30*time.Minute {
		return Check{ID: "lock", Status: StatusWarn, Message: "a stale update lock exists", Detail: fi.ModTime().UTC().Format(time.RFC3339)}
	}
	return Check{ID: "lock", Status: StatusWarn, Message: "an update lock is currently held"}
}

// checkClientProbe is the strongest read-only layer: it starts the real Xray
// client from this installation, dials the managed listener and proves an HTTP
// response arrives from the origin. A missing binary, no user-bearing inbound
// or no probe URL is reported as NOT_RUN instead of a pass.
func checkClientProbe(ctx context.Context, paths host.Paths, opts Options) Check {
	const id = "client-probe"
	if strings.TrimSpace(opts.ProbeURL) == "" {
		return Check{ID: id, Status: StatusSkip, Evidence: EvidenceNotRun,
			Message: "no probe URL supplied; the real-client layer was not exercised"}
	}
	configPath, err := paths.Join(paths.RuntimeConfig(), false)
	if err != nil {
		return Check{ID: id, Status: StatusSkip, Evidence: EvidenceNotRun,
			Message: "runtime config missing, client probe not run"}
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		return Check{ID: id, Status: StatusSkip, Evidence: EvidenceNotRun,
			Message: "runtime config unreadable, client probe not run"}
	}
	link, addr, ok, err := probeLink(body)
	if err != nil {
		return Check{ID: id, Status: StatusFail, Evidence: EvidenceRealClient,
			Message: "cannot build a client from the runtime config", Detail: err.Error()}
	}
	if !ok {
		return Check{ID: id, Status: StatusSkip, Evidence: EvidenceNotRun,
			Message: "no user-bearing vless inbound to probe"}
	}
	bin := xrayBinary(paths.Root)
	if bin == "" {
		return Check{ID: id, Status: StatusSkip, Evidence: EvidenceNotRun,
			Message: "xray binary is not installed, client probe not run"}
	}
	probe := opts.Probe
	if probe == nil {
		probe = clientprobe.Probe
	}
	res, err := probe(ctx, bin, link, addr, opts.ProbeURL, opts.ProbeExpect)
	if err != nil {
		return Check{ID: id, Status: StatusFail, Evidence: EvidenceRealClient,
			Message: "a real client could not complete the request",
			Detail:  err.Error(), Cause: "the tunnel, the credential or the origin is not usable"}
	}
	return Check{ID: id, Status: StatusOK, Evidence: EvidenceRealClient,
		Message: fmt.Sprintf("a real client reached the origin through %s", addr),
		Detail:  fmt.Sprintf("%s, %d body bytes", res.StatusLine, res.BodyBytes)}
}

// probeLink projects the first user-bearing vless inbound onto a client link.
// It never mutates the config and never persists the derived key.
func probeLink(body []byte) (clientprobe.Link, string, bool, error) {
	var doc struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Clients []struct {
					ID   string `json:"id"`
					Flow string `json:"flow"`
				} `json:"clients"`
			} `json:"settings"`
			Stream struct {
				Network  string `json:"network"`
				Security string `json:"security"`
				Reality  struct {
					PrivateKey  string   `json:"privateKey"`
					ShortIDs    []string `json:"shortIds"`
					ServerNames []string `json:"serverNames"`
				} `json:"realitySettings"`
				TLS struct {
					ServerName string `json:"serverName"`
				} `json:"tlsSettings"`
				WS struct {
					Path string `json:"path"`
				} `json:"wsSettings"`
				GRPC struct {
					ServiceName string `json:"serviceName"`
				} `json:"grpcSettings"`
				XHTTP struct {
					Path string `json:"path"`
				} `json:"xhttpSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return clientprobe.Link{}, "", false, err
	}
	for _, in := range doc.Inbounds {
		if in.Protocol != "vless" || len(in.Settings.Clients) == 0 || in.Port < 1 {
			continue
		}
		link := clientprobe.Link{
			UUID:        in.Settings.Clients[0].ID,
			Flow:        in.Settings.Clients[0].Flow,
			Network:     in.Stream.Network,
			Security:    in.Stream.Security,
			Path:        in.Stream.WS.Path,
			ShortID:     firstString(in.Stream.Reality.ShortIDs),
			SNI:         firstString(in.Stream.Reality.ServerNames),
			Fingerprint: "chrome",
		}
		if link.Network == "" || link.Network == "tcp" {
			link.Network = "raw"
		}
		switch link.Network {
		case "grpc":
			link.ServiceName = in.Stream.GRPC.ServiceName
		case "xhttp":
			link.Path = in.Stream.XHTTP.Path
		}
		if link.Security == "reality" {
			pub, err := xraycfg.DerivePublicKey(in.Stream.Reality.PrivateKey)
			if err != nil {
				return clientprobe.Link{}, "", false, fmt.Errorf("derive the reality public key: %w", err)
			}
			link.PublicKey = pub
		} else if link.Security == "tls" {
			if in.Stream.TLS.ServerName != "" {
				link.SNI = in.Stream.TLS.ServerName
			}
		}
		listen := in.Listen
		if listen == "" || listen == "0.0.0.0" || listen == "::" || listen == "[::]" {
			listen = "127.0.0.1"
		}
		return link, net.JoinHostPort(listen, strconv.Itoa(in.Port)), true, nil
	}
	return clientprobe.Link{}, "", false, nil
}

func firstString(values []string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func checkGeodata(paths host.Paths) Check {
	dir := paths.GeodataDir()
	var missing []string
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return Check{ID: "geodata", Status: StatusOK, Message: "geo assets are present"}
	}
	sort.Strings(missing)
	return Check{ID: "geodata", Status: StatusWarn, Message: "geo assets are missing", Detail: fmt.Sprintf("%v", missing)}
}
