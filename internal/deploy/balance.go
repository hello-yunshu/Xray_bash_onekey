package deploy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

// Balance upstream names. They also select the Bash fragment suffix
// (<host>.<upstream>Servers), so they are part of the on-disk contract.
const (
	BalanceUpstreamReality = "reality"
	BalanceUpstreamWS      = "ws"
	BalanceUpstreamGRPC    = "grpc"
	BalanceUpstreamXHTTP   = "xhttp"
)

// noBalanceProbeWarning is emitted whenever --probe was not requested, so the
// operator is never told a backend is alive just because it was written.
const noBalanceProbeWarning = "no liveness probe was run; nginx removes a dead backend passively via max_fails=2 fail_timeout=10"

// reservedBalancePorts are the ports a backend must never take: the public TLS
// entry (443) and the SNI guard/reality loopback ports.
var reservedBalancePorts = map[int]bool{443: true, 9403: true, 9404: true, 9443: true, 9444: true}

// balanceHostName accepts a DNS name. IPv6 literals are handled separately
// because ':' is not part of this character class.
var balanceHostName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// balanceNginxTest runs the managed binary's syntax check. It is a variable so
// tests can replace it the same way deploy_test.go replaces the service seams.
var balanceNginxTest = func(ctx context.Context, root string) error {
	installDir := filepath.Join(root, nginx.InstallDirRel)
	res, err := host.Run(ctx, host.ExecSpec{
		Path:    filepath.Join(installDir, "sbin", "nginx"),
		Args:    []string{"-t", "-p", strings.TrimRight(installDir, "/") + "/", "-c", filepath.Join(installDir, "conf", "nginx.conf")},
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

// BalanceSpec is one backend list/add/remove request.
type BalanceSpec struct {
	Root                 string
	AllowContainerWrites bool
	// Upstream is reality, ws, grpc or xhttp. Reality only exists on a
	// reality-balance primary; the others only on a TLS install.
	Upstream string
	Host     string
	Port     int
	// Weight is 0-100; zero means the Bash default of 50.
	Weight int
	Probe  bool
}

// BalanceBackend is one server line as stored on disk.
type BalanceBackend struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Weight int    `json:"weight"`
	File   string `json:"file"`
}

// BalanceReport is the machine-readable result.
type BalanceReport struct {
	Upstream string           `json:"upstream"`
	Backends []BalanceBackend `json:"backends"`
	Changed  bool             `json:"changed"`
	File     string           `json:"file,omitempty"`
	Probed   bool             `json:"probed"`
	Warnings []string         `json:"warnings"`
}

// ListBalance reports the backends of one upstream without writing anything.
func ListBalance(spec BalanceSpec) (BalanceReport, error) {
	_, _, suffix, dir, err := balanceTarget(spec)
	if err != nil {
		return BalanceReport{}, err
	}
	backends, err := readBalanceBackends(dir, suffix)
	if err != nil {
		return BalanceReport{}, err
	}
	return BalanceReport{Upstream: spec.Upstream, Backends: backends, Warnings: []string{}}, nil
}

// AddBalance writes one <host>.<suffix> fragment, validates it with nginx -t
// and reloads the managed front. Any failure leaves the previous state in place.
func AddBalance(ctx context.Context, spec BalanceSpec) (BalanceReport, error) {
	paths, meta, suffix, dir, err := balanceTarget(spec)
	if err != nil {
		return BalanceReport{}, err
	}
	backendHost, err := normalizeBalanceHost(spec.Host)
	if err != nil {
		return BalanceReport{}, err
	}
	if spec.Port < 1 || spec.Port > 65535 {
		return BalanceReport{}, fmt.Errorf("backend port must be between 1 and 65535")
	}
	if reservedBalancePorts[spec.Port] {
		return BalanceReport{}, fmt.Errorf("port %d is reserved by the managed install (443/9403/9404/9443/9444)", spec.Port)
	}
	weight := spec.Weight
	if weight == 0 {
		weight = 50
	}
	if weight < 0 || weight > 100 {
		return BalanceReport{}, fmt.Errorf("backend weight must be between 0 and 100")
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return BalanceReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return BalanceReport{}, err
	}
	defer lock.Release()

	file := filepath.Join(dir, backendHost+"."+suffix)
	if _, statErr := os.Lstat(file); statErr == nil {
		return BalanceReport{}, fmt.Errorf("a backend for host %s already exists in %s; remove it first", backendHost, file)
	}
	addr := net.JoinHostPort(backendHost, strconv.Itoa(spec.Port))
	if spec.Probe {
		sni, sniErr := balanceSNI(meta)
		if sniErr != nil {
			return BalanceReport{}, sniErr
		}
		if err := probeBalanceBackend(ctx, addr, sni); err != nil {
			return BalanceReport{}, err
		}
	}
	body := fmt.Sprintf("server %s weight=%d max_fails=2 fail_timeout=10;\n", addr, weight)
	if err := writeFileAtomic(file, []byte(body), 0o644); err != nil {
		return BalanceReport{}, err
	}
	if err := balanceNginxTest(ctx, paths.Root); err != nil {
		_ = os.Remove(file)
		return BalanceReport{}, fmt.Errorf("%w; the new backend file was removed", err)
	}
	rep := BalanceReport{
		Upstream: spec.Upstream, Changed: true, File: file,
		Probed: spec.Probe, Warnings: []string{},
	}
	if !spec.Probe {
		rep.Warnings = append(rep.Warnings, noBalanceProbeWarning)
	}
	if backends, readErr := readBalanceBackends(dir, suffix); readErr == nil {
		rep.Backends = backends
	}
	if err := balanceReload(ctx, paths.Root, &rep); err != nil {
		_ = os.Remove(file)
		return rep, fmt.Errorf("%w; the new backend file was removed", err)
	}
	return rep, nil
}

// RemoveBalance deletes one backend file. The local loopback backend and the
// last remaining backend of an upstream are refused.
func RemoveBalance(ctx context.Context, spec BalanceSpec) (BalanceReport, error) {
	paths, _, suffix, dir, err := balanceTarget(spec)
	if err != nil {
		return BalanceReport{}, err
	}
	backendHost, port, err := balanceRemoveTarget(spec.Host, spec.Port)
	if err != nil {
		return BalanceReport{}, err
	}
	if ip := net.ParseIP(backendHost); ip != nil && ip.IsLoopback() {
		return BalanceReport{}, fmt.Errorf("refusing to remove the local %s backend: it is the loopback front this install owns", backendHost)
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return BalanceReport{}, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return BalanceReport{}, err
	}
	defer lock.Release()

	file := filepath.Join(dir, backendHost+"."+suffix)
	info, statErr := os.Lstat(file)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return BalanceReport{}, fmt.Errorf("no backend file %s; check 'xray balance list --upstream %s'", file, spec.Upstream)
		}
		return BalanceReport{}, statErr
	}
	if !info.Mode().IsRegular() {
		return BalanceReport{}, fmt.Errorf("%s is not a regular file; refusing to remove it", file)
	}
	body, err := os.ReadFile(file)
	if err != nil {
		return BalanceReport{}, err
	}
	if port > 0 && !fileHasPort(string(body), port) {
		return BalanceReport{}, fmt.Errorf("%s has no server on port %d; refusing to remove the wrong backend", file, port)
	}
	count, err := countBalanceServers(dir, suffix)
	if err != nil {
		return BalanceReport{}, err
	}
	if count == 1 {
		return BalanceReport{}, fmt.Errorf("refusing to remove the last %s backend: the upstream would have no server", spec.Upstream)
	}
	if err := os.Remove(file); err != nil {
		return BalanceReport{}, err
	}
	restore := func() {
		_ = writeFileAtomic(file, body, info.Mode().Perm())
	}
	if err := balanceNginxTest(ctx, paths.Root); err != nil {
		restore()
		return BalanceReport{}, fmt.Errorf("%w; the removed backend was restored", err)
	}
	rep := BalanceReport{Upstream: spec.Upstream, Changed: true, File: file, Warnings: []string{}}
	if backends, readErr := readBalanceBackends(dir, suffix); readErr == nil {
		rep.Backends = backends
	}
	if err := balanceReload(ctx, paths.Root, &rep); err != nil {
		restore()
		return rep, fmt.Errorf("%w; the removed backend was restored", err)
	}
	return rep, nil
}

// balanceTarget loads metadata and proves this install really owns the managed
// Nginx front that includes *.<suffix>. TLS alone cannot distinguish
// reality-balance from reality-nginx, so an unknown role is refused instead of
// guessed.
func balanceTarget(spec BalanceSpec) (host.Paths, store.Metadata, string, string, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return host.Paths{}, store.Metadata{}, "", "", err
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return host.Paths{}, store.Metadata{}, "", "", err
	}
	suffix, err := balanceSuffix(meta, spec.Upstream)
	if err != nil {
		return host.Paths{}, store.Metadata{}, "", "", err
	}
	dir, err := paths.Join(nginxDirRel, false)
	if err != nil {
		return host.Paths{}, store.Metadata{}, "", "", fmt.Errorf("this install is not a managed Nginx front for upstream %q: %w", spec.Upstream, err)
	}
	anchor := nginx.MainConf
	if meta.TLS == "TLS" {
		anchor = "02-xray-server.conf"
	}
	anchorPath, err := paths.Join(nginxDirRel+"/"+anchor, false)
	if err != nil {
		return host.Paths{}, store.Metadata{}, "", "", fmt.Errorf("this install is not a managed Nginx front for upstream %q: %s is missing", spec.Upstream, anchor)
	}
	body, err := os.ReadFile(anchorPath)
	if err != nil {
		if os.IsNotExist(err) {
			return host.Paths{}, store.Metadata{}, "", "", fmt.Errorf("this install is not a managed Nginx front for upstream %q: %s is missing", spec.Upstream, anchor)
		}
		return host.Paths{}, store.Metadata{}, "", "", err
	}
	if !strings.Contains(string(body), "*."+suffix+";") {
		return host.Paths{}, store.Metadata{}, "", "", fmt.Errorf("this install is not a managed Nginx front for upstream %q: %s does not include *.%s", spec.Upstream, anchor, suffix)
	}
	return paths, meta, suffix, dir, nil
}

// balanceSuffix maps the install and upstream to the Bash fragment suffix.
func balanceSuffix(meta store.Metadata, upstream string) (string, error) {
	switch meta.TLS {
	case "Reality":
		if upstream != BalanceUpstreamReality {
			return "", fmt.Errorf("upstream %q is not available on a Reality install; reality-nginx is not managed by 'xray balance' — reinstall with --mode reality-balance --role primary", upstream)
		}
		if meta.BalanceRole != xraycfg.BalanceRolePrimary {
			return "", fmt.Errorf("cannot confirm this is a reality-balance primary (reality-nginx is not managed by 'xray balance'); reinstall with --mode reality-balance --role primary to manage backends")
		}
		return BalanceUpstreamReality + "Servers", nil
	case "TLS":
		switch upstream {
		case BalanceUpstreamWS, BalanceUpstreamGRPC, BalanceUpstreamXHTTP:
			return upstream + "Servers", nil
		}
		return "", fmt.Errorf("upstream %q is not available on a TLS install; use ws, grpc or xhttp", upstream)
	default:
		return "", fmt.Errorf("TLS mode %q has no managed Nginx upstream; 'xray balance' needs a reality-balance primary or a tls install", meta.TLS)
	}
}

// balanceReload reloads the managed front. A root whose service is not managed
// by this tool is left alone and reported, never reloaded blindly.
func balanceReload(ctx context.Context, root string, rep *BalanceReport) error {
	if !serviceManaged(root) {
		rep.Warnings = append(rep.Warnings, "managed nginx service is not managed on this root; reload skipped, run 'systemctl reload nginx' manually")
		return nil
	}
	if err := serviceCommand(ctx, "reload", "nginx"); err != nil {
		return fmt.Errorf("reload nginx: %w", err)
	}
	return nil
}

// balanceSNI takes the probe ServerName from the install snapshot. Guessing it
// from the filesystem would probe a different front than the one installed.
func balanceSNI(meta store.Metadata) (string, error) {
	if meta.Install == nil || len(meta.Install.ServerNames) == 0 {
		return "", fmt.Errorf("install metadata has no serverNames; finish a successful install before using --probe")
	}
	return meta.Install.ServerNames[0], nil
}

// probeBalanceBackend proves the backend accepts a TLS 1.3 handshake for the
// installed domain. It is a liveness check, not a trust decision: the chain is
// not verified, but the negotiated version is asserted.
func probeBalanceBackend(ctx context.Context, addr, sni string) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("backend probe %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// The probe only asserts reachability and TLS 1.3; certificate trust is not
	// the question being asked here.
	tc := tls.Client(conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("backend probe %s: TLS 1.3 handshake with SNI %q failed: %w", addr, sni, err)
	}
	if got := tc.ConnectionState().Version; got != tls.VersionTLS13 {
		return fmt.Errorf("backend probe %s: negotiated TLS version %#x, want TLS 1.3", addr, got)
	}
	return nil
}

// normalizeBalanceHost accepts an IPv4/IPv6 address or a DNS name and refuses
// anything that could escape the fragment directory or inject a directive.
func normalizeBalanceHost(raw string) (string, error) {
	h := strings.Trim(strings.TrimSpace(raw), "[]")
	if h == "" || strings.Contains(h, "..") || (net.ParseIP(h) == nil && !balanceHostName.MatchString(h)) {
		return "", fmt.Errorf("invalid backend host %q: expected an IPv4 address, DNS name or IPv6 address", raw)
	}
	return h, nil
}

// balanceRemoveTarget accepts "host", "host:port" or a separate --port.
func balanceRemoveTarget(raw string, port int) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, fmt.Errorf("a backend host is required")
	}
	host := raw
	if h, p, err := net.SplitHostPort(raw); err == nil {
		v, convErr := strconv.Atoi(p)
		if convErr != nil {
			return "", 0, fmt.Errorf("backend port in %q must be an integer", raw)
		}
		if port != 0 && port != v {
			return "", 0, fmt.Errorf("--port %d does not match the port in %q", port, raw)
		}
		host, port = h, v
	}
	host, err := normalizeBalanceHost(host)
	if err != nil {
		return "", 0, err
	}
	if port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("backend port must be between 1 and 65535")
	}
	return host, port, nil
}

// readBalanceBackends parses every *.<suffix> file in deterministic order.
func readBalanceBackends(dir, suffix string) ([]BalanceBackend, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	backends := []BalanceBackend{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, "."+suffix) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(body), "\n") {
			backend, ok := parseBalanceServer(line)
			if !ok {
				continue
			}
			backend.File = filepath.Join(dir, name)
			backends = append(backends, backend)
		}
	}
	sort.Slice(backends, func(i, j int) bool {
		if backends[i].Host != backends[j].Host {
			return backends[i].Host < backends[j].Host
		}
		return backends[i].Port < backends[j].Port
	})
	return backends, nil
}

// countBalanceServers counts the server lines of one upstream across all files.
func countBalanceServers(dir, suffix string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, "."+suffix) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "server ") {
				count++
			}
		}
	}
	return count, nil
}

func fileHasPort(body string, port int) bool {
	for _, line := range strings.Split(body, "\n") {
		backend, ok := parseBalanceServer(line)
		if ok && backend.Port == port {
			return true
		}
	}
	return false
}

// parseBalanceServer reads the exact line shape Bash writes.
func parseBalanceServer(line string) (BalanceBackend, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "server ") || !strings.HasSuffix(line, ";") {
		return BalanceBackend{}, false
	}
	fields := strings.Fields(strings.TrimSuffix(line, ";"))
	if len(fields) < 2 || fields[0] != "server" {
		return BalanceBackend{}, false
	}
	h, p, err := net.SplitHostPort(fields[1])
	if err != nil {
		return BalanceBackend{}, false
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return BalanceBackend{}, false
	}
	weight := 50
	for _, f := range fields[2:] {
		if strings.HasPrefix(f, "weight=") {
			if v, convErr := strconv.Atoi(strings.TrimPrefix(f, "weight=")); convErr == nil {
				weight = v
			}
		}
	}
	return BalanceBackend{Host: strings.Trim(h, "[]"), Port: port, Weight: weight}, true
}
