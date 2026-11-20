package deploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// Unknown-SNI policies, matching the Bash SNI Guard menu.
const (
	SNIPolicyIsolate = "isolate"
	SNIPolicyReject  = "reject"
	SNIPolicyDecoy   = "decoy"
)

// Reserved loopback ports used by the deny upstream of each policy.
const (
	GuardIsolatePort = 9403
	GuardRejectPort  = 9404
	GuardDecoyPort   = 9444
)

const (
	guardCertRel     = "etc/idleleo/cert"
	guardDecoyRel    = "etc/idleleo/decoy"
	guardIsolateFrag = "03-isolate.conf"
	guardDecoyFrag   = "03-decoy.conf"
)

var guardDomain = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// guardDenyServer rewrites the loopback port of the deny upstream without
// regenerating the whole stream block, so the install's public port is kept.
var guardDenyServer = regexp.MustCompile(`(?s)(upstream\s+deny\s*\{[^}]*?server\s+127\.0\.0\.1:)(\d+)(\s*;)`)

// guardInclude matches the only main-config lines a policy change owns.
var guardInclude = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+/etc/idleleo/conf/nginx/03-(?:isolate|decoy)\.conf;[ \t]*\r?\n?`)

// guardResolveHost is a seam: tests must not depend on public DNS.
var guardResolveHost = net.LookupHost

// SNIGuardSpec is one policy change request.
type SNIGuardSpec struct {
	Root                 string
	AllowContainerWrites bool
	Policy               string
	DecoyDomain          string
	// DecoyCert/DecoyKey optionally import an existing certificate pair. When
	// empty a self-signed certificate is generated, matching the Bash flow.
	DecoyCert string
	DecoyKey  string
	// DecoyIPs declares extra addresses the decoy domain may resolve to, for
	// hosts behind NAT where the public address is not on an interface.
	DecoyIPs []string
	DryRun   bool
}

// SNIGuardReport is the machine-readable result.
type SNIGuardReport struct {
	Mode        string   `json:"mode"`
	Policy      string   `json:"policy"`
	DecoyDomain string   `json:"decoyDomain,omitempty"`
	DenyPort    int      `json:"denyPort"`
	Changed     bool     `json:"changed"`
	DryRun      bool     `json:"dryRun"`
	Files       []string `json:"files"`
	Reloaded    bool     `json:"reloaded"`
	SelfSigned  bool     `json:"selfSigned,omitempty"`
	Warnings    []string `json:"warnings"`
}

type guardChange struct {
	path   string
	data   []byte
	delete bool
}

// SetSNIGuard changes the Reality+Nginx unknown-SNI policy with the same
// artifacts Bash writes: an isolate site, a decoy site, or a dead deny port.
func SetSNIGuard(ctx context.Context, spec SNIGuardSpec) (SNIGuardReport, error) {
	rep := SNIGuardReport{Policy: spec.Policy, DryRun: spec.DryRun, Files: []string{}, Warnings: []string{}}
	policy, err := normalizeSNIPolicy(spec.Policy)
	if err != nil {
		return rep, err
	}
	rep.Policy = policy

	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return rep, err
	}
	if !spec.DryRun {
		if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
			return rep, err
		}
		lock, err := host.AcquireUpdate(paths.LockFile())
		if err != nil {
			return rep, err
		}
		defer lock.Release()
		// The first read of metadata, artifacts and the plan must happen under
		// the same lock a concurrent install/edit/certificate change takes.
		if rec, recErr := recoverPendingLocked(ctx, paths); recErr != nil {
			return rep, recErr
		} else if rec.Action != "none" {
			rep.Warnings = append(rep.Warnings, "converged a pending deploy transaction: "+rec.Action)
			if serviceManaged(paths.Root) {
				if testErr := balanceNginxTest(ctx, paths.Root); testErr == nil {
					_ = balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings)
				}
			}
		}
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return rep, err
	}
	rep.Mode = meta.TLS
	if meta.TLS != "Reality" {
		return rep, fmt.Errorf("the current install mode %q has no Reality SNI front", meta.TLS)
	}

	nginxDir, err := paths.Join(nginxDirRel, false)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Nginx front: %w", err)
	}
	mainConf, err := paths.Join(filepath.Join(nginx.InstallDirRel, "conf/nginx.conf"), false)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Nginx front: %w", err)
	}
	xrayConf := filepath.Join(nginxDir, nginx.MainConf)
	xrayBody, err := os.ReadFile(xrayConf)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Reality+Nginx front: %w", err)
	}
	if !strings.Contains(string(xrayBody), "$ssl_preread_server_name") || !guardDenyServer.Match(xrayBody) {
		return rep, errors.New("this install is not a managed Reality+Nginx front: deny upstream not found")
	}
	mainBody, err := os.ReadFile(mainConf)
	if err != nil {
		return rep, err
	}

	denyPort := sniguardPort(policy)
	rep.DenyPort = denyPort
	if err := guardPortConflict(paths, meta, denyPort); err != nil {
		return rep, err
	}

	isolatePath := filepath.Join(nginxDir, guardIsolateFrag)
	decoyPath := filepath.Join(nginxDir, guardDecoyFrag)

	changes := make([]guardChange, 0, 8)
	if updated, changed := rewriteDenyPort(string(xrayBody), denyPort); changed {
		changes = append(changes, guardChange{path: xrayConf, data: []byte(updated)})
	}

	switch policy {
	case SNIPolicyIsolate:
		changes = append(changes,
			guardChange{path: isolatePath, data: []byte(isolateFragment())},
			guardChange{path: decoyPath, delete: true},
		)
	case SNIPolicyReject:
		changes = append(changes,
			guardChange{path: isolatePath, delete: true},
			guardChange{path: decoyPath, delete: true},
		)
	case SNIPolicyDecoy:
		domain := strings.TrimSpace(spec.DecoyDomain)
		if err := validateDecoyDomain(domain); err != nil {
			return rep, err
		}
		rep.DecoyDomain = domain
		if err := verifyDecoyDomain(domain, spec.DecoyIPs); err != nil {
			return rep, err
		}
		certPath, keyPath, certPEM, keyPEM, generated, err := prepareDecoyCert(paths, spec, domain)
		if err != nil {
			return rep, err
		}
		rep.SelfSigned = generated
		webroot, err := paths.Join(guardDecoyRel, true)
		if err != nil {
			return rep, err
		}
		changes = append(changes,
			guardChange{path: certPath, data: certPEM},
			guardChange{path: keyPath, data: keyPEM},
			guardChange{path: filepath.Join(webroot, "index.html"), data: []byte(decoyIndex(domain, decoyToken()))},
			guardChange{path: decoyPath, data: []byte(decoyFragment(domain, certPath, keyPath, webroot))},
			guardChange{path: isolatePath, delete: true},
		)
	}

	updatedMain, mainChanged, err := rewriteGuardInclude(string(mainBody), policy)
	if err != nil {
		return rep, err
	}
	if mainChanged {
		changes = append(changes, guardChange{path: mainConf, data: []byte(updatedMain)})
	}

	meta.SNIGuard = &store.SNIGuardState{
		Enabled:     true,
		Policy:      policy,
		DecoyDomain: rep.DecoyDomain,
	}
	meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaBytes = append(metaBytes, '\n')
	metaPath, err := paths.Join(paths.ManagerMetadata(), false)
	if err != nil {
		return rep, err
	}
	changes = append(changes, guardChange{path: metaPath, data: metaBytes})

	for _, ch := range changes {
		rep.Files = append(rep.Files, ch.path)
	}
	if spec.DryRun {
		rep.Changed = len(changes) > 0
		return rep, nil
	}

	backups, err := captureGuardFiles(changes)
	if err != nil {
		return rep, err
	}
	// Persist the snapshot before mutating: a SIGKILL between two file writes is
	// then converged by the next lock holder instead of leaving a half-applied
	// policy on disk.
	journal, err := newJournal(paths, backups, serviceState{}, nil, meta.TLS, meta.Transport)
	if err != nil {
		return rep, err
	}
	if err := applyGuardChanges(changes); err != nil {
		return rep, guardRollback(paths, &journal, backups, err, "apply")
	}
	if err := balanceNginxTest(ctx, paths.Root); err != nil {
		return rep, guardRollback(paths, &journal, backups, err, "nginx -t")
	}
	rep.Changed = true
	if err := balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings); err != nil {
		rbErr := guardRollback(paths, &journal, backups, err, "reload")
		if rbErr == nil {
			// The files are back; bring the running master in sync with them.
			if testErr := balanceNginxTest(ctx, paths.Root); testErr == nil {
				_ = balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings)
			}
		}
		return rep, rbErr
	}
	if err := journalMarkCommitted(paths, &journal); err != nil {
		return rep, err
	}
	return rep, nil
}

// guardRollback restores every guard file and records a terminal journal state.
// It distinguishes a completed rollback from RECOVERY_NEEDED; a failed restore
// is never reported as "the previous policy was restored".
func guardRollback(paths host.Paths, j *deployJournal, backups []fileState, cause error, stage string) error {
	if err := restoreGuardFiles(backups); err != nil {
		journalMarkRecoveryRequired(paths, j, err)
		return fmt.Errorf("%w; %s failed and the rollback did not complete: %v (RECOVERY_NEEDED, run 'idleleo recover')",
			cause, stage, err)
	}
	_ = journalMarkRolledBack(paths, j, cause)
	return fmt.Errorf("%w; the previous SNI Guard policy was restored", cause)
}

// SNIGuardStatus is the read-only view of the unknown-SNI policy. It is derived
// from the deployed Nginx artifacts and reconciled with metadata; it never
// invents "enabled/isolate" for a node that has no managed Reality front.
type SNIGuardStatus struct {
	Applicable     bool     `json:"applicable"`
	TLS            string   `json:"tls,omitempty"`
	ManagedFront   bool     `json:"managedFront"`
	Enabled        bool     `json:"enabled"`
	Policy         string   `json:"policy,omitempty"`
	DecoyDomain    string   `json:"decoyDomain,omitempty"`
	Status         string   `json:"status"`
	MetadataSynced bool     `json:"metadataSynced"`
	DenyPort       int      `json:"denyPort,omitempty"`
	Evidence       []string `json:"evidence"`
	Warnings       []string `json:"warnings"`
}

var (
	guardDecoyServerName = regexp.MustCompile(`(?m)^[ \t]*server_name[ \t]+([^;]+);`)
	guardIncludePolicy   = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+/etc/idleleo/conf/nginx/(03-(?:isolate|decoy)\.conf);`)
	guardIncludeGlob     = regexp.MustCompile(`(?m)^[ \t]*include[ \t]+/etc/idleleo/conf/nginx/\*\.conf;[ \t]*$`)
)

// InspectSNIGuard reports the actual policy and any disagreement between the
// deployed files and the ownership metadata. It is strictly read-only.
func InspectSNIGuard(root string) (SNIGuardStatus, error) {
	st := SNIGuardStatus{Evidence: []string{}, Warnings: []string{}, Status: "not-applicable"}
	paths, err := host.NewPaths(root)
	if err != nil {
		return st, err
	}
	meta, _, metaErr := store.LoadMetadata(paths)
	if metaErr == nil {
		st.TLS = meta.TLS
	} else {
		st.Warnings = append(st.Warnings, "manager metadata is unavailable; runtime artifacts only")
	}
	if st.TLS != "" && st.TLS != "Reality" {
		return st, nil
	}
	nginxDir, err := paths.Join(nginxDirRel, false)
	if err != nil {
		return st, nil
	}
	xrayConf := filepath.Join(nginxDir, nginx.MainConf)
	body, err := os.ReadFile(xrayConf)
	if err != nil {
		return st, nil
	}
	text := string(body)
	if !strings.Contains(text, "$ssl_preread_server_name") {
		return st, nil
	}
	loc := guardDenyServer.FindStringSubmatchIndex(text)
	if loc == nil {
		return st, nil
	}
	st.Applicable = true
	st.ManagedFront = true
	port, _ := strconv.Atoi(text[loc[4]:loc[5]])
	st.DenyPort = port
	st.Evidence = append(st.Evidence, xrayConf)

	mainConf, err := paths.Join(filepath.Join(nginx.InstallDirRel, "conf/nginx.conf"), false)
	if err != nil {
		return st, err
	}
	mainBody, readErr := os.ReadFile(mainConf)
	if readErr == nil {
		st.Evidence = append(st.Evidence, mainConf)
	}
	includes := map[string]bool{}
	globInclude := false
	if readErr == nil {
		for _, m := range guardIncludePolicy.FindAllStringSubmatch(string(mainBody), -1) {
			includes[m[1]] = true
		}
		globInclude = guardIncludeGlob.Match(mainBody)
	}
	decoyFrag := filepath.Join(nginxDir, guardDecoyFrag)
	isolateFrag := filepath.Join(nginxDir, guardIsolateFrag)
	hasDecoy := fileExists(decoyFrag)
	hasIsolate := fileExists(isolateFrag)
	if hasDecoy {
		st.Evidence = append(st.Evidence, decoyFrag)
		if raw, err := os.ReadFile(decoyFrag); err == nil {
			if m := guardDecoyServerName.FindStringSubmatch(string(raw)); m != nil {
				st.DecoyDomain = strings.TrimSpace(m[1])
			}
		}
	}
	if hasIsolate {
		st.Evidence = append(st.Evidence, isolateFrag)
	}

	inconsistent := func(reason string) (SNIGuardStatus, error) {
		st.Status = "inconsistent"
		st.Warnings = append(st.Warnings, reason)
		return st, nil
	}
	if hasDecoy && hasIsolate {
		return inconsistent("both 03-isolate.conf and 03-decoy.conf exist")
	}
	if includes[guardIsolateFrag] && includes[guardDecoyFrag] {
		return inconsistent("nginx.conf includes both isolate and decoy fragments")
	}
	if hasDecoy && !includes[guardDecoyFrag] && !globInclude {
		return inconsistent("03-decoy.conf exists but nginx.conf does not include it")
	}
	if hasIsolate && !includes[guardIsolateFrag] && !globInclude {
		return inconsistent("03-isolate.conf exists but nginx.conf does not include it")
	}

	switch {
	case hasDecoy:
		st.Policy = SNIPolicyDecoy
		if port != GuardDecoyPort {
			return inconsistent(fmt.Sprintf("decoy fragment present but the deny upstream is port %d", port))
		}
	case hasIsolate:
		st.Policy = SNIPolicyIsolate
		if port != GuardIsolatePort {
			return inconsistent(fmt.Sprintf("isolate fragment present but the deny upstream is port %d", port))
		}
	case port == GuardDecoyPort:
		return inconsistent("the deny upstream targets the decoy port but 03-decoy.conf is missing")
	case port == GuardIsolatePort:
		st.Policy = SNIPolicyIsolate
	default:
		st.Policy = SNIPolicyReject
	}
	st.Enabled = true
	st.Status = "active"

	if metaErr != nil {
		st.MetadataSynced = false
		return st, nil
	}
	if meta.SNIGuard == nil {
		st.MetadataSynced = false
		st.Warnings = append(st.Warnings, "metadata has no sniGuard record; showing deployed artifacts, nothing was rewritten")
		return st, nil
	}
	st.MetadataSynced = true
	if !meta.SNIGuard.Enabled {
		if st.Enabled {
			st.Status = "drift"
			st.Warnings = append(st.Warnings, "metadata says sniGuard is disabled but the deployed front still applies a policy")
			return st, nil
		}
		st.Enabled = false
		return st, nil
	}
	if meta.SNIGuard.Policy != st.Policy {
		st.Status = "drift"
		st.Warnings = append(st.Warnings, fmt.Sprintf("metadata policy %q does not match deployed policy %q", meta.SNIGuard.Policy, st.Policy))
		return st, nil
	}
	if st.DecoyDomain == "" {
		st.DecoyDomain = meta.SNIGuard.DecoyDomain
	}
	st.Status = "active"
	return st, nil
}

func normalizeSNIPolicy(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", SNIPolicyIsolate:
		return SNIPolicyIsolate, nil
	case SNIPolicyReject:
		return SNIPolicyReject, nil
	case SNIPolicyDecoy:
		return SNIPolicyDecoy, nil
	}
	return "", fmt.Errorf("unknown SNI policy %q; use isolate, reject or decoy", policy)
}

func sniguardPort(policy string) int {
	switch policy {
	case SNIPolicyReject:
		return GuardRejectPort
	case SNIPolicyDecoy:
		return GuardDecoyPort
	}
	return GuardIsolatePort
}

// guardPortConflict refuses a guard port already used by an inbound, matching
// Bash's sni_guard_port_conflicts.
func guardPortConflict(paths host.Paths, meta store.Metadata, port int) error {
	ports := map[int]bool{}
	if meta.Install != nil {
		ports[meta.Install.Port] = true
	}
	if runtimePath, err := paths.Join(meta.RuntimeConfigPath, false); err == nil {
		if raw, readErr := os.ReadFile(runtimePath); readErr == nil {
			portPattern := regexp.MustCompile(`"port"\s*:\s*(\d+)`)
			for _, m := range portPattern.FindAllSubmatch(raw, -1) {
				if n, convErr := strconv.Atoi(string(m[1])); convErr == nil {
					ports[n] = true
				}
			}
		}
	}
	if ports[port] {
		return fmt.Errorf("port %d is already used by an inbound; choose another SNI policy or move the inbound", port)
	}
	return nil
}

func rewriteDenyPort(body string, port int) (string, bool) {
	loc := guardDenyServer.FindStringSubmatchIndex(body)
	if loc == nil {
		return body, false
	}
	current, err := strconv.Atoi(body[loc[4]:loc[5]])
	if err == nil && current == port {
		return body, false
	}
	replacement := body[loc[2]:loc[3]] + strconv.Itoa(port) + body[loc[6]:loc[7]]
	return body[:loc[0]] + replacement + body[loc[1]:], true
}

// rewriteGuardInclude keeps exactly the http-level include the policy needs.
// A *.conf glob already picks fragments up, so only explicit includes change.
func rewriteGuardInclude(body, policy string) (string, bool, error) {
	wanted := ""
	switch policy {
	case SNIPolicyIsolate:
		wanted = guardIsolateFrag
	case SNIPolicyDecoy:
		wanted = guardDecoyFrag
	}
	hasGlob := regexp.MustCompile(`(?m)^[ \t]*include[ \t]+/etc/idleleo/conf/nginx/\*\.conf;[ \t]*$`).MatchString(body)
	cleaned := guardInclude.ReplaceAllString(body, "")
	if hasGlob {
		return cleaned, cleaned != body, nil
	}
	if wanted == "" {
		return cleaned, cleaned != body, nil
	}
	line := "    include /etc/idleleo/conf/nginx/" + wanted + ";"
	lines := strings.Split(cleaned, "\n")
	httpOpen := regexp.MustCompile(`^\s*http\s*\{`)
	for i, text := range lines {
		if httpOpen.MatchString(text) {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, line)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n"), true, nil
		}
	}
	return cleaned, cleaned != body, errors.New("nginx main config has no http { block; the SNI Guard site cannot be included")
}

func isolateFragment() string {
	return "# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert\n" +
		"server {\n" +
		"    listen 127.0.0.1:9403 ssl;\n" +
		"    ssl_reject_handshake on;\n" +
		"    access_log off;\n" +
		"    error_log /dev/null;\n" +
		"}\n"
}

func decoyFragment(domain, cert, key, webroot string) string {
	return "# decoy 回落站点 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 HTTPS 站点\n" +
		"server {\n" +
		"    listen 127.0.0.1:9444 ssl;\n" +
		"    server_name " + domain + ";\n" +
		"    ssl_certificate " + cert + ";\n" +
		"    ssl_certificate_key " + key + ";\n" +
		"    ssl_protocols TLSv1.2 TLSv1.3;\n" +
		"    ssl_ciphers HIGH:!aNULL:!MD5;\n" +
		"    root " + webroot + ";\n" +
		"    index index.html;\n" +
		"    location / {\n" +
		"        try_files $uri $uri/ =404;\n" +
		"    }\n" +
		"}\n"
}

func validateDecoyDomain(domain string) error {
	if !guardDomain.MatchString(domain) || !strings.Contains(domain, ".") {
		return errors.New("decoy domain must be a DNS name containing a dot")
	}
	return nil
}

// verifyDecoyDomain requires the domain's A/AAAA set to overlap this host's
// addresses, matching the Bash safety check before serving a decoy site.
func verifyDecoyDomain(domain string, extra []string) error {
	resolved, err := guardResolveHost(domain)
	if err != nil || len(resolved) == 0 {
		return fmt.Errorf("cannot resolve decoy domain %s: %v", domain, err)
	}
	local := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				local[ipNet.IP.String()] = true
			}
		}
	}
	for _, raw := range extra {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			local[ip.String()] = true
		}
	}
	for _, raw := range resolved {
		if ip := net.ParseIP(raw); ip != nil && local[ip.String()] {
			return nil
		}
	}
	return fmt.Errorf("decoy domain %s resolves to %s, which does not include this host; point DNS at this server first",
		domain, strings.Join(resolved, ","))
}

func prepareDecoyCert(paths host.Paths, spec SNIGuardSpec, domain string) (certPath, keyPath string, certPEM, keyPEM []byte, generated bool, err error) {
	certPath, err = paths.Join(filepath.Join(guardCertRel, "decoy.crt"), true)
	if err != nil {
		return "", "", nil, nil, false, err
	}
	keyPath, err = paths.Join(filepath.Join(guardCertRel, "decoy.key"), true)
	if err != nil {
		return "", "", nil, nil, false, err
	}
	if spec.DecoyCert == "" && spec.DecoyKey == "" {
		certPEM, keyPEM, err = selfSignedDecoyCert(domain)
		if err != nil {
			return "", "", nil, nil, false, err
		}
		return certPath, keyPath, certPEM, keyPEM, true, nil
	}
	if spec.DecoyCert == "" || spec.DecoyKey == "" {
		return "", "", nil, nil, false, errors.New("--decoy-cert and --decoy-key must be provided together")
	}
	certPEM, err = os.ReadFile(spec.DecoyCert)
	if err != nil {
		return "", "", nil, nil, false, fmt.Errorf("read decoy certificate: %w", err)
	}
	keyPEM, err = os.ReadFile(spec.DecoyKey)
	if err != nil {
		return "", "", nil, nil, false, fmt.Errorf("read decoy key: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return "", "", nil, nil, false, fmt.Errorf("decoy certificate and key do not match: %w", err)
	}
	return certPath, keyPath, certPEM, keyPEM, false, nil
}

func selfSignedDecoyCert(domain string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func decoyToken() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "ok" + strconv.FormatInt(time.Now().Unix()%100000, 10)
	}
	return hex.EncodeToString(buf)[:6]
}

func decoyIndex(domain, token string) string {
	return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" +
		"<title>" + domain + "</title>\n</head>\n<body>\n<h1>It works</h1>\n" +
		"<p>Service status: OK (" + token + ")</p>\n</body>\n</html>\n"
}

func captureGuardFiles(changes []guardChange) ([]fileState, error) {
	paths := make([]string, 0, len(changes))
	for _, ch := range changes {
		paths = append(paths, ch.path)
	}
	return captureFiles(paths)
}

func applyGuardChanges(changes []guardChange) error {
	for _, ch := range changes {
		if ch.delete {
			if err := os.Remove(ch.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(ch.path), 0o755); err != nil {
			return err
		}
		if err := writeFileAtomic(ch.path, ch.data, guardFileMode(ch.path)); err != nil {
			return err
		}
		if isGuardSensitive(ch.path) {
			applyNginxGroup(ch.path)
		}
	}
	return nil
}

func restoreGuardFiles(backups []fileState) error {
	var errs []string
	for i := len(backups) - 1; i >= 0; i-- {
		if err := backups[i].restore(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", backups[i].path, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func guardFileMode(path string) os.FileMode {
	if isGuardSensitive(path) {
		return 0o600
	}
	return 0o644
}

func isGuardSensitive(path string) bool {
	return strings.HasSuffix(path, ".key") || strings.HasSuffix(path, ".crt")
}

// applyNginxGroup lets the managed worker read the certificate without making
// it world-readable. It is best-effort: a missing group leaves root-only 0600.
func applyNginxGroup(path string) {
	group, err := user.LookupGroup("idleleo-nginx")
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return
	}
	_ = os.Chmod(path, 0o640)
}
