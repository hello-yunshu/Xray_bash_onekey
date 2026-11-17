// Package acme implements the certificate workflow (account, order, HTTP-01,
// CSR, finalize, download, install, renew) on top of the lego ACME library.
//
// The protocol layer is provided by github.com/go-acme/lego/v5 in library mode:
// no external lego binary and no acme.sh invocation. Everything that touches
// local state on purpose stays in this package: the account key/state files,
// the webroot token check, the atomic certificate-pair install (0644/0600),
// reload and the rollback of a failed install. The package is used against a
// local Pebble CA in tests (ACME_LOCAL_CA); it is not a public-CA acceptance and
// the CLI requires an explicit --directory URL so a production CA is never
// contacted implicitly.
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
)

// Config describes one issuance or renewal run.
type Config struct {
	DirectoryURL   string
	CACertFile     string
	Insecure       bool
	Email          string
	Domain         string
	Webroot        string
	CertFile       string
	KeyFile        string
	AccountKeyFile string
	StateFile      string
	RenewBefore    time.Duration
	Force          bool
	ReloadCommand  string
	// CertGroup switches the installed pair to the layered nginx model:
	// directory 0750, certificate and key 0640, owned by root:<group>.
	// Empty keeps the standalone 0644/0600 pair owned by the caller.
	CertGroup string
	// Takeover replaces a certificate that the operator marked as user-managed.
	Takeover bool
}

// Result reports what happened.
type Result struct {
	Domain       string `json:"domain"`
	DirectoryURL string `json:"directoryUrl"`
	AccountURL   string `json:"accountUrl"`
	OrderURL     string `json:"orderUrl"`
	Certificate  string `json:"certificateFile"`
	Key          string `json:"keyFile"`
	NotAfter     string `json:"notAfter,omitempty"`
	Serial       string `json:"serial,omitempty"`
	Issued       bool   `json:"issued"`
	Skipped      bool   `json:"skipped"`
	Reason       string `json:"reason,omitempty"`
	Reloaded     bool   `json:"reloaded,omitempty"`
}

const (
	wellKnownPath  = "/.well-known/acme-challenge/"
	defaultTimeout = 30 * time.Second

	// StagingDirectory and ProductionDirectory are the two Let's Encrypt
	// endpoints the Bash installer used through acme.sh. Staging is the CLI
	// default so a manual run can never consume production quota by accident.
	StagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"

	// DefaultAccountDir keeps ACME account state outside the certificate
	// directory. acme.sh used /root/.acme.sh for the same reason: the cert
	// tree has a group-readable layered permission model, and an account key
	// must never be exposed to the nginx worker group.
	DefaultAccountDir = "/etc/idleleo/acme"

	// ManagedCertDir is the only directory whose mode the layered model owns.
	// Issuing into any other directory must never rewrite that directory.
	ManagedCertDir = "/etc/idleleo/cert"

	// userManagedMarker marks a certificate that the operator supplied and
	// renews elsewhere. Native issuance and renewal never overwrite it unless
	// Takeover is set.
	userManagedMarker = ".user-managed"

	// managedMarker records that this manager issued the installed pair. The
	// Bash installer uses its absence (together with missing acme.sh state) to
	// recognise an operator-supplied certificate on a later run.
	managedMarker = ".managed-by-idleleo"
)

// Issue performs a full ACME issuance and installs the certificate.
func Issue(ctx context.Context, cfg Config) (Result, error) {
	if err := validateConfig(cfg); err != nil {
		return Result{}, err
	}
	if IsUserManaged(cfg.CertFile) && !cfg.Takeover {
		return Result{}, fmt.Errorf("certificate %s is marked as user-managed; refusing to overwrite it (pass --takeover to adopt it)", cfg.CertFile)
	}
	if err := migrateLegacyAccount(cfg); err != nil {
		return Result{}, err
	}
	res := Result{Domain: cfg.Domain, DirectoryURL: cfg.DirectoryURL,
		Certificate: cfg.CertFile, Key: cfg.KeyFile}
	// Keep the installed pair in memory so a failed install/reload restores the
	// previous, still-usable certificate instead of leaving a half-applied pair.
	old := snapshotPair(cfg.CertFile, cfg.KeyFile)
	client, accountURL, err := newLegoClient(ctx, cfg)
	if err != nil {
		return res, err
	}
	res.AccountURL = accountURL
	resource, err := obtainWithLego(ctx, client, cfg.Domain)
	if err != nil && isAccountMissing(err) && cfg.StateFile != "" {
		// The persisted account is unknown to this CA (fresh Pebble instance or
		// a reset state dir): forget the URL, register with the same key, retry.
		if rmErr := os.Remove(cfg.StateFile); rmErr == nil || os.IsNotExist(rmErr) {
			client, accountURL, err = newLegoClient(ctx, cfg)
			if err != nil {
				return res, err
			}
			res.AccountURL = accountURL
			resource, err = obtainWithLego(ctx, client, cfg.Domain)
		}
	}
	if err != nil {
		return res, err
	}
	cert, err := firstCertificate(resource.Certificate)
	if err != nil {
		return res, err
	}
	if _, err := tls.X509KeyPair(resource.Certificate, resource.PrivateKey); err != nil {
		return res, fmt.Errorf("issued certificate and key are not a valid pair: %w", err)
	}
	keyBlock, _ := pem.Decode(resource.PrivateKey)
	if keyBlock == nil {
		return res, fmt.Errorf("issued private key is not PEM")
	}
	res.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	res.Serial = cert.SerialNumber.Text(16)
	if err := replacePair(cfg.CertFile, cfg.KeyFile, resource.Certificate, keyBlock.Bytes); err != nil {
		return res, err
	}
	if err := applyPairPermissions(cfg.CertFile, cfg.KeyFile, cfg.CertGroup); err != nil {
		if restoreErr := old.restore(cfg.CertFile, cfg.KeyFile); restoreErr != nil {
			return res, fmt.Errorf("certificate installed but permissions could not be applied: %w (restoring the previous pair also failed: %v)", err, restoreErr)
		}
		return res, fmt.Errorf("certificate installed but permissions could not be applied; previous pair restored: %w", err)
	}
	res.Issued = true
	if err := reloadOrRestore(ctx, cfg, old); err != nil {
		return res, err
	}
	// Ownership is recorded only after the new pair is live and accepted by the
	// service. Doing it earlier would clear the user-managed marker even when a
	// failed reload rolled the operator's certificate back into place.
	if err := markManaged(cfg.CertFile, cfg.CertGroup); err != nil {
		return res, err
	}
	if err := clearUserManaged(cfg.CertFile); err != nil {
		return res, err
	}
	res.Reloaded = cfg.ReloadCommand != ""
	return res, nil
}

// reloadOrRestore runs the reload command after a successful install. If the
// reload fails the newly installed pair is rolled back to the previous one, so
// the service never keeps a certificate it refused to load.
func reloadOrRestore(ctx context.Context, cfg Config, old pairSnapshot) error {
	if cfg.ReloadCommand == "" {
		return nil
	}
	if err := runReload(ctx, cfg.ReloadCommand); err != nil {
		if restoreErr := old.restore(cfg.CertFile, cfg.KeyFile); restoreErr != nil {
			return fmt.Errorf("certificate installed but reload failed, and restoring the previous pair also failed: %w (restore: %v)", err, restoreErr)
		}
		return fmt.Errorf("certificate installed but reload failed; previous pair restored: %w", err)
	}
	return nil
}

// Renew reissues only when the installed certificate is inside the renew
// window (or Force is set). It is the same protocol flow as Issue; the result
// reports Skipped when the current certificate is still valid.
func Renew(ctx context.Context, cfg Config) (Result, error) {
	res := Result{Domain: cfg.Domain, DirectoryURL: cfg.DirectoryURL,
		Certificate: cfg.CertFile, Key: cfg.KeyFile}
	if IsUserManaged(cfg.CertFile) && !cfg.Takeover {
		res.Skipped = true
		res.Reason = "certificate is marked user-managed; renewal is external (pass --takeover to adopt it)"
		return res, nil
	}
	notAfter, err := certNotAfter(cfg.CertFile)
	if err != nil {
		if os.IsNotExist(err) {
			return Issue(ctx, cfg)
		}
		return res, err
	}
	res.NotAfter = notAfter.UTC().Format(time.RFC3339)
	if !cfg.Force && time.Now().Add(cfg.RenewBefore).Before(notAfter) {
		res.Skipped = true
		res.Reason = fmt.Sprintf("certificate valid until %s; renew window %s not reached",
			notAfter.UTC().Format(time.RFC3339), cfg.RenewBefore)
		return res, nil
	}
	return Issue(ctx, cfg)
}

// Preflight validates the domain and HTTP-01 webroot against the staging CA
// without installing anything. This mirrors the acme.sh flow the Bash
// installer used: try staging first, discard it, then issue for production.
func Preflight(ctx context.Context, cfg Config) error {
	if cfg.Domain == "" || cfg.Webroot == "" {
		return fmt.Errorf("domain and webroot are required")
	}
	if err := validateDomain(cfg.Domain); err != nil {
		return err
	}
	if err := migrateLegacyAccount(cfg); err != nil {
		return err
	}
	probe := cfg
	probe.DirectoryURL = StagingDirectory
	probe.CertFile = ""
	probe.KeyFile = ""
	probe.ReloadCommand = ""
	client, _, err := newLegoClient(ctx, probe)
	if err != nil {
		return err
	}
	_, err = obtainWithLego(ctx, client, cfg.Domain)
	return err
}

// Inspection is the read-only view printed by `cert renew --dry-run`.
type Inspection struct {
	Domain      string `json:"domain,omitempty"`
	Certificate string `json:"certificateFile"`
	Key         string `json:"keyFile"`
	NotAfter    string `json:"notAfter,omitempty"`
	RenewAt     string `json:"renewAt,omitempty"`
	RenewBefore string `json:"renewBefore"`
	Due         bool   `json:"due"`
	Missing     bool   `json:"missing,omitempty"`
	UserManaged bool   `json:"userManaged,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// Inspect reports certificate lifetime and the next renewal point without
// contacting the CA or touching any file.
func Inspect(certFile string, renewBefore time.Duration) (Inspection, error) {
	ins := Inspection{
		Certificate: certFile,
		RenewBefore: renewBefore.String(),
		UserManaged: IsUserManaged(certFile),
	}
	notAfter, err := certNotAfter(certFile)
	if err != nil {
		if os.IsNotExist(err) {
			ins.Due = true
			ins.Missing = true
			ins.Reason = "certificate file does not exist"
			return ins, nil
		}
		return ins, err
	}
	ins.NotAfter = notAfter.UTC().Format(time.RFC3339)
	renewAt := notAfter.Add(-renewBefore)
	ins.RenewAt = renewAt.UTC().Format(time.RFC3339)
	ins.Due = !time.Now().Before(renewAt)
	switch {
	case ins.UserManaged:
		ins.Reason = "certificate is user-managed; renewal is external"
	case ins.Due:
		ins.Reason = fmt.Sprintf("renew window reached (expires in %s)", time.Until(notAfter).Round(time.Hour))
	default:
		ins.Reason = fmt.Sprintf("next renewal at %s (expires in %s)", ins.RenewAt, time.Until(notAfter).Round(time.Hour))
	}
	return ins, nil
}

func validateConfig(cfg Config) error {
	if cfg.DirectoryURL == "" {
		return fmt.Errorf("acme directory URL is required")
	}
	if cfg.Domain == "" || cfg.Webroot == "" || cfg.CertFile == "" || cfg.KeyFile == "" {
		return fmt.Errorf("domain, webroot, cert file and key file are required")
	}
	return validateDomain(cfg.Domain)
}

func isAccountMissing(err error) bool {
	var problem *legoacme.ProblemDetails
	return errors.As(err, &problem) && problem.Type == legoacme.AccountDoesNotExistErrorType
}

func rootPool(caFile string, insecure bool) (*x509.CertPool, error) {
	if insecure {
		return nil, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
	}
	return pool, nil
}

func validateDomain(domain string) error {
	if strings.ContainsAny(domain, "/ \t\r\n:*") || !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid ACME domain %q", domain)
	}
	return nil
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("account key file is required")
	}
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("account key %s is not PEM", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("account key %s is not ECDSA", path)
		}
		return ec, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(path, "PRIVATE KEY", der, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func firstCertificate(chain []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate response is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certNotAfter(path string) (time.Time, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	cert, err := firstCertificate(raw)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// validToken accepts only the RFC 8555 base64url token alphabet. A token is
// joined into the webroot path, so anything that could traverse directories
// (slashes, dots, whitespace) is rejected before a file is written.
func validToken(token string) bool {
	if token == "" || len(token) > 256 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// replacePair installs a certificate and key as one transaction: both temp
// files are written and fsynced first, the certificate is renamed into place,
// then the key. If the key cannot be renamed the previous certificate is
// restored, so callers never observe a new certificate with an old key.
func replacePair(certPath, keyPath string, chain, keyDER []byte) error {
	if _, err := firstCertificate(chain); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	old := snapshotPair(certPath, keyPath)
	certPEM := chain
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certTmp, err := stageFile(certPath, certPEM, 0o644)
	if err != nil {
		return err
	}
	keyTmp, err := stageFile(keyPath, keyPEM, 0o600)
	if err != nil {
		os.Remove(certTmp)
		return err
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		os.Remove(certTmp)
		os.Remove(keyTmp)
		return fmt.Errorf("install certificate: %w", err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		os.Remove(keyTmp)
		// Roll the certificate back to the pair that was working before this run.
		if restoreErr := old.restore(certPath, keyPath); restoreErr != nil {
			return fmt.Errorf("install private key: %w (certificate rollback also failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("install private key: %w", err)
	}
	if err := os.Chmod(certPath, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return err
	}
	return nil
}

// stageFile writes a temp file next to the destination and fsyncs it so the
// later rename cannot publish a partially written artifact.
func stageFile(dest string, body []byte, mode os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".idleleo-acme-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// readMaybe returns the file contents and whether anything existed at path. A
// file that exists but cannot be read is reported as existing with nil contents
// so a rollback never deletes or overwrites it.
func readMaybe(path string) ([]byte, bool) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return raw, true
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	return nil, true
}

// pairSnapshot captures the previous pair and its permission bits so a
// rollback restores the layered ownership model instead of resetting the files
// to the standalone 0644/0600 defaults.
type pairSnapshot struct {
	cert, key               []byte
	certExisted             bool
	keyExisted              bool
	certMode, keyMode       os.FileMode
	certModeSet, keyModeSet bool
	certUID, certGID        int
	certOwnerSet            bool
	keyUID, keyGID          int
	keyOwnerSet             bool
}

func snapshotPair(certPath, keyPath string) pairSnapshot {
	s := pairSnapshot{}
	s.cert, s.certExisted = readMaybe(certPath)
	s.key, s.keyExisted = readMaybe(keyPath)
	if info, err := os.Stat(certPath); err == nil {
		s.certMode, s.certModeSet = info.Mode().Perm(), true
		s.certUID, s.certGID, s.certOwnerSet = fileOwner(info)
	}
	if info, err := os.Stat(keyPath); err == nil {
		s.keyMode, s.keyModeSet = info.Mode().Perm(), true
		s.keyUID, s.keyGID, s.keyOwnerSet = fileOwner(info)
	}
	return s
}

// fileOwner reads the numeric owner of a file. A rollback rewrites the pair
// through a temp file, so ownership must be captured and re-applied explicitly;
// otherwise a restored 0640 key would be left root:root and the nginx worker
// would lose read access.
func fileOwner(info os.FileInfo) (int, int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func (s pairSnapshot) restore(certPath, keyPath string) error {
	var errs []string
	if err := restoreOneMode(certPath, s.cert, s.certExisted, 0o644, s.certMode, s.certModeSet, s.certUID, s.certGID, s.certOwnerSet); err != nil {
		errs = append(errs, "certificate: "+err.Error())
	}
	if err := restoreOneMode(keyPath, s.key, s.keyExisted, 0o600, s.keyMode, s.keyModeSet, s.keyUID, s.keyGID, s.keyOwnerSet); err != nil {
		errs = append(errs, "key: "+err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func restoreOneMode(dest string, body []byte, existed bool, fallback os.FileMode, mode os.FileMode, haveMode bool, uid, gid int, haveOwner bool) error {
	if body == nil {
		if existed {
			return nil
		}
		if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if !haveMode {
		mode = fallback
	}
	if err := stageReplace(dest, body, mode); err != nil {
		return err
	}
	if haveOwner && os.Geteuid() == 0 {
		if err := os.Chown(dest, uid, gid); err != nil {
			return &os.PathError{Op: "chown", Path: dest, Err: err}
		}
	}
	return nil
}

// applyPairPermissions enforces the certificate permission contract. Bash
// installs the pair as 0640 root:idleleo-nginx inside a 0750 directory so the
// nginx worker group can read it; without a group the pair stays 0644/0600.
func applyPairPermissions(certPath, keyPath, group string) error {
	if group == "" {
		if err := os.Chmod(certPath, 0o644); err != nil {
			return err
		}
		return os.Chmod(keyPath, 0o600)
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("lookup certificate group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("certificate group %q has invalid gid %q: %w", group, g.Gid, err)
	}
	chown := os.Geteuid() == 0
	dirs := []string{filepath.Dir(certPath)}
	if filepath.Dir(keyPath) != dirs[0] {
		dirs = append(dirs, filepath.Dir(keyPath))
	}
	for _, dir := range dirs {
		// Only the managed certificate directory has a known contract. A manual
		// --cert-out elsewhere (a harness, /tmp, an existing Nginx tree) must
		// keep its own mode; tightening it would break unrelated traversal.
		if filepath.Clean(dir) != ManagedCertDir {
			continue
		}
		if chown {
			if err := os.Chown(dir, 0, gid); err != nil {
				return fmt.Errorf("chown certificate directory %s: %w", dir, err)
			}
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return fmt.Errorf("chmod certificate directory %s: %w", dir, err)
		}
	}
	for _, path := range []string{certPath, keyPath} {
		if chown {
			if err := os.Chown(path, 0, gid); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		}
		if err := os.Chmod(path, 0o640); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
	}
	return nil
}

// IsUserManaged reports whether the operator supplied this certificate and
// renews it elsewhere. The marker lives next to the pair, so it follows
// backups and survives installer re-runs.
func IsUserManaged(certFile string) bool {
	_, err := os.Stat(UserManagedMarker(certFile))
	return err == nil
}

// UserManagedMarker returns the path of the user-managed marker.
func UserManagedMarker(certFile string) string {
	return filepath.Join(filepath.Dir(certFile), userManagedMarker)
}

// MarkUserManaged marks the installed certificate as externally managed.
func MarkUserManaged(certFile string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return err
	}
	body := []byte("managed-by=user\n")
	return os.WriteFile(UserManagedMarker(certFile), body, 0o640)
}

// ManagedMarker returns the path of the marker that records native ownership.
func ManagedMarker(certFile string) string {
	return filepath.Join(filepath.Dir(certFile), managedMarker)
}

// markManaged records that this manager issued the installed pair. The marker
// lives in the certificate directory, which the layered model makes group
// readable, so it must be chowned like the pair itself or the next
// `verify_nginx_layered_permissions` pass would reject it.
func markManaged(certFile, group string) error {
	dir := filepath.Dir(certFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	var gid = -1
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("lookup certificate group %q: %w", group, err)
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return fmt.Errorf("certificate group %q has invalid gid %q: %w", group, g.Gid, err)
		}
		mode = 0o640
	}
	body := []byte("managed-by=idleleo\n")
	if err := os.WriteFile(ManagedMarker(certFile), body, mode); err != nil {
		return err
	}
	if gid >= 0 && os.Geteuid() == 0 {
		if err := os.Chown(ManagedMarker(certFile), 0, gid); err != nil {
			return fmt.Errorf("chown %s: %w", ManagedMarker(certFile), err)
		}
	}
	return nil
}

func clearUserManaged(certFile string) error {
	if err := os.Remove(UserManagedMarker(certFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// migrateLegacyAccount moves account state out of <cert dir>/acme, where the
// Bash permission pass would have exposed the account key to the nginx group.
func migrateLegacyAccount(cfg Config) error {
	if cfg.AccountKeyFile == "" || cfg.StateFile == "" || cfg.CertFile == "" {
		return nil
	}
	newDir := filepath.Dir(cfg.AccountKeyFile)
	legacyDir := filepath.Join(filepath.Dir(cfg.CertFile), "acme")
	if filepath.Clean(newDir) == filepath.Clean(legacyDir) {
		return nil
	}
	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || (entry.Name() != "account.key" && entry.Name() != "account.json") {
			return fmt.Errorf("legacy ACME state %s contains unexpected entry %q; refusing to migrate", legacyDir, entry.Name())
		}
	}
	if err := os.MkdirAll(newDir, 0o700); err != nil {
		return err
	}
	// The legacy directory sat inside the certificate tree, where the Bash
	// permission pass makes files group-readable. A rename would carry that
	// ownership along, so the target directory and every account artifact are
	// re-tightened to root-only here.
	if err := os.Chmod(newDir, 0o700); err != nil {
		return fmt.Errorf("secure ACME account directory %s: %w", newDir, err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(newDir, 0, 0); err != nil {
			return fmt.Errorf("secure ACME account directory %s: %w", newDir, err)
		}
	}
	tighten := func(path string) error {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("migrate ACME state %s: %w", path, err)
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(path, 0, 0); err != nil {
				return fmt.Errorf("migrate ACME state %s: %w", path, err)
			}
		}
		return nil
	}
	for _, entry := range entries {
		src := filepath.Join(legacyDir, entry.Name())
		dst := filepath.Join(newDir, entry.Name())
		if info, err := os.Stat(dst); err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("ACME state target %s is not a regular file; refusing to migrate", dst)
			}
			if err := os.Remove(src); err != nil {
				return err
			}
			if err := tighten(dst); err != nil {
				return err
			}
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			raw, readErr := os.ReadFile(src)
			if readErr != nil {
				return fmt.Errorf("migrate ACME state %s: %w", src, readErr)
			}
			if werr := os.WriteFile(dst, raw, 0o600); werr != nil {
				return fmt.Errorf("migrate ACME state %s: %w", src, werr)
			}
			if rerr := os.Remove(src); rerr != nil {
				return fmt.Errorf("migrate ACME state %s: %w", src, rerr)
			}
		}
		if err := tighten(dst); err != nil {
			return err
		}
	}
	if err := os.Remove(legacyDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("legacy ACME state migrated but %s could not be removed: %w", legacyDir, err)
	}
	return nil
}

func stageReplace(dest string, body []byte, mode os.FileMode) error {
	tmp, err := stageFile(dest, body, mode)
	if err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	buf := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	return os.WriteFile(path, buf, mode)
}

func runReload(ctx context.Context, command string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload command failed: %v: %s", err, out)
	}
	return nil
}
