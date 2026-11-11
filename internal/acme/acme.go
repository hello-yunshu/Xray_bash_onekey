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
	"path/filepath"
	"strings"
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
)

// Issue performs a full ACME issuance and installs the certificate.
func Issue(ctx context.Context, cfg Config) (Result, error) {
	if err := validateConfig(cfg); err != nil {
		return Result{}, err
	}
	res := Result{Domain: cfg.Domain, DirectoryURL: cfg.DirectoryURL,
		Certificate: cfg.CertFile, Key: cfg.KeyFile}
	// Keep the installed pair in memory so a failed install/reload restores the
	// previous, still-usable certificate instead of leaving a half-applied pair.
	oldCert, oldKey, hadCert, hadKey := readPair(cfg.CertFile, cfg.KeyFile)
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
	res.Issued = true
	if err := reloadOrRestore(ctx, cfg, oldCert, oldKey, hadCert, hadKey); err != nil {
		return res, err
	}
	res.Reloaded = cfg.ReloadCommand != ""
	return res, nil
}

// reloadOrRestore runs the reload command after a successful install. If the
// reload fails the newly installed pair is rolled back to the previous one, so
// the service never keeps a certificate it refused to load.
func reloadOrRestore(ctx context.Context, cfg Config, oldCert, oldKey []byte, hadCert, hadKey bool) error {
	if cfg.ReloadCommand == "" {
		return nil
	}
	if err := runReload(ctx, cfg.ReloadCommand); err != nil {
		if restoreErr := restorePair(cfg.CertFile, cfg.KeyFile, oldCert, oldKey, hadCert, hadKey); restoreErr != nil {
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
	oldCert, oldKey, hadCert, hadKey := readPair(certPath, keyPath)
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
		if restoreErr := restorePair(certPath, keyPath, oldCert, oldKey, hadCert, hadKey); restoreErr != nil {
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

func readPair(certPath, keyPath string) (cert, key []byte, certExisted, keyExisted bool) {
	cert, certExisted = readMaybe(certPath)
	key, keyExisted = readMaybe(keyPath)
	return cert, key, certExisted, keyExisted
}

// restorePair puts the previous certificate pair back after a failed install.
// Only files that existed before are restored, and a file that existed but was
// unreadable is left untouched rather than being silently deleted. A failure
// creating the temporary artifact is reported so the caller can say the pair
// may be half-applied.
func restorePair(certPath, keyPath string, cert, key []byte, certExisted, keyExisted bool) error {
	var errs []string
	if err := restoreOne(certPath, cert, certExisted, 0o644); err != nil {
		errs = append(errs, "certificate: "+err.Error())
	}
	if err := restoreOne(keyPath, key, keyExisted, 0o600); err != nil {
		errs = append(errs, "key: "+err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func restoreOne(dest string, body []byte, existed bool, mode os.FileMode) error {
	if body != nil {
		return stageReplace(dest, body, mode)
	}
	if existed {
		return nil
	}
	if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
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
