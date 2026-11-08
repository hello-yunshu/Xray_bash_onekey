// Package acme implements the ACME v2 client needed for the Go certificate
// workflow (account, order, HTTP-01, CSR, finalize, download, install, renew).
//
// It intentionally has no external dependencies: every request is a JWS built
// with crypto/ecdsa and the HTTP-01 key authorization follows RFC 8555. The
// package is used against a local Pebble CA in tests (ACME_LOCAL_CA); it is not
// a public-CA acceptance and the CLI requires an explicit --directory URL so a
// production CA is never contacted implicitly.
package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	wellKnownPath   = "/.well-known/acme-challenge/"
	signatureAlg    = "ES256"
	defaultTimeout  = 30 * time.Second
	authzPoll       = time.Second
	authzMaxWait    = 120 * time.Second
	orderPoll       = time.Second
	orderMaxWait    = 120 * time.Second
	problemBadNonce = "urn:ietf:params:acme:error:badNonce"
	problemNoAcct   = "urn:ietf:params:acme:error:accountDoesNotExist"
)

type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (p *problem) Error() string {
	return fmt.Sprintf("acme problem %s: %s", p.Type, p.Detail)
}

type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
}

type order struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type authorization struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Token  string `json:"token"`
		Status string `json:"status"`
	} `json:"challenges"`
}

type client struct {
	cfg      Config
	hc       *http.Client
	dir      directory
	account  *ecdsa.PrivateKey
	kid      string
	nonce    string
	jwk      map[string]string
	thumb    string
	stateURL string
	// lastOrderURL is set by newOrder so issue can poll it after finalize.
	lastOrderURL string
}

// Issue performs a full ACME issuance and installs the certificate.
func Issue(ctx context.Context, cfg Config) (Result, error) {
	c, err := newClient(cfg)
	if err != nil {
		return Result{}, err
	}
	res := Result{Domain: cfg.Domain, DirectoryURL: cfg.DirectoryURL,
		Certificate: cfg.CertFile, Key: cfg.KeyFile}
	res.AccountURL, res.OrderURL, res.NotAfter, res.Serial, err = c.issue(ctx)
	if err != nil {
		return res, err
	}
	res.Issued = true
	if cfg.ReloadCommand != "" {
		if err := runReload(ctx, cfg.ReloadCommand); err != nil {
			return res, err
		}
		res.Reloaded = true
	}
	return res, nil
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

func newClient(cfg Config) (*client, error) {
	if cfg.DirectoryURL == "" {
		return nil, fmt.Errorf("acme directory URL is required")
	}
	if cfg.Domain == "" || cfg.Webroot == "" || cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, fmt.Errorf("domain, webroot, cert file and key file are required")
	}
	if err := validateDomain(cfg.Domain); err != nil {
		return nil, err
	}
	pool, err := rootPool(cfg.CACertFile, cfg.Insecure)
	if err != nil {
		return nil, err
	}
	c := &client{cfg: cfg, hc: &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: cfg.Insecure},
		},
	}}
	if err := c.loadDirectory(); err != nil {
		return nil, err
	}
	if err := c.loadAccount(); err != nil {
		return nil, err
	}
	return c, nil
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

func (c *client) loadDirectory() error {
	resp, err := c.hc.Get(c.cfg.DirectoryURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme directory: http %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &c.dir); err != nil {
		return err
	}
	if c.dir.NewNonce == "" || c.dir.NewAccount == "" || c.dir.NewOrder == "" {
		return fmt.Errorf("acme directory is missing endpoints")
	}
	return nil
}

func (c *client) loadAccount() error {
	key, err := loadOrCreateAccountKey(c.cfg.AccountKeyFile)
	if err != nil {
		return err
	}
	c.account = key
	c.jwk = publicJWK(&key.PublicKey)
	c.thumb = jwkThumbprint(c.jwk)
	if c.cfg.StateFile != "" {
		if raw, err := os.ReadFile(c.cfg.StateFile); err == nil {
			var st struct {
				DirectoryURL string `json:"directoryUrl"`
				AccountURL   string `json:"accountUrl"`
			}
			if json.Unmarshal(raw, &st) == nil && st.DirectoryURL == c.cfg.DirectoryURL {
				c.kid = st.AccountURL
				c.stateURL = c.cfg.StateFile
			}
		}
	}
	if c.kid == "" {
		return c.register()
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

func (c *client) register() error {
	payload, _ := json.Marshal(map[string]any{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:" + c.cfg.Email},
	})
	resp, body, err := c.postJWS(c.dir.NewAccount, payload, "", true)
	if err != nil {
		return err
	}
	kid := resp.Header.Get("Location")
	if kid == "" {
		return fmt.Errorf("newAccount did not return an account URL: %s", body)
	}
	c.kid = kid
	if c.cfg.StateFile != "" {
		st := map[string]string{"directoryUrl": c.cfg.DirectoryURL, "accountUrl": kid}
		raw, _ := json.MarshalIndent(st, "", "  ")
		if err := os.WriteFile(c.cfg.StateFile, append(raw, '\n'), 0o600); err != nil {
			return err
		}
		c.stateURL = c.cfg.StateFile
	}
	return nil
}

func (c *client) issue(ctx context.Context) (accountURL, orderURL, notAfter, serial string, err error) {
	payload, _ := json.Marshal(map[string]any{
		"identifiers": []map[string]string{{"type": "dns", "value": c.cfg.Domain}},
	})
	var ord order
	ord, err = c.newOrder(payload)
	if err != nil && isProblem(err, problemNoAcct) && c.stateURL != "" {
		// The persisted account is unknown to this CA (fresh Pebble instance
		// or a reset state dir): register with the same key and retry once.
		_ = os.Remove(c.stateURL)
		c.kid = ""
		if regErr := c.register(); regErr != nil {
			return "", "", "", "", regErr
		}
		ord, err = c.newOrder(payload)
	}
	if err != nil {
		return "", "", "", "", err
	}
	orderURL = c.lastOrderURL

	for _, authzURL := range ord.Authorizations {
		if err := c.completeHTTP01(ctx, authzURL); err != nil {
			return "", "", "", "", err
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", "", err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: c.cfg.Domain},
		DNSNames: []string{c.cfg.Domain},
	}, certKey)
	if err != nil {
		return "", "", "", "", err
	}
	finPayload, _ := json.Marshal(map[string]string{
		"csr": base64.RawURLEncoding.EncodeToString(csrDER),
	})
	if _, _, err = c.postJWS(ord.Finalize, finPayload, c.kid, false); err != nil {
		return "", "", "", "", err
	}

	ord, err = c.waitOrder(orderURL)
	if err != nil {
		return "", "", "", "", err
	}
	if ord.Certificate == "" {
		return "", "", "", "", fmt.Errorf("order %s is valid but has no certificate URL", orderURL)
	}
	_, chain, err := c.postJWS(ord.Certificate, nil, c.kid, false)
	if err != nil {
		return "", "", "", "", err
	}
	leaf, err := firstCertificate(chain)
	if err != nil {
		return "", "", "", "", err
	}
	if err := writeCertificate(c.cfg.CertFile, chain); err != nil {
		return "", "", "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return "", "", "", "", err
	}
	if err := writePEM(c.cfg.KeyFile, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", "", "", err
	}
	return c.kid, orderURL, leaf.NotAfter.UTC().Format(time.RFC3339), leaf.SerialNumber.Text(16), nil
}

func (c *client) newOrder(payload []byte) (order, error) {
	var ord order
	resp, body, err := c.postJWS(c.dir.NewOrder, payload, c.kid, false)
	if err != nil {
		return ord, err
	}
	c.lastOrderURL = resp.Header.Get("Location")
	if c.lastOrderURL == "" {
		return ord, fmt.Errorf("newOrder did not return an order URL")
	}
	if err := json.Unmarshal(body, &ord); err != nil {
		return ord, err
	}
	return ord, nil
}

func (c *client) waitOrder(orderURL string) (order, error) {
	deadline := time.Now().Add(orderMaxWait)
	for {
		_, body, err := c.postJWS(orderURL, nil, c.kid, false)
		if err != nil {
			return order{}, err
		}
		var ord order
		if err := json.Unmarshal(body, &ord); err != nil {
			return order{}, err
		}
		switch ord.Status {
		case "valid":
			return ord, nil
		case "invalid":
			return ord, fmt.Errorf("order became invalid")
		}
		if time.Now().After(deadline) {
			return order{}, fmt.Errorf("timed out waiting for order %s", orderURL)
		}
		time.Sleep(orderPoll)
	}
}

func (c *client) completeHTTP01(ctx context.Context, authzURL string) error {
	_, body, err := c.postJWS(authzURL, nil, c.kid, false)
	if err != nil {
		return err
	}
	var authz authorization
	if err := json.Unmarshal(body, &authz); err != nil {
		return err
	}
	var challengeURL, token string
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			challengeURL, token = ch.URL, ch.Token
			break
		}
	}
	if challengeURL == "" {
		return fmt.Errorf("authorization for %s has no http-01 challenge", authz.Identifier.Value)
	}
	keyAuth := token + "." + c.thumb
	challengeFile := filepath.Join(c.cfg.Webroot, filepath.FromSlash(strings.TrimPrefix(wellKnownPath, "/")), token)
	if err := os.MkdirAll(filepath.Dir(challengeFile), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(challengeFile, []byte(keyAuth), 0o644); err != nil {
		return err
	}
	defer os.Remove(challengeFile)

	if _, _, err := c.postJWS(challengeURL, []byte("{}"), c.kid, false); err != nil {
		return err
	}
	deadline := time.Now().Add(authzMaxWait)
	for {
		_, body, err := c.postJWS(authzURL, nil, c.kid, false)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(body, &authz); err != nil {
			return err
		}
		switch authz.Status {
		case "valid":
			return nil
		case "invalid":
			return fmt.Errorf("authorization for %s became invalid", authz.Identifier.Value)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for authorization %s", authzURL)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(authzPoll):
		}
	}
}

func (c *client) postJWS(url string, payload []byte, kid string, useJWK bool) (*http.Response, []byte, error) {
	resp, body, err := c.postJWSOnce(url, payload, kid, useJWK)
	if p, ok := err.(*problem); ok && p.Type == problemBadNonce {
		c.nonce = ""
		return c.postJWSOnce(url, payload, kid, useJWK)
	}
	return resp, body, err
}

func (c *client) postJWSOnce(url string, payload []byte, kid string, useJWK bool) (*http.Response, []byte, error) {
	nonce, err := c.nextNonce()
	if err != nil {
		return nil, nil, err
	}
	protected := map[string]any{"alg": signatureAlg, "nonce": nonce, "url": url}
	if useJWK {
		protected["jwk"] = c.jwk
	} else {
		protected["kid"] = kid
	}
	protJSON, _ := json.Marshal(protected)
	protB64 := base64.RawURLEncoding.EncodeToString(protJSON)
	payB64 := base64.RawURLEncoding.EncodeToString(payload)
	signing := protB64 + "." + payB64
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.account, digest[:])
	if err != nil {
		return nil, nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	bodyJSON, _ := json.Marshal(map[string]string{
		"protected": protB64, "payload": payB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", "idleleo-go-acme/1.0")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, nil, err
	}
	if resp.StatusCode >= 400 {
		var p problem
		if json.Unmarshal(raw, &p) == nil && p.Type != "" {
			return resp, nil, &p
		}
		return resp, nil, fmt.Errorf("acme %s: http %d: %s", url, resp.StatusCode, raw)
	}
	return resp, raw, nil
}

func (c *client) nextNonce() (string, error) {
	if c.nonce != "" {
		return c.nonce, nil
	}
	req, err := http.NewRequest(http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("newNonce returned no Replay-Nonce")
	}
	return n, nil
}

func isProblem(err error, typ string) bool {
	p, ok := err.(*problem)
	return ok && p.Type == typ
}

func publicJWK(pub *ecdsa.PublicKey) map[string]string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]string{
		"crv": "P-256", "kty": "EC",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

func jwkThumbprint(jwk map[string]string) string {
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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

func writeCertificate(path string, chain []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, chain, 0o644)
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
