package acme

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

// legoUser adapts the account key and registration URL kept on disk to the
// registration.User interface lego expects. The account key stays in our own
// PEM file (0600) so an existing installation keeps its account identity.
type legoUser struct {
	email string
	key   crypto.Signer
	reg   *legoacme.ExtendedAccount
}

func (u *legoUser) GetEmail() string                           { return u.email }
func (u *legoUser) GetRegistration() *legoacme.ExtendedAccount { return u.reg }
func (u *legoUser) GetPrivateKey() crypto.Signer               { return u.key }

// webrootProvider serves HTTP-01 tokens from an externally managed webroot.
// The token is validated with the same base64url alphabet rule D-018 requires
// before it is joined into a path, so a hostile CA response can never traverse
// directories.
type webrootProvider struct {
	root string
}

func (p *webrootProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	if !validToken(token) {
		return fmt.Errorf("CA returned an unsafe http-01 token %q", token)
	}
	path := filepath.Join(p.root, filepath.FromSlash(strings.TrimPrefix(wellKnownPath, "/")), token)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(keyAuth), 0o644)
}

func (p *webrootProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	if !validToken(token) {
		return nil
	}
	path := filepath.Join(p.root, filepath.FromSlash(strings.TrimPrefix(wellKnownPath, "/")), token)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// newLegoClient builds a lego client for cfg and restores (or creates) the ACME
// account. Registration is the only protocol step kept here; issuance is driven
// by obtainWithLego.
func newLegoClient(ctx context.Context, cfg Config) (*lego.Client, error) {
	key, err := loadOrCreateAccountKey(cfg.AccountKeyFile)
	if err != nil {
		return nil, err
	}
	pool, err := rootPool(cfg.CACertFile, cfg.Insecure)
	if err != nil {
		return nil, err
	}
	user := &legoUser{email: cfg.Email, key: key}
	if kid := readAccountURL(cfg.StateFile, cfg.DirectoryURL); kid != "" {
		user.reg = &legoacme.ExtendedAccount{Location: kid}
	}
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.DirectoryURL
	legoCfg.Certificate.Timeout = 60 * time.Second
	legoCfg.HTTPClient = &http.Client{
		Timeout: defaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: cfg.Insecure},
		},
	}
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, err
	}
	if user.reg == nil {
		account, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, err
		}
		if account.Location == "" {
			return nil, fmt.Errorf("newAccount did not return an account URL")
		}
		user.reg = account
		if err := writeAccountURL(cfg.StateFile, cfg.DirectoryURL, account.Location); err != nil {
			return nil, err
		}
	}
	if err := client.Challenge.SetHTTP01Provider(&webrootProvider{root: cfg.Webroot}); err != nil {
		return nil, err
	}
	return client, nil
}

// obtainWithLego runs the ACME order through lego and returns the issued chain
// and private key as PEM. Installing them atomically remains our responsibility.
func obtainWithLego(ctx context.Context, client *lego.Client, domain string) (*certificate.Resource, error) {
	return client.Certificate.Obtain(ctx, certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
		KeyType: certcrypto.EC256,
	})
}

func readAccountURL(stateFile, directoryURL string) string {
	if stateFile == "" {
		return ""
	}
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		return ""
	}
	var st struct {
		DirectoryURL string `json:"directoryUrl"`
		AccountURL   string `json:"accountUrl"`
	}
	if json.Unmarshal(raw, &st) != nil || st.DirectoryURL != directoryURL {
		return ""
	}
	return st.AccountURL
}

func writeAccountURL(stateFile, directoryURL, accountURL string) error {
	if stateFile == "" {
		return nil
	}
	st := map[string]string{"directoryUrl": directoryURL, "accountUrl": accountURL}
	raw, _ := json.MarshalIndent(st, "", "  ")
	if err := os.MkdirAll(filepath.Dir(stateFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(stateFile, append(raw, '\n'), 0o600)
}

// compile-time guard: the adapter must keep satisfying lego's User interface.
var _ registration.User = (*legoUser)(nil)
