package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
)

// acmeIssueFn and acmeRenewFn are variables so tests can verify directory
// resolution without contacting a CA.
var (
	acmeIssueFn = acme.Issue
	acmeRenewFn = acme.Renew
)

// xrayCert implements `xray cert issue|renew`. The directory defaults to Let's
// Encrypt staging; production requires --production or IDLELEO_ACME_DIRECTORY.
func xrayCert(ctx context.Context, opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	action, rest := args[0], args[1:]
	switch action {
	case "issue", "renew":
	default:
		return usage(opts, cfg.lang, "help")
	}

	domain := flagValue(rest, "--domain")
	webroot := flagValue(rest, "--webroot")
	certFile := flagValue(rest, "--cert-out")
	keyFile := flagValue(rest, "--key-out")
	directory := flagValue(rest, "--directory")
	if directory == "" {
		directory = os.Getenv("IDLELEO_ACME_DIRECTORY")
	}
	if directory == "" {
		if hasFlag(rest, "--production") {
			directory = schedule.ACMEProductionDirectory
		} else {
			directory = schedule.ACMEStagingDirectory
		}
	}
	if domain == "" || webroot == "" || certFile == "" || keyFile == "" {
		return usage(opts, cfg.lang, "help")
	}
	if cfg.root != "/" {
		return usage(opts, cfg.lang, "help")
	}

	accountKey := flagValue(rest, "--account-key")
	stateFile := flagValue(rest, "--state")
	if accountKey == "" {
		accountKey = filepath.Join(filepath.Dir(certFile), "acme", "account.key")
	}
	if stateFile == "" {
		stateFile = filepath.Join(filepath.Dir(certFile), "acme", "account.json")
	}
	renewBefore := 720 * time.Hour
	if raw := flagValue(rest, "--renew-before"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fail(opts, cfg, &change.UsageError{Msg: "--renew-before must be a duration such as 720h"})
		}
		renewBefore = d
	}

	spec := acme.Config{
		DirectoryURL:   directory,
		CACertFile:     flagValue(rest, "--ca-cert"),
		Insecure:       hasFlag(rest, "--insecure-skip-verify"),
		Email:          flagValue(rest, "--email"),
		Domain:         domain,
		Webroot:        webroot,
		CertFile:       certFile,
		KeyFile:        keyFile,
		AccountKeyFile: accountKey,
		StateFile:      stateFile,
		RenewBefore:    renewBefore,
		Force:          hasFlag(rest, "--force"),
		ReloadCommand:  flagValue(rest, "--reload-command"),
	}
	var (
		result acme.Result
		err    error
	)
	if action == "renew" {
		result, err = acmeRenewFn(ctx, spec)
	} else {
		result, err = acmeIssueFn(ctx, spec)
	}
	if err != nil {
		return fail(opts, cfg, err)
	}
	cfg.json = cfg.json || hasFlag(rest, "--json")
	if cfg.json {
		return writeJSON(opts, result)
	}
	state := "issued"
	switch {
	case result.Skipped:
		state = "skipped"
	case result.Issued:
		state = "issued"
	}
	fmt.Fprintf(opts.Out, "cert %s: domain=%s state=%s notAfter=%s\n", action, result.Domain, state, result.NotAfter)
	fmt.Fprintf(opts.Out, "certificate: %s\nkey: %s\n", result.Certificate, result.Key)
	fmt.Fprintf(opts.Out, "account: %s\n", result.AccountURL)
	if result.OrderURL != "" {
		fmt.Fprintf(opts.Out, "order: %s\n", result.OrderURL)
	}
	if result.Reason != "" {
		fmt.Fprintf(opts.Out, "reason: %s\n", result.Reason)
	}
	if result.Reloaded {
		fmt.Fprintln(opts.Out, "reload: done")
	}
	return 0
}
