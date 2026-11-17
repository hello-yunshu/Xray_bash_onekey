package cli

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/acme"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
)

// acmeIssueFn, acmeRenewFn and acmePreflightFn are variables so tests can
// verify flow decisions without contacting a CA.
var (
	acmeIssueFn     = acme.Issue
	acmeRenewFn     = acme.Renew
	acmePreflightFn = acme.Preflight
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
	explicitDirectory := flagValue(rest, "--directory")
	if explicitDirectory == "" {
		explicitDirectory = os.Getenv("IDLELEO_ACME_DIRECTORY")
	}
	production := hasFlag(rest, "--production")
	takeover := hasFlag(rest, "--takeover")
	directory := explicitDirectory
	if directory == "" {
		if production {
			directory = acme.ProductionDirectory
		} else {
			directory = acme.StagingDirectory
		}
	}
	if domain == "" || webroot == "" || certFile == "" || keyFile == "" {
		return usage(opts, cfg.lang, "help")
	}
	if cfg.root != "/" {
		return usage(opts, cfg.lang, "help")
	}

	accountDir := flagValue(rest, "--account-dir")
	if accountDir == "" {
		accountDir = acme.DefaultAccountDir
	}
	accountKey := flagValue(rest, "--account-key")
	stateFile := flagValue(rest, "--state")
	if accountKey == "" {
		accountKey = filepath.Join(accountDir, "account.key")
	}
	if stateFile == "" {
		stateFile = filepath.Join(accountDir, "account.json")
	}
	certGroup := flagValue(rest, "--cert-group")
	if certGroup == "" {
		certGroup = defaultNginxCertGroup(certFile)
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
		CertGroup:      certGroup,
		Takeover:       takeover,
	}

	cfg.json = cfg.json || hasFlag(rest, "--json")
	if action == "renew" && hasFlag(rest, "--dry-run") {
		ins, err := acme.Inspect(certFile, renewBefore)
		if err != nil {
			return fail(opts, cfg, err)
		}
		ins.Domain = domain
		ins.Key = keyFile
		if cfg.json {
			return writeJSON(opts, ins)
		}
		state := "not-due"
		switch {
		case ins.Missing:
			state = "missing"
		case ins.UserManaged:
			state = "user-managed"
		case ins.Due:
			state = "due"
		}
		fmt.Fprintf(opts.Out, "cert renew (dry-run): domain=%s state=%s\n", domain, state)
		fmt.Fprintf(opts.Out, "certificate: %s\nkey: %s\n", certFile, keyFile)
		if ins.NotAfter != "" {
			fmt.Fprintf(opts.Out, "notAfter: %s\n", ins.NotAfter)
		}
		if ins.RenewAt != "" {
			fmt.Fprintf(opts.Out, "renewAt: %s\n", ins.RenewAt)
		}
		fmt.Fprintf(opts.Out, "renewBefore: %s\n", ins.RenewBefore)
		fmt.Fprintf(opts.Out, "challenge: http-01 (webroot %s)\n", webroot)
		fmt.Fprintf(opts.Out, "directory: %s\n", directory)
		reload := "none (idleleo schedule reloads services after renewal)"
		if spec.ReloadCommand != "" {
			reload = "configured"
		}
		fmt.Fprintf(opts.Out, "reload: %s\n", reload)
		if ins.Reason != "" {
			fmt.Fprintf(opts.Out, "reason: %s\n", ins.Reason)
		}
		return 0
	}

	// Mirror the acme.sh flow the Bash installer used: validate against staging
	// and only then consume production quota. An explicit --directory (including
	// the Pebble test harness) opts out because the caller already chose the CA.
	// A user-managed certificate without --takeover is refused by Issue itself,
	// so probing staging first would only burn a round trip.
	userManaged := acme.IsUserManaged(certFile) && !takeover
	if action == "issue" && production && explicitDirectory == "" &&
		!hasFlag(rest, "--no-staging-check") && !userManaged {
		if err := acmePreflightFn(ctx, spec); err != nil {
			return fail(opts, cfg, fmt.Errorf("staging preflight failed: %w", err))
		}
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

// defaultNginxCertGroup enables the layered permission model only for the
// managed certificate directory and only when its worker group exists. A
// manual issuance into another directory keeps standalone 0644/0600 modes.
func defaultNginxCertGroup(certFile string) string {
	if filepath.Clean(filepath.Dir(certFile)) != acme.ManagedCertDir {
		return ""
	}
	const group = "idleleo-nginx"
	if _, err := user.LookupGroup(group); err != nil {
		return ""
	}
	return group
}
