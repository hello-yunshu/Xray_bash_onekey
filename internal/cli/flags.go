package cli

import (
	"fmt"
	"strings"
)

// flagSpec is the accepted flag vocabulary for one command path. Names are
// stored without leading dashes. Value flags consume the following argument so
// a value that happens to start with "-" is not mistaken for an unknown flag.
type flagSpec struct {
	values []string
	bools  []string
}

func (s flagSpec) allowed(name string) (takesValue, ok bool) {
	for _, v := range s.values {
		if v == name {
			return true, true
		}
	}
	for _, b := range s.bools {
		if b == name {
			return false, true
		}
	}
	return false, false
}

// checkUnknown returns the first token that looks like a flag but is not part
// of this command's vocabulary, or "" when every token is accepted. Both
// -name and --name are accepted (legacy callers use both), a bare "--" ends
// option parsing, and --name=value is validated by name only.
func (s flagSpec) checkUnknown(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return ""
		}
		name, _, hasInline, isFlag := splitFlagToken(a)
		if !isFlag {
			continue
		}
		takesValue, ok := s.allowed(name)
		if !ok {
			return a
		}
		if hasInline {
			continue
		}
		if takesValue && i+1 < len(args) {
			i++ // consume the value, even when it starts with "-"
		}
	}
	return ""
}

// splitFlagToken normalises -name / --name / --name=value. A bare "-" or "--"
// is not a flag token.
func splitFlagToken(a string) (name, inline string, hasInline, isFlag bool) {
	if a == "-" || a == "--" || !strings.HasPrefix(a, "-") {
		return "", "", false, false
	}
	name = strings.TrimPrefix(a, "-")
	name = strings.TrimPrefix(name, "-")
	if name == "" {
		return "", "", false, false
	}
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		return name[:eq], name[eq+1:], true, true
	}
	return name, "", false, true
}

// specOf builds a spec whose every command also accepts the shared output
// flags, so specs only enumerate their own vocabulary.
func specOf(values []string, bools ...string) flagSpec {
	shared := append([]string{"json", "help"}, bools...)
	return flagSpec{values: values, bools: shared}
}

// installSpecValues are the deployment plan flags shared by `xray install` and
// `xray generate`.
var installSpecValues = []string{
	"mode", "transport", "domain", "target", "path", "service-name",
	"uuid", "email", "flow", "private-key", "short-id", "role",
	"unknown-sni-policy", "backend", "listen", "port", "public-port",
	"server-names", "cert", "cert-key",
}

// commandFlags is the whitelist used to reject misspelled flags instead of
// silently ignoring them. Keys are the exact command paths that own flags.
var commandFlags = map[string]flagSpec{
	"status":         specOf(nil),
	"show":           specOf([]string{"path"}),
	"config inspect": specOf([]string{"path"}),
	"change set-inbound-port": specOf(
		[]string{"sandbox", "port", "inbound", "validator", "service", "fault", "path"},
		"container"),
	"change recover": specOf(nil, "container"),

	"xray generate": specOf(
		append(append([]string{}, installSpecValues...), "out", "nginx-out", "fragments-out", "from-config"),
		"force", "allow-non-loopback"),
	"xray install": specOf(
		append(append([]string{}, installSpecValues...), "binary", "nginx-bin", "local-ip"),
		"keep-config", "rewrite-config", "external-nginx-managed", "no-service", "container", "allow-non-loopback"),
	"xray uninstall": specOf(nil, "purge", "keep-nginx-conf", "container"),
	"xray recover":   specOf(nil, "container"),
	"xray share":     specOf([]string{"path", "inbound", "public-port", "host", "public-security", "user"}),
	"xray relay":     specOf([]string{"target", "listen-port", "listen-address", "out"}, "force"),
	"xray user list": specOf([]string{"path", "inbound"}),
	"xray user add": specOf(
		[]string{"inbound", "sandbox", "validator", "service", "uuid", "email", "flow", "short-id", "level", "path", "fault"},
		"container"),
	"xray user remove": specOf(
		[]string{"inbound", "sandbox", "validator", "service", "uuid", "email", "flow", "short-id", "level", "path", "fault"},
		"container"),
	"xray cert issue": specOf(
		[]string{"domain", "webroot", "cert-out", "key-out", "directory", "account-key", "state", "renew-before", "ca-cert", "email", "reload-command"},
		"production", "insecure-skip-verify", "force"),
	"xray cert renew": specOf(
		[]string{"domain", "webroot", "cert-out", "key-out", "directory", "account-key", "state", "renew-before", "ca-cert", "email", "reload-command"},
		"production", "insecure-skip-verify", "force"),

	"bridge audit":      specOf(nil, "summary"),
	"bridge prepare":    specOf([]string{"candidate", "candidate-manifest", "recovery", "fault"}, "acknowledge-custom", "container"),
	"bridge validate":   specOf([]string{"xray", "nginx"}, "container"),
	"bridge activate":   specOf([]string{"crontab", "fault"}, "container"),
	"bridge recover":    specOf(nil, "container"),
	"bridge deactivate": specOf([]string{"export"}, "container"),
	"bridge status":     specOf(nil),
	"recover":           specOf(nil, "container"),

	"metadata import": specOf([]string{"from"}, "container"),
	"metadata export": specOf([]string{"out"}),

	"schedule install": specOf(
		[]string{"interval", "acme-directory", "geodata-url", "cert-domain", "cert-webroot", "cert-out", "cert-key-out", "acme-email", "alert-webhook"},
		"acme-production", "container"),
	"schedule remove": specOf(nil, "container"),
	"schedule run":    specOf([]string{"jobs", "job"}),
	"schedule alert":  specOf([]string{"job", "detail"}),
	"schedule status": specOf(nil),

	"update status":    specOf(nil),
	"update check":     specOf([]string{"manifest-url"}),
	"update configure": specOf([]string{"manifest-url", "install-path"}, "container"),
	"update apply":     specOf([]string{"manifest-url"}, "container"),

	"stats": specOf([]string{"path", "pattern", "timeout"}),

	"service status":  specOf([]string{"unit"}),
	"service start":   specOf([]string{"unit"}, "container"),
	"service stop":    specOf([]string{"unit"}, "container"),
	"service restart": specOf([]string{"unit"}, "container"),
	"service reload":  specOf([]string{"unit"}, "container"),
	"service logs":    specOf([]string{"unit", "lines"}),

	"tcp status":   specOf(nil),
	"tcp plan":     specOf([]string{"profile"}),
	"tcp apply":    specOf([]string{"profile"}, "confirm"),
	"tcp rollback": specOf(nil),

	"speedtest":   specOf([]string{"server", "bytes", "samples", "timeout"}),
	"rill status": specOf(nil),
}

// checkFlags validates args against the command whitelist. ok is false when the
// key is not a known command path, so the caller keeps its existing usage path.
func checkFlags(opts Options, cfg config, args []string, key string) (rc int, ok bool) {
	spec, known := commandFlags[key]
	if !known {
		return 0, false
	}
	if bad := spec.checkUnknown(args); bad != "" {
		fmt.Fprintf(opts.Err, "unknown flag: %s\n", bad)
		return 2, true
	}
	return 0, true
}
