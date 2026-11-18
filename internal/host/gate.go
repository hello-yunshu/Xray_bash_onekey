package host

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteAuditRel is the append-only record of real-root write approvals.
const WriteAuditRel = "var/log/idleleo/system-writes.log"

// containerMarkers is a variable so tests can simulate both sides of the
// boundary without changing the production paths.
var containerMarkers = []string{"/.dockerenv", "/run/.containerenv"}

// InContainer reports whether this process runs inside a container. The marker
// must be a regular file: binding an empty directory over it is a supported way
// to simulate a real-host run in tests.
func InContainer() bool {
	for _, marker := range containerMarkers {
		fi, err := os.Stat(marker)
		if err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// RequireSystemWrite gates commands that write outside a disposable sandbox.
//
// A sandbox root must carry the Phase 01 marker. On the real root, container
// runs still require the explicit --container acknowledgement plus the
// IDLELEO_ALLOW_SYSTEM_WRITES environment value; a real host (no container
// marker) is allowed so an actual VPS can migrate, but every such write is
// appended to WriteAuditRel before it proceeds. If the audit trail cannot be
// written, the write is refused.
func RequireSystemWrite(root string, ack bool) error {
	if root != "/" {
		p, err := NewPaths(root)
		if err != nil {
			return err
		}
		return p.RequireSandbox()
	}
	mode, err := writeMode(ack)
	if err != nil {
		return err
	}
	if err := recordWrite(root, mode); err != nil {
		return fmt.Errorf("system write refused: audit trail unavailable: %w", err)
	}
	return nil
}

// recordWrite is a test seam so the audit-trail failure branch can be proven
// without making /var/log unwritable.
var recordWrite = recordSystemWrite

// writeMode decides whether a real-root write is allowed. Container runs need
// both the flag and the environment acknowledgement; a real host does not.
func writeMode(ack bool) (string, error) {
	if !InContainer() {
		return "host", nil
	}
	if !ack {
		return "", errors.New("container root writes require --container")
	}
	if os.Getenv("IDLELEO_ALLOW_SYSTEM_WRITES") != "I_ACCEPT_CONTAINER_ONLY" {
		return "", errors.New("container root writes require IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY")
	}
	return "container", nil
}

// auditPlainFlags is the small allowlist of flag values that carry no secret
// and no operator identity. Everything else is redacted before it reaches the
// audit trail: unknown flags therefore get the protective default.
var auditPlainFlags = map[string]bool{
	"mode": true, "transport": true, "role": true, "port": true, "public-port": true,
	"listen-port": true, "listen": true, "ws-port": true, "grpc-port": true,
	"xhttp-port": true, "inbound": true, "profile": true, "unit": true,
	"upstream": true, "lines": true, "interval": true, "samples": true,
	"bytes": true, "timeout": true, "flow": true, "level": true, "fp": true,
}

// auditBoolFlags never consume the following token as a value.
var auditBoolFlags = map[string]bool{
	"json": true, "help": true, "yes": true, "force": true, "dry-run": true,
	"container": true, "keep-config": true, "rewrite-config": true,
	"external-nginx-managed": true, "no-service": true, "allow-non-loopback": true,
	"purge": true, "keep-nginx-conf": true, "no-restart": true, "no-probe": true,
	"production": true, "insecure-skip-verify": true, "no-staging-check": true,
	"takeover": true, "confirm": true, "short-id-auto": true, "short-id-list": true,
	"rotate-reality-private-key": true, "acknowledge-custom": true, "summary": true,
	"acme-production": true, "no-nginx-no-host": true, "no-nginx-tls-error": true,
	"qr": true, "probe": true, "deep": true,
}

const auditRedacted = "<redacted>"

// auditEvent is the structured record written before a real-root write.
type auditEvent struct {
	Operation   string
	Fingerprint string
	Flags       string
}

// describeAudit builds a structured, redacted view of the current command.
//
// The operation is limited to the leading command words (for example
// "xray install"); flag values are only kept for a small allowlist. The plan
// fingerprint is a one-way hash of the full argv so an operator can still
// correlate an audit line with a shell history entry without storing secrets.
func describeAudit(argv []string) auditEvent {
	var words []string
	var flags []string
	plan := sha256.Sum256([]byte(strings.Join(argv, "\x00")))

	for i := 1; i < len(argv); i++ {
		token := argv[i]
		if token == "--" || token == "-" {
			continue
		}
		if strings.HasPrefix(token, "-") {
			name := strings.TrimLeft(token, "-")
			inline := ""
			hasInline := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				inline, hasInline = name[eq+1:], true
				name = name[:eq]
			}
			name = sanitizeAuditWord(name)
			if name == "" {
				continue
			}
			if auditBoolFlags[name] {
				flags = append(flags, "--"+name)
				continue
			}
			value := inline
			if !hasInline && i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				value = argv[i+1]
				i++
			}
			if value == "" {
				flags = append(flags, "--"+name)
				continue
			}
			if auditPlainFlags[name] {
				flags = append(flags, "--"+name+"="+sanitizeAuditWord(value))
			} else {
				flags = append(flags, "--"+name+"="+auditRedacted)
			}
			continue
		}
		if len(words) < 3 {
			if word := sanitizeAuditWord(token); word != "" {
				words = append(words, word)
			}
		}
	}
	operation := "unknown"
	if len(words) > 0 {
		operation = strings.Join(words, " ")
	}
	return auditEvent{
		Operation:   operation,
		Fingerprint: hex.EncodeToString(plan[:8]),
		Flags:       strings.Join(flags, " "),
	}
}

// sanitizeAuditWord keeps only characters that cannot carry a quoted secret
// payload. Any value outside the set is dropped rather than escaped, so a
// crafted flag cannot smuggle bytes into the log through the allowlist.
func sanitizeAuditWord(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.', r == ':', r == '/', r == ',':
			b.WriteRune(r)
		default:
			return ""
		}
		if b.Len() >= 128 {
			return ""
		}
	}
	return b.String()
}

func recordSystemWrite(root, mode string) error {
	dir := filepath.Join(root, "var/log/idleleo")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(root, WriteAuditRel)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	event := describeAudit(os.Args)
	line := fmt.Sprintf("%s mode=%s operation=%q uid=%d pid=%d plan=%s flags=%q\n",
		time.Now().UTC().Format(time.RFC3339), mode, event.Operation, os.Geteuid(), os.Getpid(),
		event.Fingerprint, event.Flags)
	_, err = f.WriteString(line)
	return err
}
