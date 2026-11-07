package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultTimeout bounds every external validator/service command.
const DefaultTimeout = 10 * time.Second

// MaxOutput keeps validator noise out of logs and UI.
const MaxOutput = 64 * 1024

// FixedPATH is the only search path for external binaries.
const FixedPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// ExecSpec is a shell-free command description.
type ExecSpec struct {
	Path    string
	Args    []string
	Timeout time.Duration
}

// ExecResult captures exit status and bounded, redacted output.
type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	TimedOut bool
}

var secretLine = regexp.MustCompile(`(?i)(privateKey|private_key|shortId|short_id|password|token|uuid|id)\s*[:=]\s*["']?([^\s"',}]+)`)
var privateKeyBlock = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)

// ResolveBinary accepts an absolute executable or a bare name found in the
// fixed PATH. It never consults the caller's PATH.
func ResolveBinary(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("empty executable")
	}
	if strings.Contains(name, "/") {
		if !filepath.IsAbs(name) {
			return "", errors.New("relative executable paths are refused")
		}
		fi, err := os.Stat(name)
		if err != nil {
			return "", err
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&0111 == 0 {
			return "", fmt.Errorf("not an executable file: %s", name)
		}
		return name, nil
	}
	for _, dir := range strings.Split(FixedPATH, ":") {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() && fi.Mode().Perm()&0111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("executable not found in fixed PATH: %s", name)
}

// Run executes without a shell, with timeout and output limits.
func Run(ctx context.Context, spec ExecSpec) (ExecResult, error) {
	bin, err := ResolveBinary(spec.Path)
	if err != nil {
		return ExecResult{}, err
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, spec.Args...)
	cmd.Env = []string{
		"PATH=" + FixedPATH,
		"HOME=/",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}
	var out, errOut limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	res := ExecResult{Stdout: redact(out.String()), Stderr: redact(errOut.String())}
	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res, fmt.Errorf("command timed out after %s", timeout)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

func redact(s string) string {
	s = privateKeyBlock.ReplaceAllString(s, "[REDACTED PRIVATE KEY BLOCK]")
	return secretLine.ReplaceAllString(s, "$1=[REDACTED]")
}

type limitedBuffer struct {
	buf bytes.Buffer
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := MaxOutput - l.buf.Len()
	if room <= 0 {
		return len(p), nil
	}
	if len(p) > room {
		p = p[:room]
	}
	_, _ = l.buf.Write(p)
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.buf.String() }
