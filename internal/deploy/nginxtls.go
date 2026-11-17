package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
)

// TLS version choices accepted by `xray tls`. Bash offers the same two
// variants interactively: TLSv1.3 only (default) and TLSv1.2+ compatibility
// for the Reality stream map.
const (
	TLSVersion13     = "1.3"
	TLSVersion12Plus = "1.2+"
)

// tlsProtocolDirective matches the `ssl_protocols ...;` line of a managed TLS
// server block, keeping the indentation and the spacing after the keyword.
var tlsProtocolDirective = regexp.MustCompile(`(?m)^([ \t]*)ssl_protocols([ \t]+)([^;\n]*);`)

// tls12Active and tls12Comment match the two states Bash toggles with sed in
// the Reality `$ssl_preread_protocol` map.
var (
	tls12Active  = regexp.MustCompile(`(?m)^([ \t]*)TLSv1\.2([ \t]+)1;`)
	tls12Comment = regexp.MustCompile(`(?m)^([ \t]*)#TLSv1\.2([ \t]+)1;`)
)

// TLSSpec is one TLS version request against a managed Nginx front.
type TLSSpec struct {
	Root                 string
	AllowContainerWrites bool
	// Version is "1.3" or "1.2+".
	Version string
}

// TLSReport is the machine-readable result.
type TLSReport struct {
	Mode     string   `json:"mode"`
	Version  string   `json:"version"`
	Changed  bool     `json:"changed"`
	File     string   `json:"file,omitempty"`
	Reloaded bool     `json:"reloaded"`
	Warnings []string `json:"warnings"`
}

// SetTLSVersion changes the managed Nginx TLS version and validates the result
// with the real binary. Bash rewrites the file with sed and restarts both
// services without a rollback; here a failed `nginx -t` or reload restores the
// previous file.
func SetTLSVersion(ctx context.Context, spec TLSSpec) (TLSReport, error) {
	rep := TLSReport{Version: spec.Version, Warnings: []string{}}
	if spec.Version != TLSVersion13 && spec.Version != TLSVersion12Plus {
		return rep, fmt.Errorf("TLS version must be %q or %q", TLSVersion13, TLSVersion12Plus)
	}
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return rep, err
	}
	meta, _, err := store.LoadMetadata(paths)
	if err != nil {
		return rep, err
	}
	rep.Mode = meta.TLS
	if meta.TLS != "TLS" && meta.TLS != "Reality" {
		return rep, fmt.Errorf("the current install mode %q has no managed Nginx TLS front", meta.TLS)
	}
	if meta.TLS == "TLS" && spec.Version == TLSVersion12Plus {
		return rep, fmt.Errorf("TLS mode serves h3/quic, which requires TLS 1.3; TLSv1.2 cannot be enabled")
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return rep, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return rep, err
	}
	defer lock.Release()

	dir, err := paths.Join(nginxDirRel, false)
	if err != nil {
		return rep, fmt.Errorf("this install is not a managed Nginx front: %w", err)
	}
	target, original, err := findTLSConfig(dir, meta.TLS)
	if err != nil {
		return rep, err
	}
	rep.File = target

	var updated string
	var changed bool
	if meta.TLS == "TLS" {
		updated, changed = setTLSProtocols(original)
	} else {
		updated, changed = setRealityTLS12(original, spec.Version == TLSVersion12Plus)
	}
	if !changed {
		return rep, nil
	}

	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(target); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := writeFileAtomic(target, []byte(updated), mode); err != nil {
		return rep, err
	}
	if err := balanceNginxTest(ctx, paths.Root); err != nil {
		_ = writeFileAtomic(target, []byte(original), mode)
		return rep, fmt.Errorf("%w; the TLS setting was restored", err)
	}
	rep.Changed = true
	if err := balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings); err != nil {
		_ = writeFileAtomic(target, []byte(original), mode)
		if testErr := balanceNginxTest(ctx, paths.Root); testErr == nil {
			_ = balanceReloadWithReport(ctx, paths.Root, &rep.Reloaded, &rep.Warnings)
		}
		return rep, fmt.Errorf("%w; the TLS setting was restored", err)
	}
	return rep, nil
}

// findTLSConfig returns the managed file that owns the TLS version. TLS
// installs keep `ssl_protocols` in the server block; Reality installs keep the
// `$ssl_preread_protocol` map in the stream block. A front that owns neither is
// refused instead of guessed.
func findTLSConfig(dir, mode string) (string, string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", fmt.Errorf("this install is not a managed Nginx front: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".conf") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", "", readErr
		}
		text := string(body)
		if mode == "TLS" && tlsProtocolDirective.MatchString(text) {
			return path, text, nil
		}
		if mode == "Reality" && strings.Contains(text, "$ssl_preread_protocol") &&
			(tls12Active.MatchString(text) || tls12Comment.MatchString(text)) {
			return path, text, nil
		}
	}
	if mode == "TLS" {
		return "", "", fmt.Errorf("this install is not a managed Nginx front: no ssl_protocols directive under %s", dir)
	}
	return "", "", fmt.Errorf("this install is not a managed Nginx front: no $ssl_preread_protocol map under %s", dir)
}

// setTLSProtocols pins a TLS server block to TLSv1.3, keeping the indentation
// and the spacing Bash's sed preserves.
func setTLSProtocols(text string) (string, bool) {
	loc := tlsProtocolDirective.FindStringSubmatchIndex(text)
	if loc == nil {
		return text, false
	}
	current := strings.TrimSpace(text[loc[6]:loc[7]])
	if current == "TLSv1.3" {
		return text, false
	}
	replacement := text[loc[2]:loc[3]] + "ssl_protocols" + text[loc[4]:loc[5]] + "TLSv1.3;"
	return text[:loc[0]] + replacement + text[loc[1]:], true
}

// setRealityTLS12 toggles the `TLSv1.2 1;` map entry Bash edits with sed.
func setRealityTLS12(text string, enable bool) (string, bool) {
	if enable {
		loc := tls12Comment.FindStringSubmatchIndex(text)
		if loc == nil {
			return text, false
		}
		replacement := text[loc[2]:loc[3]] + "TLSv1.2" + text[loc[4]:loc[5]] + "1;"
		return text[:loc[0]] + replacement + text[loc[1]:], true
	}
	loc := tls12Active.FindStringSubmatchIndex(text)
	if loc == nil {
		return text, false
	}
	replacement := text[loc[2]:loc[3]] + "#TLSv1.2" + text[loc[4]:loc[5]] + "1;"
	return text[:loc[0]] + replacement + text[loc[1]:], true
}

// balanceReloadWithReport is balanceReload with the report fields the TLS
// command exposes.
func balanceReloadWithReport(ctx context.Context, root string, reloaded *bool, warnings *[]string) error {
	if !serviceManaged(root) {
		*warnings = append(*warnings, "managed nginx service is not managed on this root; reload skipped, run 'systemctl reload nginx' manually")
		return nil
	}
	if err := serviceCommand(ctx, "reload", "nginx"); err != nil {
		return fmt.Errorf("reload nginx: %w", err)
	}
	*reloaded = true
	return nil
}
