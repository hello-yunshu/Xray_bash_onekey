// Package app assembles read-only views and the single Phase 01 change.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/compat"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/runtime"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

// App binds one root, language and output mode.
type App struct {
	Paths host.Paths
	Lang  string
}

// StatusReport is the JSON contract for `status`.
type StatusReport struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Installed     bool                 `json:"installed"`
	Engine        string               `json:"engine,omitempty"`
	Role          string               `json:"role,omitempty"`
	TLS           string               `json:"tls,omitempty"`
	Transport     string               `json:"transport,omitempty"`
	Config        ConfigStatus         `json:"config"`
	Service       runtime.ServiceState `json:"service"`
	Drift         []string             `json:"drift"`
	Warnings      []string             `json:"warnings"`
}

// ConfigStatus is the runtime config fingerprint comparison.
type ConfigStatus struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	MatchesMetadata bool   `json:"matchesMetadata"`
}

// Status never writes and never contacts an update server.
func (a *App) Status(ctx context.Context) (StatusReport, error) {
	meta, _, err := store.LoadMetadata(a.Paths)
	if err != nil {
		return StatusReport{SchemaVersion: 1, Installed: false}, err
	}
	path, err := a.runtimePath(meta)
	if err != nil {
		return StatusReport{SchemaVersion: 1, Installed: true}, err
	}
	view, err := store.LoadConfig(path)
	if err != nil {
		return StatusReport{SchemaVersion: 1, Installed: true}, err
	}
	report := StatusReport{
		SchemaVersion: 1, Installed: true, Engine: meta.ActiveEngine,
		Role: meta.Role, TLS: meta.TLS, Transport: meta.Transport,
		Config:  ConfigStatus{Path: path, SHA256: view.SHA256},
		Service: runtime.InspectServices(ctx, a.Paths.Root),
		Drift:   []string{}, Warnings: []string{},
	}
	if meta.RuntimeSHA256 == "" {
		report.Warnings = append(report.Warnings, "metadata-has-no-runtime-sha")
	} else if meta.RuntimeSHA256 != view.SHA256 {
		report.Drift = append(report.Drift, "runtime-config-sha-mismatch")
	} else {
		report.Config.MatchesMetadata = true
	}
	if view.Custom.DNS {
		report.Warnings = append(report.Warnings, "custom-dns-present")
	}
	if view.Custom.Routing {
		report.Warnings = append(report.Warnings, "custom-routing-present")
	}
	return report, nil
}

// ShowReport is the JSON contract for `show`.
type ShowReport struct {
	Path      string              `json:"path,omitempty"`
	SHA256    string              `json:"sha256,omitempty"`
	Authority string              `json:"authority,omitempty"`
	Inbounds  []store.InboundView `json:"inbounds,omitempty"`
	Info      map[string]string   `json:"info,omitempty"`
	Warnings  []string            `json:"warnings"`
}

// Show prefers the legacy info file but never rewrites it.
func (a *App) Show(override string) (ShowReport, error) {
	report := ShowReport{Warnings: []string{}}
	if infoPath, err := a.Paths.Join(a.Paths.InfoFile(), false); err == nil {
		if b, _, err := store.ReadRegular(infoPath, "info file"); err == nil {
			report.Info = parseInfo(string(b))
		}
	}
	path, err := store.ResolveRuntimePath(a.Paths, override)
	if err != nil {
		if report.Info != nil {
			report.Warnings = append(report.Warnings, "runtime-config-missing")
			return report, nil
		}
		return report, err
	}
	view, err := store.LoadConfig(path)
	if err != nil {
		if report.Info != nil {
			report.Warnings = append(report.Warnings, "runtime-config-unreadable")
			return report, nil
		}
		return report, err
	}
	report.Path, report.SHA256, report.Inbounds = view.Path, view.SHA256, view.Inbounds
	if len(view.Inbounds) > 0 {
		listen := view.Inbounds[0].Listen
		if listen == "" {
			listen = "0.0.0.0"
		}
		report.Authority = strings.TrimSpace(compat.FormatURIAuthorityHost(listen))
	}
	return report, nil
}

func parseInfo(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			out[line] = ""
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// Inspect returns the structured read-only config view.
func (a *App) Inspect(override string) (store.ConfigView, error) {
	return store.LoadRuntimeView(a.Paths, override)
}

// ChangePort performs the one isolated Phase 01 change.
func (a *App) ChangePort(ctx context.Context, override string, inbound, port int, validatorPath, servicePath, fault string) (change.Entry, error) {
	if err := a.Paths.RequireSandbox(); err != nil {
		return change.Entry{}, &change.UsageError{Msg: err.Error()}
	}
	path, err := store.ResolveRuntimePath(a.Paths, override)
	if err != nil {
		return change.Entry{}, err
	}
	// Refuse a stale baseline before staging anything. A missing metadata file
	// is allowed for isolated samples; a mismatching SHA is never allowed.
	meta, _, metaErr := store.LoadMetadata(a.Paths)
	if metaErr == nil && meta.RuntimeSHA256 != "" {
		snap, err := store.ReadRuntimeSnapshot(path)
		if err != nil {
			return change.Entry{}, err
		}
		if snap.SHA != meta.RuntimeSHA256 {
			return change.Entry{}, &store.Error{Kind: store.KindDrift, Msg: "runtime config differs from metadata sha256"}
		}
	} else if metaErr != nil {
		var se *store.Error
		if !errors.As(metaErr, &se) || se.Kind != store.KindNotFound {
			return change.Entry{}, metaErr
		}
	}
	req := change.Request{
		Target:    path,
		Mutate:    func(raw []byte) ([]byte, error) { return change.SetInboundPort(raw, inbound, port) },
		Validator: runtime.XrayValidator{Path: validatorPath},
		Service:   runtime.CommandService{Path: servicePath},
		Journal:   change.Journal{Path: a.Paths.JournalFile()},
		LockPath:  a.Paths.LockFile(),
		Fault:     fault,
	}
	entry, err := change.Apply(ctx, req)
	if err != nil {
		return entry, err
	}
	_ = a.refreshRuntimeSHA(entry.NewSHA256)
	return entry, nil
}

// ChangeUser adds or removes one VLESS client through the same atomic
// transaction as ChangePort. The metadata drift check is identical.
func (a *App) ChangeUser(ctx context.Context, override string, inbound int, add bool, ident string, spec xraycfg.AddUserSpec, validatorPath, servicePath, fault string) (change.Entry, xraycfg.UserView, error) {
	if err := a.Paths.RequireSandbox(); err != nil {
		return change.Entry{}, xraycfg.UserView{}, &change.UsageError{Msg: err.Error()}
	}
	path, err := store.ResolveRuntimePath(a.Paths, override)
	if err != nil {
		return change.Entry{}, xraycfg.UserView{}, err
	}
	meta, _, metaErr := store.LoadMetadata(a.Paths)
	if metaErr == nil && meta.RuntimeSHA256 != "" {
		snap, err := store.ReadRuntimeSnapshot(path)
		if err != nil {
			return change.Entry{}, xraycfg.UserView{}, err
		}
		if snap.SHA != meta.RuntimeSHA256 {
			return change.Entry{}, xraycfg.UserView{}, &store.Error{Kind: store.KindDrift, Msg: "runtime config differs from metadata sha256"}
		}
	} else if metaErr != nil {
		var se *store.Error
		if !errors.As(metaErr, &se) || se.Kind != store.KindNotFound {
			return change.Entry{}, xraycfg.UserView{}, metaErr
		}
	}
	var view xraycfg.UserView
	mutate := func(raw []byte) ([]byte, error) {
		if add {
			out, v, err := xraycfg.AddUser(raw, inbound, spec)
			if err != nil {
				return nil, err
			}
			view = v
			return out, nil
		}
		out, v, err := xraycfg.RemoveUser(raw, inbound, ident)
		if err != nil {
			return nil, err
		}
		view = v
		return out, nil
	}
	req := change.Request{
		Target:    path,
		Mutate:    mutate,
		Validator: runtime.XrayValidator{Path: validatorPath},
		Service:   runtime.CommandService{Path: servicePath},
		Journal:   change.Journal{Path: a.Paths.JournalFile()},
		LockPath:  a.Paths.LockFile(),
		Fault:     fault,
	}
	entry, err := change.Apply(ctx, req)
	if err != nil {
		return entry, xraycfg.UserView{}, err
	}
	// The committed config is now ours, so the ownership fingerprint must move
	// with it. Otherwise the next transaction would see self-inflicted drift.
	_ = a.refreshRuntimeSHA(entry.NewSHA256)
	return entry, view, nil
}

// refreshRuntimeSHA updates only the metadata fingerprint after a successful
// commit. It never creates metadata for isolated samples.
func (a *App) refreshRuntimeSHA(sha string) error {
	if sha == "" {
		return nil
	}
	p, err := a.Paths.Join(a.Paths.ManagerMetadata(), false)
	if err != nil {
		return nil
	}
	fi, err := os.Stat(p)
	if err != nil {
		return nil
	}
	meta, _, err := store.LoadMetadata(a.Paths)
	if err != nil {
		return err
	}
	if meta.RuntimeSHA256 == sha {
		return nil
	}
	meta.RuntimeSHA256 = sha
	meta.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, fi.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (a *App) runtimePath(meta store.Metadata) (string, error) {
	if meta.RuntimeConfigPath != "" {
		if err := store.ValidateManagerPath(meta.RuntimeConfigPath); err != nil {
			return "", &store.Error{Kind: store.KindCorrupt, Msg: err.Error()}
		}
		return a.Paths.Join(meta.RuntimeConfigPath, false)
	}
	return a.Paths.Join(a.Paths.RuntimeConfig(), false)
}

// EnsureRootReadable is a small helper for CLI root checks.
func EnsureRootReadable() error {
	if os.Geteuid() == 0 {
		return nil
	}
	return &store.Error{Kind: store.KindPermission, Msg: "root required"}
}
