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
	"github.com/hello-yunshu/Xray_bash_onekey/internal/schedule"
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
	Alerts        []schedule.Alert     `json:"alerts,omitempty"`
	// AlertsUnreadable marks a read failure rather than an empty alert list, so
	// a script can tell "nothing wrong" apart from "the alert store is broken".
	AlertsUnreadable bool   `json:"alertsUnreadable,omitempty"`
	AlertsError      string `json:"alertsError,omitempty"`
}

// ConfigStatus is the runtime config fingerprint comparison.
type ConfigStatus struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	MatchesMetadata bool   `json:"matchesMetadata"`
}

// Status never writes and never contacts an update server.
func (a *App) Status(ctx context.Context) (StatusReport, error) {
	// Alerts are loaded first and attached to every return path so a failed
	// renewal stays visible even when metadata or config cannot be read.
	alerts, alertsErr := schedule.Alerts(a.Paths.Root)
	withAlerts := func(r StatusReport) StatusReport {
		r.Alerts = alerts
		if alertsErr != nil {
			r.AlertsUnreadable = true
			r.AlertsError = alertsErr.Error()
		}
		return r
	}
	meta, _, err := store.LoadMetadata(a.Paths)
	if err != nil {
		return withAlerts(StatusReport{SchemaVersion: 1, Installed: false}), err
	}
	path, err := a.runtimePath(meta)
	if err != nil {
		return withAlerts(StatusReport{SchemaVersion: 1, Installed: true}), err
	}
	report := StatusReport{
		SchemaVersion: 1, Installed: true, Engine: meta.ActiveEngine,
		Role: meta.Role, TLS: meta.TLS, Transport: meta.Transport,
		Config:  ConfigStatus{Path: path},
		Service: runtime.InspectServices(ctx, a.Paths.Root),
		Drift:   []string{}, Warnings: []string{}, Alerts: alerts,
	}
	if alertsErr != nil {
		report.AlertsUnreadable = true
		report.AlertsError = alertsErr.Error()
	}
	// Relay installations have no Xray runtime config; status must still work
	// so the bridge can pre-validate a converted relay metadata.
	if meta.RuntimeSHA256 == "" {
		report.Warnings = append(report.Warnings, "metadata-has-no-runtime-sha")
		return report, nil
	}
	view, err := store.LoadConfig(path)
	if err != nil {
		return withAlerts(StatusReport{SchemaVersion: 1, Installed: true}), err
	}
	report.Config.SHA256 = view.SHA256
	if meta.RuntimeSHA256 != view.SHA256 {
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

// ChangePort changes one inbound port.
//
// Both a disposable sandbox and the real root are allowed, but the gate is
// different: a sandbox still needs its marker, while the real root needs a Go
// metadata record whose runtime fingerprint matches the current config. The
// sandbox path is byte-for-byte the old behaviour.
func (a *App) ChangePort(ctx context.Context, override string, inbound, port int, validatorPath, servicePath, fault string, containerAck bool) (change.Entry, error) {
	if err := a.beginSystemChange(fault, containerAck); err != nil {
		return change.Entry{}, err
	}
	if a.Paths.Root == "/" {
		if err := a.requireManagerMetadata(); err != nil {
			return change.Entry{}, err
		}
	}
	path, err := store.ResolveRuntimePath(a.Paths, override)
	if err != nil {
		return change.Entry{}, err
	}
	if err := a.requireChangeBaseline(path); err != nil {
		return change.Entry{}, err
	}
	req := change.Request{
		Target:    path,
		Mutate:    func(raw []byte) ([]byte, error) { return change.SetInboundPort(raw, inbound, port) },
		Validator: runtime.XrayValidator{Path: validatorPath},
		Service:   runtime.CommandService{Path: servicePath},
		Journal:   change.Journal{Path: a.Paths.JournalFile()},
		LockPath:  a.Paths.LockFile(),
		Fault:     fault,
		Finalize:  a.refreshRuntimeSHA,
	}
	entry, err := change.Apply(ctx, req)
	return entry, err
}

// ChangeUser adds or removes one VLESS client through the same atomic
// transaction as ChangePort. The gate and the metadata drift check are
// identical.
func (a *App) ChangeUser(ctx context.Context, override string, inbound int, add bool, ident string, spec xraycfg.AddUserSpec, validatorPath, servicePath, fault string, containerAck bool) (change.Entry, xraycfg.UserView, error) {
	if err := a.beginSystemChange(fault, containerAck); err != nil {
		return change.Entry{}, xraycfg.UserView{}, err
	}
	if a.Paths.Root == "/" {
		if err := a.requireManagerMetadata(); err != nil {
			return change.Entry{}, xraycfg.UserView{}, err
		}
	}
	path, err := store.ResolveRuntimePath(a.Paths, override)
	if err != nil {
		return change.Entry{}, xraycfg.UserView{}, err
	}
	if err := a.requireChangeBaseline(path); err != nil {
		return change.Entry{}, xraycfg.UserView{}, err
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
		// The committed config is now ours, so the ownership fingerprint must
		// move with it. Otherwise the next transaction would see self-inflicted
		// drift - and a fingerprint that cannot move must roll the config back.
		Finalize: a.refreshRuntimeSHA,
	}
	entry, err := change.Apply(ctx, req)
	if err != nil {
		return entry, xraycfg.UserView{}, err
	}
	return entry, view, nil
}

// beginSystemChange applies the write gate to every root. For a disposable
// sandbox this is exactly the old marker check; for the real root it requires
// the container acknowledgement on a container host and writes the audit line
// before the transaction starts. Failure injection stays sandbox-only.
func (a *App) beginSystemChange(fault string, containerAck bool) error {
	if err := host.RequireSystemWrite(a.Paths.Root, containerAck); err != nil {
		return &change.UsageError{Msg: err.Error()}
	}
	if fault != "" && a.Paths.Root == "/" {
		return &change.UsageError{Msg: "failure injection (--fault) is only available in a marked sandbox"}
	}
	return nil
}

// requireManagerMetadata proves, before any path resolution, that the Go
// manager owns this real root. It runs first so an uninstalled host gets an
// ownership error instead of a confusing missing-directory error.
func (a *App) requireManagerMetadata() error {
	meta, _, err := store.LoadMetadata(a.Paths)
	if err != nil {
		var se *store.Error
		if errors.As(err, &se) && se.Kind == store.KindNotFound {
			return &store.Error{Kind: store.KindNotFound, Msg: "real-root changes require manager metadata"}
		}
		return err
	}
	if meta.RuntimeSHA256 == "" {
		return &store.Error{Kind: store.KindUnsupported, Msg: "real-root changes require metadata with runtimeSha256"}
	}
	return nil
}

// requireChangeBaseline refuses a stale or unowned baseline. A disposable
// sandbox may run without metadata (isolated samples); the real root may not:
// only a metadata record with a matching runtime fingerprint proves that the
// Go manager owns this config.
func (a *App) requireChangeBaseline(path string) error {
	realRoot := a.Paths.Root == "/"
	meta, _, metaErr := store.LoadMetadata(a.Paths)
	if metaErr != nil {
		var se *store.Error
		if !errors.As(metaErr, &se) || se.Kind != store.KindNotFound {
			return metaErr
		}
		if realRoot {
			return &store.Error{Kind: store.KindNotFound, Msg: "real-root changes require manager metadata"}
		}
		return nil
	}
	if meta.RuntimeSHA256 == "" {
		if realRoot {
			return &store.Error{Kind: store.KindUnsupported, Msg: "real-root changes require metadata with runtimeSha256"}
		}
		return nil
	}
	snap, err := store.ReadRuntimeSnapshot(path)
	if err != nil {
		return err
	}
	if snap.SHA != meta.RuntimeSHA256 {
		return &store.Error{Kind: store.KindDrift, Msg: "runtime config differs from metadata sha256"}
	}
	return nil
}

// refreshRuntimeSHA updates only the metadata fingerprint after a successful
// commit. It never creates metadata for isolated samples, but any failure on a
// root that does own metadata is returned so the transaction rolls back.
func (a *App) refreshRuntimeSHA(sha string) error {
	if sha == "" {
		return nil
	}
	p, err := a.Paths.Join(a.Paths.ManagerMetadata(), false)
	if err != nil {
		return err
	}
	fi, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
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
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
