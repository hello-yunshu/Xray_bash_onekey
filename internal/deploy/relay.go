package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/store"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

// RelayInstallSpec is one standalone relay installation request. A relay never
// installs Xray; it only runs a managed Nginx stream{} forwarder.
type RelayInstallSpec struct {
	Root                 string
	BackendHost          string
	BackendPort          int
	ListenPort           int
	ListenAddress        string
	LocalIP              string
	NoService            bool
	AllowContainerWrites bool
}

// RelayReport is the machine-readable relay installation result.
type RelayReport struct {
	Role          string   `json:"role"`
	Backend       string   `json:"backend"`
	Listen        string   `json:"listen"`
	ConfigPath    string   `json:"configPath"`
	NginxDir      string   `json:"nginxDir"`
	NginxManaged  bool     `json:"nginxManaged"`
	NginxVerified bool     `json:"nginxVerified"`
	Warnings      []string `json:"warnings"`
}

// InstallRelay installs the managed Nginx front and its relay stream fragment.
// Bash parity: an Xray runtime config means the host already serves as a node,
// so a relay needs a dedicated host.
func InstallRelay(ctx context.Context, spec RelayInstallSpec) (RelayReport, error) {
	rep := RelayReport{Role: "relay", Warnings: []string{}}
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return rep, err
	}
	if err := requireWriteAccess(paths, spec.AllowContainerWrites); err != nil {
		return rep, err
	}
	lock, err := host.AcquireUpdate(paths.LockFile())
	if err != nil {
		return rep, err
	}
	defer lock.Release()
	if _, err := recoverPendingLocked(ctx, paths); err != nil {
		return rep, err
	}

	if spec.BackendHost == "" {
		return rep, fmt.Errorf("relay backend host required")
	}
	if spec.BackendPort < 1 || spec.BackendPort > 65535 {
		return rep, fmt.Errorf("relay backend port must be between 1 and 65535")
	}
	if spec.ListenPort < 1 || spec.ListenPort > 65535 {
		return rep, fmt.Errorf("relay listen port must be between 1 and 65535")
	}
	if spec.ListenAddress == "" {
		spec.ListenAddress = "0.0.0.0"
	}

	configPath, err := paths.Join(configRel, false)
	if err == nil {
		if _, statErr := os.Lstat(configPath); statErr == nil {
			return rep, fmt.Errorf("existing Xray node config %s; a relay requires a dedicated host (bash parity)", configPath)
		}
	} else if !os.IsNotExist(err) {
		return rep, err
	}

	artifact, installedOK := nginx.InstalledArtifact(paths.Root)
	if !installedOK {
		artifact, err = resolveManagedNginx(ctx, nginx.Options{})
		if err != nil {
			return rep, err
		}
	}
	localIP := spec.LocalIP
	if localIP == "" {
		if detected, ipErr := nginx.LocalAddress(ctx); ipErr != nil {
			rep.Warnings = append(rep.Warnings, "managed nginx: local IP detection failed, local-IP 403 guard skipped: "+ipErr.Error())
		} else {
			localIP = detected
		}
	}
	installed, err := installManagedNginx(ctx, nginx.InstallSpec{
		Root: paths.Root, Artifact: artifact, Stream: true, RelayOnly: true,
		LocalIP: localIP, NoService: spec.NoService,
	})
	if err != nil {
		rep.NginxManaged = true
		rep.NginxDir = filepath.Join(paths.Root, nginxDirRel)
		return rep, fmt.Errorf("%w; managed Nginx is installed at %s and can be removed with 'idleleo xray uninstall'", err, rep.NginxDir)
	}
	rep.NginxDir = installed.ConfDir
	rep.NginxManaged = true
	rep.Warnings = append(rep.Warnings, installed.Warnings...)

	relayDir, err := joinDir(paths, nginxDirRel)
	if err != nil {
		return rep, err
	}
	confPath := filepath.Join(relayDir, nginx.RelayConf)
	body, err := xraycfg.RelayConf(xraycfg.RelaySpec{
		ListenAddress: spec.ListenAddress, ListenPort: spec.ListenPort,
		BackendHost: spec.BackendHost, BackendPort: spec.BackendPort,
	})
	if err != nil {
		return rep, err
	}
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(confPath, []byte(body), 0o640); err != nil {
		return rep, err
	}
	if err := nginx.EnsureRelayInclude(paths.Root); err != nil {
		return rep, err
	}
	if err := finalizeManagedNginx(ctx, nginx.FinalizeSpec{Root: paths.Root, NoService: spec.NoService}); err != nil {
		return rep, fmt.Errorf("%w; managed Nginx is installed at %s and can be removed with 'idleleo xray uninstall'", err, rep.NginxDir)
	}
	rep.NginxVerified = true

	metaPath, err := paths.Join(paths.ManagerMetadata(), true)
	if err != nil {
		return rep, err
	}
	meta := store.Metadata{
		SchemaVersion:  store.ManagerSchemaVersion,
		ActiveEngine:   "xray",
		Provenance:     "native",
		Role:           "relay",
		TLS:            "None",
		Transport:      "None",
		OwnedResources: []string{nginxDirRel + "/" + nginx.RelayConf},
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return rep, err
	}
	metaBytes = append(metaBytes, '\n')
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		return rep, err
	}
	if err := writeFileAtomic(metaPath, metaBytes, 0o644); err != nil {
		return rep, err
	}

	rep.Backend = net.JoinHostPort(spec.BackendHost, fmt.Sprint(spec.BackendPort))
	rep.Listen = net.JoinHostPort(spec.ListenAddress, fmt.Sprint(spec.ListenPort))
	rep.ConfigPath = confPath
	return rep, nil
}
