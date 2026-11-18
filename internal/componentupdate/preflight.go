package componentupdate

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/nginx"
)

// Evidence level statuses. A preflight never claims more than it observed:
// "degraded" and "not-run" are first-class answers, not failures to hide.
const (
	EvidencePass     = "pass"
	EvidenceFail     = "fail"
	EvidenceDegraded = "degraded"
	EvidenceNotRun   = "not-run"
)

// EvidenceLevel is one layer of the upgrade qualification. The four names are
// stable so scripts can assert on them:
//
//	installable     manifest, digest, artifact format and version direction
//	config-parses   the candidate binary accepts the currently installed config
//	service-starts  a real service start under the candidate (never in preflight)
//	client-connects a real client reaches the service (never in preflight)
type EvidenceLevel struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// PreflightReport is the JSON contract for `update preflight`.
type PreflightReport struct {
	SchemaVersion    int             `json:"schemaVersion"`
	Component        string          `json:"component"`
	PreviousVersion  string          `json:"previousVersion"`
	CandidateVersion string          `json:"candidateVersion"`
	Action           string          `json:"action"`
	SHA256           string          `json:"sha256"`
	SizeBytes        int64           `json:"sizeBytes"`
	DigestVerified   bool            `json:"digestVerified"`
	Compatible       bool            `json:"compatible"`
	Levels           []EvidenceLevel `json:"levels"`
	Warnings         []string        `json:"warnings,omitempty"`
}

// Preflight qualifies a candidate without touching the installed artifacts.
// It downloads and verifies the manifest asset, inspects the artifact, and runs
// the candidate binary against the live configuration in a temporary directory.
// It never replaces a binary, starts a service, or writes under the root.
func Preflight(ctx context.Context, spec Spec) (PreflightReport, error) {
	paths, err := host.NewPaths(spec.Root)
	if err != nil {
		return PreflightReport{}, &change.UsageError{Msg: err.Error()}
	}
	if spec.Component != KindXray && spec.Component != KindNginx {
		return PreflightReport{}, &change.UsageError{Msg: "component must be xray or nginx"}
	}
	m, err := LoadManifest(ctx, spec.ManifestSource)
	if err != nil {
		return PreflightReport{}, err
	}
	if m.Component != spec.Component {
		return PreflightReport{}, fmt.Errorf("%w: manifest is for %s, command is %s",
			ErrComponentMismatch, m.Component, spec.Component)
	}
	report := PreflightReport{
		SchemaVersion:    1,
		Component:        spec.Component,
		CandidateVersion: m.Version,
		SHA256:           m.SHA256,
		SizeBytes:        m.SizeBytes,
	}

	previous, err := installedVersion(ctx, paths.Root, spec.Component)
	if err != nil {
		return report, err
	}
	report.PreviousVersion = previous
	report.Action = "install"
	if previous != "" {
		cmp, err := CompareVersions(m.Version, previous)
		if err != nil {
			return report, err
		}
		switch {
		case cmp < 0:
			report.Action = "downgrade"
			report.Levels = append(report.Levels, EvidenceLevel{
				Name: "installable", Status: EvidenceFail,
				Detail: fmt.Sprintf("manifest %s is older than installed %s", m.Version, previous),
			})
			report.Compatible = false
			return report, fmt.Errorf("%w: installed %s, manifest %s", ErrDowngrade, previous, m.Version)
		case cmp == 0:
			report.Action = "reinstall"
		default:
			report.Action = "update"
		}
	}

	data, err := FetchAsset(ctx, m)
	if err != nil {
		report.Levels = append(report.Levels, EvidenceLevel{
			Name: "installable", Status: EvidenceFail, Detail: err.Error(),
		})
		return report, err
	}
	report.DigestVerified = true

	artStatus, artDetail, artErr := checkArtifact(spec.Component, data, paths.Root == "/")
	report.Levels = append(report.Levels, EvidenceLevel{
		Name: "installable", Status: artStatus, Detail: artDetail,
	})
	if artErr != nil {
		report.Compatible = false
		return report, artErr
	}

	configStatus, configDetail := preflightConfig(ctx, paths.Root, spec.Component, data)
	report.Levels = append(report.Levels, EvidenceLevel{
		Name: "config-parses", Status: configStatus, Detail: configDetail,
	})
	report.Levels = append(report.Levels,
		EvidenceLevel{
			Name: "service-starts", Status: EvidenceNotRun,
			Detail: "preflight never replaces the artifact or restarts a service; run `idleleo update " + spec.Component + "` to activate",
		},
		EvidenceLevel{
			Name: "client-connects", Status: EvidenceNotRun,
			Detail: "requires an activated service and a real client; check after activation with `idleleo doctor --deep`",
		},
	)
	report.Compatible = configStatus != EvidenceFail
	if configStatus == EvidenceFail {
		return report, fmt.Errorf("%w: %s", ErrConfig, configDetail)
	}
	return report, nil
}

// checkArtifact validates the shape of the downloaded bytes. A real root only
// accepts a Linux ELF for Xray and a tar.gz for Nginx; a sandbox root accepts a
// script so tests can exercise the flow, but says so explicitly.
func checkArtifact(component string, data []byte, realRoot bool) (string, string, error) {
	switch component {
	case KindXray:
		if isELF(data) {
			if arch := elfMachine(data); arch != "" && arch != runtime.GOARCH {
				return EvidenceFail, "ELF architecture " + arch + " does not match this host " + runtime.GOARCH,
					fmt.Errorf("%w: xray artifact is %s, host is %s", ErrArtifact, arch, runtime.GOARCH)
			}
			return EvidencePass, "ELF binary for " + runtime.GOARCH, nil
		}
		if !realRoot && bytes.HasPrefix(data, []byte("#!")) {
			return EvidenceDegraded, "script candidate accepted for a sandbox root only", nil
		}
		return EvidenceFail, "candidate is not a Linux ELF binary",
			fmt.Errorf("%w: xray candidate is not an ELF binary", ErrArtifact)
	case KindNginx:
		if isGzip(data) {
			return EvidencePass, "gzip-compressed nginx artifact", nil
		}
		if !realRoot && bytes.HasPrefix(data, []byte("#!")) {
			return EvidenceDegraded, "script candidate accepted for a sandbox root only", nil
		}
		return EvidenceFail, "candidate is not a gzip archive",
			fmt.Errorf("%w: nginx candidate is not a tar.gz archive", ErrArtifact)
	}
	return EvidenceFail, "unknown component", fmt.Errorf("%w: unknown component", ErrArtifact)
}

func isELF(data []byte) bool {
	return len(data) >= 20 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'})
}

func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// elfMachine maps the ELF e_machine field to a Go GOARCH name. An empty result
// means "unknown", which is reported but not treated as a mismatch.
func elfMachine(data []byte) string {
	if !isELF(data) || data[5] != 1 { // 1 = little endian
		return ""
	}
	switch binary.LittleEndian.Uint16(data[18:20]) {
	case 0x03:
		return "386"
	case 0x28:
		return "arm"
	case 0x3e:
		return "amd64"
	case 0xb7:
		return "arm64"
	}
	return ""
}

// preflightConfig runs the candidate against the installed configuration. Like
// Apply's health check it uses a test/config-only invocation and never starts a
// listener on the host.
func preflightConfig(ctx context.Context, root, component string, data []byte) (string, string) {
	switch component {
	case KindXray:
		conf := filepath.Join(root, "etc/idleleo/conf/xray/config.json")
		if !regular(conf) {
			return EvidenceNotRun, "no installed xray config at " + conf + "; activation installs one"
		}
		dir, err := os.MkdirTemp("", "idleleo-preflight-xray-")
		if err != nil {
			return EvidenceFail, "stage candidate: " + err.Error()
		}
		defer os.RemoveAll(dir)
		bin := filepath.Join(dir, "xray")
		if err := os.WriteFile(bin, data, 0o755); err != nil {
			return EvidenceFail, "stage candidate: " + err.Error()
		}
		res, err := host.Run(ctx, host.ExecSpec{
			Path:    bin,
			Args:    []string{"-test", "-config", conf},
			Env:     []string{"XRAY_LOCATION_ASSET=" + filepath.Join(root, "etc/idleleo/share/xray")},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			return EvidenceFail, "run candidate: " + err.Error()
		}
		if res.ExitCode != 0 {
			return EvidenceFail, "candidate rejected the installed config: " + firstLine(res.Stderr+res.Stdout)
		}
		return EvidencePass, "candidate loaded the installed config"
	case KindNginx:
		conf := filepath.Join(nginxDir(root), "conf/nginx.conf")
		if !regular(conf) {
			return EvidenceNotRun, "no installed nginx config at " + conf + "; activation installs one"
		}
		dir, err := os.MkdirTemp("", "idleleo-preflight-nginx-")
		if err != nil {
			return EvidenceFail, "stage candidate: " + err.Error()
		}
		defer os.RemoveAll(dir)
		if err := nginx.Extract(data, dir); err != nil {
			return EvidenceFail, "extract candidate: " + err.Error()
		}
		staged := filepath.Join(dir, "nginx")
		bin := filepath.Join(staged, "sbin/nginx")
		if !executable(bin) {
			return EvidenceFail, "artifact does not contain an executable nginx/sbin/nginx"
		}
		// Validate the candidate binary against the live config, not the
		// config shipped in the archive: compatibility is the question.
		live, err := os.ReadFile(conf)
		if err != nil {
			return EvidenceFail, "read installed config: " + err.Error()
		}
		if err := os.WriteFile(filepath.Join(staged, "conf/nginx.conf"), live, 0o644); err != nil {
			return EvidenceFail, "stage installed config: " + err.Error()
		}
		res, err := host.Run(ctx, host.ExecSpec{
			Path:    bin,
			Args:    []string{"-t", "-p", staged + "/", "-c", filepath.Join(staged, "conf/nginx.conf")},
			Timeout: 30 * time.Second,
		})
		if err != nil {
			return EvidenceFail, "run candidate: " + err.Error()
		}
		if res.ExitCode != 0 {
			return EvidenceFail, "candidate rejected the installed config: " + firstLine(res.Stderr+res.Stdout)
		}
		return EvidencePass, "candidate loaded the installed config"
	}
	return EvidenceNotRun, "no compatibility check for this component"
}
