// Package ops builds the read-only operator summary: listeners, certificate
// expiry, the last change, recent failures and restart counts.
package ops

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/app"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/change"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// Port is one configured inbound listener.
type Port struct {
	Protocol string `json:"protocol"`
	Listen   string `json:"listen,omitempty"`
	Port     int    `json:"port"`
	Tag      string `json:"tag,omitempty"`
}

// Certificate is the managed leaf certificate state.
type Certificate struct {
	Path     string   `json:"path"`
	Present  bool     `json:"present"`
	NotAfter string   `json:"notAfter,omitempty"`
	DaysLeft int      `json:"daysLeft,omitempty"`
	SANs     []string `json:"sans,omitempty"`
}

// Report is the JSON contract for `ops summary`.
type Report struct {
	SchemaVersion int              `json:"schemaVersion"`
	GeneratedAt   string           `json:"generatedAt"`
	Status        app.StatusReport `json:"status"`
	Ports         []Port           `json:"ports"`
	Certificate   Certificate      `json:"certificate"`
	LastChange    *change.Entry    `json:"lastChange,omitempty"`
	Failures      []change.Entry   `json:"recentFailures,omitempty"`
	RestartCount  int              `json:"restartCount"`
}

// Summary reads everything from disk and the service manager; it never writes
// and never contacts the network.
func Summary(ctx context.Context, a *app.App) (Report, error) {
	status, err := a.Status(ctx)
	if err != nil && !status.Installed {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        status,
		Ports:         []Port{},
		RestartCount:  -1,
	}
	if raw, readErr := os.ReadFile(filepath.Join(a.Paths.Root, a.Paths.RuntimeConfig())); readErr == nil {
		report.Ports = parsePorts(raw)
	}
	report.Certificate = certificate(filepath.Join(a.Paths.Root, "etc/idleleo/cert/xray.crt"))
	entries := journal(filepath.Join(a.Paths.Root, a.Paths.JournalFile()))
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		report.LastChange = &last
		for i := len(entries) - 1; i >= 0 && len(report.Failures) < 5; i-- {
			if entries[i].State != change.StateCommitted {
				report.Failures = append(report.Failures, entries[i])
			}
		}
	}
	if a.Paths.Root == "/" {
		if res, runErr := host.Run(ctx, host.ExecSpec{
			Path: "systemctl", Args: []string{"show", "xray", "-p", "NRestarts", "--value"}, Timeout: 5 * time.Second,
		}); runErr == nil && res.ExitCode == 0 {
			if n, convErr := strconv.Atoi(strings.TrimSpace(res.Stdout)); convErr == nil {
				report.RestartCount = n
			}
		}
	}
	return report, nil
}

func parsePorts(raw []byte) []Port {
	var doc struct {
		Inbounds []struct {
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return []Port{}
	}
	out := make([]Port, 0, len(doc.Inbounds))
	for _, in := range doc.Inbounds {
		if in.Port == 0 {
			continue
		}
		out = append(out, Port{Protocol: in.Protocol, Listen: in.Listen, Port: in.Port, Tag: in.Tag})
	}
	return out
}

func certificate(path string) Certificate {
	report := Certificate{Path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		return report
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return report
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return report
	}
	report.Present = true
	report.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	report.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	report.SANs = cert.DNSNames
	return report
}

// journal reads the bounded transaction record. The canonical form is one JSON
// array (see change.Journal), so that is tried first; a line-delimited file is
// still accepted so an older or hand-edited record does not disappear.
func journal(path string) []change.Entry {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []change.Entry
	if json.Unmarshal(raw, &out) == nil {
		return out
	}
	out = nil
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry change.Entry
		if json.Unmarshal([]byte(line), &entry) == nil {
			out = append(out, entry)
		}
	}
	return out
}

// Text renders the same report for a terminal.
func Text(r Report) string {
	var b strings.Builder
	state := "not installed"
	if r.Status.Installed {
		state = fmt.Sprintf("%s/%s tls=%s transport=%s", r.Status.Engine, r.Status.Role, r.Status.TLS, r.Status.Transport)
	}
	fmt.Fprintf(&b, "state=%s configDrift=%d warnings=%d alerts=%d\n",
		state, len(r.Status.Drift), len(r.Status.Warnings), len(r.Status.Alerts))
	for _, p := range r.Ports {
		fmt.Fprintf(&b, "port=%d protocol=%s listen=%s tag=%s\n", p.Port, p.Protocol, p.Listen, p.Tag)
	}
	if r.Certificate.Present {
		fmt.Fprintf(&b, "certificate=%s notAfter=%s daysLeft=%d\n",
			r.Certificate.Path, r.Certificate.NotAfter, r.Certificate.DaysLeft)
	} else {
		fmt.Fprintf(&b, "certificate=%s missing\n", r.Certificate.Path)
	}
	if r.LastChange != nil {
		fmt.Fprintf(&b, "lastChange=%s state=%s target=%s at=%s\n",
			r.LastChange.ID, r.LastChange.State, r.LastChange.Target, r.LastChange.UpdatedAt)
	}
	fmt.Fprintf(&b, "recentFailures=%d restartCount=%d\n", len(r.Failures), r.RestartCount)
	return b.String()
}
