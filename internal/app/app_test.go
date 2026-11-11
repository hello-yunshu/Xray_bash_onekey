package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// TestStatusLoadsAlertsWithoutMetadata proves the failure alert is attached
// before any read that can fail, so `idleleo status` still shows it.
func TestStatusLoadsAlertsWithoutMetadata(t *testing.T) {
	root := t.TempDir()
	alertDir := filepath.Join(root, "etc/idleleo/alerts")
	if err := os.MkdirAll(alertDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alert := `{"schemaVersion":1,"job":"cert-renew","result":"failed","detail":"renewal failed","at":"2026-11-12T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(alertDir, "cert-renew.json"), []byte(alert), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{Paths: host.Paths{Root: root}}
	report, err := a.Status(context.Background())
	if err == nil {
		t.Fatal("expected a metadata error for an empty root")
	}
	if len(report.Alerts) != 1 || report.Alerts[0].Job != "cert-renew" {
		t.Fatalf("alerts=%+v", report.Alerts)
	}
}
