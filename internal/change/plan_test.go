package change

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlanFingerprintIsStableAndSecretFree(t *testing.T) {
	base := Plan{
		Operation:        "edit-runtime-config",
		Resource:         "etc/idleleo/conf/xray/config.json",
		OldSHA256:        "aaa",
		NewSHA256:        "bbb",
		Changed:          []string{"port", "uuid"},
		AffectedServices: []string{"xray", "nginx"},
		DisconnectRisk:   "drops live client sessions",
		ValidationSteps:  []string{"xray -test", "nginx -t"},
		RollbackScope:    "runtime config + nginx front",
		Ownership:        "idleleo-managed",
	}
	first := BuildPlan(base)
	reordered := base
	reordered.Changed = []string{"uuid", "port"}
	if got := BuildPlan(reordered).Fingerprint; got != first.Fingerprint {
		t.Fatalf("fingerprint depends on change order: %s != %s", got, first.Fingerprint)
	}
	// A changed payload must change the fingerprint.
	other := base
	other.NewSHA256 = "ccc"
	if BuildPlan(other).Fingerprint == first.Fingerprint {
		t.Fatal("different new hash kept the same fingerprint")
	}
	body, err := MarshalPlan(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"privateKey", "00000000-0000", "BEGIN PRIVATE KEY"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("plan leaked %q: %s", secret, body)
		}
	}
	if !bytes.Contains(body, []byte(`"fingerprint"`)) {
		t.Fatalf("plan JSON has no fingerprint: %s", body)
	}
}
