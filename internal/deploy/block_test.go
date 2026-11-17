package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
	"github.com/hello-yunshu/Xray_bash_onekey/internal/xraycfg"
)

func writeBlockFixture(t *testing.T, root string, doc map[string]any) {
	t.Helper()
	p := filepath.Join(root, blockStateRel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readBlockFixture(t *testing.T, root string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, blockStateRel))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestCustomListMutationIsIsolated is the D5 contract: clearing or disabling a
// custom list must not touch the built-in four or the other custom list, and
// unknown keys written by Bash must survive.
func TestCustomListMutationIsIsolated(t *testing.T) {
	root := sandbox(t)
	writeBlockFixture(t, root, map[string]any{
		"country_block": []any{"cn"},
		"bittorrent":    true,
		"private_ip":    true,
		"ads":           true,
		"custom_domains": map[string]any{
			"enabled": true, "items": []any{"keep.example"},
		},
		"custom_ips": map[string]any{
			"enabled": true, "items": []any{"198.51.100.0/24"},
		},
		"future_key": map[string]any{"owner": "bash"},
	})

	if _, err := UpdateBlockCustom(root, "domain", []string{"add.example", "add.example"}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	doc := readBlockFixture(t, root)
	if doc["ads"] != true || doc["private_ip"] != true || doc["bittorrent"] != true {
		t.Fatalf("built-in switches changed: %v", doc)
	}
	ips := customList(doc["custom_ips"])
	if len(ips.Items) != 1 || ips.Items[0] != "198.51.100.0/24" || !ips.Enabled {
		t.Fatalf("custom ip list changed: %+v", ips)
	}
	domains := customList(doc["custom_domains"])
	if len(domains.Items) != 2 || domains.Items[0] != "keep.example" || domains.Items[1] != "add.example" {
		t.Fatalf("custom domain list wrong: %+v", domains)
	}
	if doc["future_key"] == nil {
		t.Fatal("unknown key was dropped")
	}

	// Removing every item must not disable the list or touch the built-ins.
	if _, err := UpdateBlockCustom(root, "domain", nil, []string{"keep.example", "add.example"}, nil, false); err != nil {
		t.Fatal(err)
	}
	doc = readBlockFixture(t, root)
	if custom := customList(doc["custom_domains"]); len(custom.Items) != 0 || !custom.Enabled {
		t.Fatalf("clearing items changed enabled state: %+v", custom)
	}
	if doc["ads"] != true {
		t.Fatal("clearing a custom list disturbed ads")
	}

	// Disabling one list must leave the other enabled.
	off := false
	if _, err := UpdateBlockCustom(root, "domain", nil, nil, &off, false); err != nil {
		t.Fatal(err)
	}
	doc = readBlockFixture(t, root)
	if customList(doc["custom_ips"]).Enabled != true {
		t.Fatal("disabling custom domains disturbed custom ips")
	}
}

// TestBlockStateRoundTripPreservesBashState proves the Go side reads and writes
// the same keys Bash uses.
func TestBlockStateRoundTripPreservesBashState(t *testing.T) {
	root := sandbox(t)
	writeBlockFixture(t, root, map[string]any{
		"country_block":            []any{"cn", "us"},
		"bittorrent":               true,
		"private_ip":               false,
		"ads":                      true,
		"previous_domain_strategy": "AsIs",
		"previous_sniffing":        []any{map[string]any{"tag": "vless-ws", "sniffing": nil}},
		"owned_rules":              []any{},
		"applied":                  true,
	})
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	st, ok, err := loadBlockState(paths)
	if err != nil || !ok {
		t.Fatalf("state not loaded (ok=%t err=%v)", ok, err)
	}
	if len(st.Block.Countries) != 2 || !st.Block.Ads || st.Block.PrivateIP || !st.Block.BitTorrent {
		t.Fatalf("state decoded wrong: %+v", st.Block)
	}
	if st.PrevDomainStrategy != "AsIs" || len(st.PrevSniffing) != 1 || st.PrevSniffing[0].Sniffing != nil {
		t.Fatalf("previous values decoded wrong: %+v", st)
	}

	// Configured but never applied: edit must not treat it as live.
	writeBlockFixture(t, root, map[string]any{"ads": true, "applied": false})
	if _, ok, err := loadBlockState(paths); err != nil || ok {
		t.Fatalf("unapplied state must be ignored (ok=%t err=%v)", ok, err)
	}
}

// TestSetAppliedRecordsLiveness guards the C2 gate. After a successful apply
// the state must carry applied=true; otherwise `config edit` cannot see the
// BlockState, regenerates without sniffing/routing, and refuses the edit (or,
// before the fix, silently drops the block).
func TestSetAppliedRecordsLiveness(t *testing.T) {
	root := sandbox(t)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	d, err := loadBlockDoc(paths)
	if err != nil {
		t.Fatal(err)
	}
	// The switches themselves are written by UpdateBlockSwitches; this test only
	// covers the liveness flag the edit path reads back.
	d.doc["ads"] = true
	st := xraycfg.BlockState{
		Block: xraycfg.RoutingBlock{Ads: true},
		OwnedRules: []any{map[string]any{
			"type": "field", "outboundTag": "blocked", "domain": []any{"geosite:category-ads-all"},
		}},
	}
	d.setApplied(st, true)
	if err := d.save(paths); err != nil {
		t.Fatal(err)
	}
	got, ok, err := loadBlockState(paths)
	if err != nil || !ok {
		t.Fatalf("applied state not visible to edit (ok=%t err=%v)", ok, err)
	}
	if !got.Block.Ads || len(got.OwnedRules) != 1 {
		t.Fatalf("state decoded wrong: %+v", got)
	}

	d.setApplied(xraycfg.BlockState{}, false)
	if err := d.save(paths); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := loadBlockState(paths); err != nil || ok {
		t.Fatalf("state must not steer edits after block off (ok=%t err=%v)", ok, err)
	}
}

// TestBlockStateAbsentKeepsEditStrict ensures an install that never ran the
// blocker keeps the pre-C2 contract.
func TestBlockStateAbsentKeepsEditStrict(t *testing.T) {
	root := sandbox(t)
	paths, err := host.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := loadBlockState(paths); err != nil || ok {
		t.Fatalf("expected no state (ok=%t err=%v)", ok, err)
	}
}
