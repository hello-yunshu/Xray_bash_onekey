package xraycfg

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func realitySettings(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	in := editInbounds(t, raw)[0]
	return asMap(asMap(in["streamSettings"])["realitySettings"])
}

func shortIDs(t *testing.T, raw []byte) []string {
	t.Helper()
	out := []string{}
	for _, id := range asSlice(realitySettings(t, raw)["shortIds"]) {
		out = append(out, asString(id))
	}
	return out
}

func TestEditShortIDAppendKeepsOldClients(t *testing.T) {
	raw := editBase(t)
	old := shortIDs(t, raw)
	if len(old) != 1 {
		t.Fatalf("base shortIds = %v, want one", old)
	}
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{ShortIDSet: true, ShortID: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	got := shortIDs(t, g.Config)
	if len(got) != 2 || got[0] != old[0] || got[1] != "deadbeef" {
		t.Fatalf("shortIds = %v, want [%s deadbeef]", got, old[0])
	}
	if res.Disconnect {
		t.Fatalf("appending a sid must not be disconnect-prone")
	}
	if !res.RealityCredentialMoved {
		t.Fatalf("credential edit not reported")
	}
	// The verified/published link must carry the newly added sid.
	if !strings.Contains(g.ShareURI, "sid=deadbeef") {
		t.Fatalf("new link does not use the appended sid: %s", g.ShareURI)
	}
}

func TestEditRealityLinkKeepsPortWithoutPublicDefault(t *testing.T) {
	raw := editBase(t)
	// A direct Reality install has no front to supply PublicPort; the share
	// link must still name the port clients have to dial.
	g, _, err := EditRuntime(raw, EditDefaults{Mode: ModeReality}, EditRequest{ShortIDAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.ShareURI, ":443?") {
		t.Fatalf("share link lost the public port: %s", g.ShareURI)
	}
}

func TestEditShortIDEmptyClearsExplicitly(t *testing.T) {
	raw := editBase(t)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{ShortIDSet: true, ShortID: ""})
	if err != nil {
		t.Fatal(err)
	}
	if got := shortIDs(t, g.Config); len(got) != 0 {
		t.Fatalf("shortIds = %v, want an explicit empty list", got)
	}
	if !res.Disconnect {
		t.Fatalf("clearing every sid drops clients and must be disconnect-prone")
	}
	if !hasChange(res.Changed, "short-id-clear") {
		t.Fatalf("changed = %v, want short-id-clear", res.Changed)
	}
}

func TestEditShortIDAutoIsSeparateFromClear(t *testing.T) {
	raw := editBase(t)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{ShortIDAuto: true})
	if err != nil {
		t.Fatal(err)
	}
	got := shortIDs(t, g.Config)
	if len(got) != 2 {
		t.Fatalf("shortIds = %v, want old + generated", got)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(got[1]) {
		t.Fatalf("generated sid %q is not 8 hex", got[1])
	}
	if res.Disconnect {
		t.Fatalf("auto-append must not drop clients")
	}
	if !strings.Contains(g.ShareURI, "sid="+got[1]) {
		t.Fatalf("new link does not use the generated sid: %s", g.ShareURI)
	}
}

func TestEditShortIDRemove(t *testing.T) {
	raw := editBase(t)
	first := shortIDs(t, raw)[0]
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{ShortIDSet: true, ShortID: "cafebabe"})
	if err != nil {
		t.Fatal(err)
	}
	g, res, err = EditRuntime(g.Config, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{ShortIDRemove: first})
	if err != nil {
		t.Fatal(err)
	}
	if got := shortIDs(t, g.Config); len(got) != 1 || got[0] != "cafebabe" {
		t.Fatalf("shortIds = %v, want [cafebabe]", got)
	}
	if !res.Disconnect {
		t.Fatalf("removing a sid is disconnect-prone")
	}
	if _, _, err := EditRuntime(g.Config, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{ShortIDRemove: "deadbeef"}); err == nil {
		t.Fatal("removing an unknown sid must fail")
	}
}

func TestEditLinkPreferencesDoNotTouchRuntime(t *testing.T) {
	raw := editBase(t)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{LinkFPChanged: true, LinkFingerprint: "firefox",
			LinkSpiderXSet: true, LinkSpiderX: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, g.Config) {
		t.Fatalf("link preferences must not change the runtime config")
	}
	if !res.LinkPrefsChanged || res.NoChanges {
		t.Fatalf("link prefs change not reported: %+v", res)
	}
	if res.Disconnect {
		t.Fatalf("link preferences cannot drop sessions")
	}
	if !strings.Contains(g.ShareURI, "fp=firefox") || !strings.Contains(g.ShareURI, "spx=/") {
		t.Fatalf("link did not take the preferences: %s", g.ShareURI)
	}
}

func TestEditRotatePrivateKeyChangesCredential(t *testing.T) {
	raw := editBase(t)
	before := realitySettings(t, raw)
	oldIDs := shortIDs(t, raw)
	g, res, err := EditRuntime(raw, EditDefaults{Mode: ModeReality, PublicPort: 443},
		EditRequest{RotatePrivateKey: true})
	if err != nil {
		t.Fatal(err)
	}
	after := realitySettings(t, g.Config)
	if asString(before["privateKey"]) == asString(after["privateKey"]) {
		t.Fatal("private key did not rotate")
	}
	if got := shortIDs(t, g.Config); len(got) != len(oldIDs) || got[0] != oldIDs[0] {
		t.Fatalf("rotation must not touch shortIds: %v -> %v", oldIDs, got)
	}
	if !res.PrivateKeyRotated || !res.Disconnect {
		t.Fatalf("rotation not reported as disconnect-prone: %+v", res)
	}
	if res.OldShareURI == "" || res.OldShareURI == g.ShareURI {
		t.Fatalf("old/new links must differ and the old one must be preserved")
	}
	if !strings.Contains(res.OldShareURI, "pbk="+derivePublicKeyOrFail(t, asString(before["privateKey"]))) {
		t.Fatalf("old link does not carry the old public key: %s", res.OldShareURI)
	}
	if !strings.Contains(g.ShareURI, "pbk="+derivePublicKeyOrFail(t, asString(after["privateKey"]))) {
		t.Fatalf("new link does not carry the new public key: %s", g.ShareURI)
	}
}

func derivePublicKeyOrFail(t *testing.T, priv string) string {
	t.Helper()
	pub, err := DerivePublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestValidShortIDAcceptsEmptyAndHex(t *testing.T) {
	for _, ok := range []string{"", "ab", "deadbeef", "0123456789abcdef"} {
		if !validShortID(ok) {
			t.Fatalf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"a", "abc", "zz", "0123456789abcdef00"} {
		if validShortID(bad) {
			t.Fatalf("%q should be invalid", bad)
		}
	}
}
