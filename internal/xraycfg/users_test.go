package xraycfg

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	userAUUID = "11111111-2222-3333-4444-555555555555"
	userBUUID = "99999999-2222-3333-4444-555555555555"
	userCUUID = "77777777-2222-3333-4444-555555555555"
)

// multiUserConfig returns a two-inbound config where every inbound carries the
// same three users, which is what a ws+grpc install looks like in practice.
func multiUserConfig(t *testing.T) []byte {
	t.Helper()
	stubCanBind(t, func(string, int) bool { return true })
	g, err := Generate(Spec{Mode: ModeReality, Domain: "example.com", Transport: TransportWS,
		UUID: userAUUID, Email: "user-a@idleleo"})
	if err != nil {
		t.Fatal(err)
	}
	raw := g.Config
	for _, spec := range []AddUserSpec{
		{UUID: userBUUID, Email: "user-b@idleleo"},
		{UUID: userCUUID, Email: "user-c@idleleo"},
	} {
		raw, _, err = AddUser(raw, 0, spec)
		if err != nil {
			t.Fatal(err)
		}
	}
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	inbounds := asSlice(root["inbounds"])
	clone, _ := json.Marshal(inbounds[0])
	var second map[string]any
	if err := json.Unmarshal(clone, &second); err != nil {
		t.Fatal(err)
	}
	second["port"] = 10443
	second["tag"] = "vless-ws-2"
	// Replace the generator's own extra inbound so both inbounds are exact
	// copies of the same three-user credential set.
	root["inbounds"] = []any{inbounds[0], second}
	return mustMarshal(root)
}

func clientByEmail(t *testing.T, raw []byte, inbound int, email string) map[string]any {
	t.Helper()
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range allInboundClients(root)[inbound] {
		if asStringField(client["email"]) == email {
			return client
		}
	}
	t.Fatalf("%s not found in inbound %d", email, inbound)
	return nil
}

func TestSetUserUUIDUpdatesEveryInboundAtomically(t *testing.T) {
	raw := multiUserConfig(t)
	newUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	out, change, err := SetUserUUID(raw, "user-b@idleleo", newUUID, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if change.NoChanges {
		t.Fatal("rotation must not report no-changes")
	}
	if len(change.Previous) != 2 || len(change.Updated) != 2 {
		t.Fatalf("expected one match per inbound, got previous=%d updated=%d", len(change.Previous), len(change.Updated))
	}
	for _, ref := range change.Previous {
		if ref.User.UUID != userBUUID || ref.User.Email != "user-b@idleleo" {
			t.Fatalf("unexpected previous ref: %+v", ref)
		}
	}
	for inbound := 0; inbound < 2; inbound++ {
		if got := asStringField(clientByEmail(t, out, inbound, "user-b@idleleo")["id"]); got != newUUID {
			t.Fatalf("inbound %d user-b uuid = %s, want %s", inbound, got, newUUID)
		}
		// The other two users must stay byte-for-byte on their credentials.
		for email, uuid := range map[string]string{"user-a@idleleo": userAUUID, "user-c@idleleo": userCUUID} {
			if got := asStringField(clientByEmail(t, out, inbound, email)["id"]); got != uuid {
				t.Fatalf("inbound %d %s uuid drifted: %s", inbound, email, got)
			}
		}
	}
	// Only clients[].id may move: rebuild the expectation independently.
	expected, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	for inbound := 0; inbound < 2; inbound++ {
		for _, client := range allInboundClients(expected)[inbound] {
			if asStringField(client["email"]) == "user-b@idleleo" {
				client["id"] = newUUID
			}
		}
	}
	if !sameJSON(t, expected, mustParse(t, out)) {
		t.Fatal("rotation changed fields other than clients[].id")
	}
	// email/flow/level survive, which is what keeps stats and routing stable.
	for inbound := 0; inbound < 2; inbound++ {
		before := clientByEmail(t, raw, inbound, "user-b@idleleo")
		after := clientByEmail(t, out, inbound, "user-b@idleleo")
		if asStringField(after["email"]) != "user-b@idleleo" {
			t.Fatalf("inbound %d email changed", inbound)
		}
		if asStringField(after["flow"]) != asStringField(before["flow"]) {
			t.Fatalf("inbound %d flow changed: %v -> %v", inbound, before["flow"], after["flow"])
		}
		if asIntField(after["level"]) != asIntField(before["level"]) {
			t.Fatalf("inbound %d level changed", inbound)
		}
	}
}

func TestSetUserUUIDRejectsDuplicate(t *testing.T) {
	raw := multiUserConfig(t)
	if _, _, err := SetUserUUID(raw, "user-b@idleleo", userAUUID, 0, false); err == nil ||
		!strings.Contains(err.Error(), "already used") {
		t.Fatalf("duplicate uuid must be rejected, got %v", err)
	}
}

func TestSetUserUUIDNoOp(t *testing.T) {
	raw := multiUserConfig(t)
	out, change, err := SetUserUUID(raw, "user-b@idleleo", userBUUID, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if !change.NoChanges {
		t.Fatalf("repeating the current uuid must be a no-op: %+v", change)
	}
	if out != nil {
		t.Fatal("a no-op must not return bytes to write")
	}
}

func TestSetUserUUIDRestrictedInboundKeepsOther(t *testing.T) {
	raw := multiUserConfig(t)
	newUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	out, change, err := SetUserUUID(raw, "user-b@idleleo", newUUID, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(change.Previous) != 1 || change.Previous[0].Inbound != 0 {
		t.Fatalf("restricted rotation touched %+v", change.Previous)
	}
	if got := asStringField(clientByEmail(t, out, 0, "user-b@idleleo")["id"]); got != newUUID {
		t.Fatalf("inbound 0 not updated: %s", got)
	}
	if got := asStringField(clientByEmail(t, out, 1, "user-b@idleleo")["id"]); got != userBUUID {
		t.Fatalf("inbound 1 must keep the old uuid, got %s", got)
	}
}

func TestSetUserUUIDNotFoundListsUsers(t *testing.T) {
	raw := multiUserConfig(t)
	_, _, err := SetUserUUID(raw, "nobody@idleleo", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 0, false)
	if err == nil || !strings.Contains(err.Error(), "available users") ||
		!strings.Contains(err.Error(), "user-a@idleleo") || !strings.Contains(err.Error(), "user-c@idleleo") {
		t.Fatalf("not-found must list candidates, got %v", err)
	}
}

func TestSetUserUUIDRefusesAmbiguousEmail(t *testing.T) {
	raw := multiUserConfig(t)
	root := mustParse(t, raw)
	// Hand-edited configs can repeat an email; rotating both at once would
	// silently merge two people.
	clients := allInboundClients(root)[0]
	clients[2]["email"] = "user-b@idleleo"
	patched := mustMarshal(root)
	if _, _, err := SetUserUUID(patched, "user-b@idleleo", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 0, false); err == nil ||
		!strings.Contains(err.Error(), "select by current UUID") {
		t.Fatalf("ambiguous email must be refused, got %v", err)
	}
}

func TestSetUserUUIDRejectsBadUUID(t *testing.T) {
	raw := multiUserConfig(t)
	if _, _, err := SetUserUUID(raw, "user-b@idleleo", "not-a-uuid", 0, false); err == nil ||
		!strings.Contains(err.Error(), "RFC4122") {
		t.Fatalf("invalid uuid must be rejected, got %v", err)
	}
}

func mustParse(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	root, err := parseRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func sameJSON(t *testing.T, a, b map[string]any) bool {
	t.Helper()
	left, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(left) == string(right)
}
