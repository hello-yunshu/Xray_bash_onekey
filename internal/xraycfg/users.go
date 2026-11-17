package xraycfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// UserRef locates one client inside one inbound. Index is the position in the
// inbound's clients array, so callers can report exactly what moved.
type UserRef struct {
	Inbound int
	User    UserView
}

// UserUUIDChange is the before/after view of a single-user credential change.
// Previous and Updated are aligned by position.
type UserUUIDChange struct {
	Ident     string
	NewUUID   string
	Previous  []UserRef
	Updated   []UserRef
	NoChanges bool
}

// SetUserUUID rewrites one user's UUID everywhere that user appears. The whole
// document is cloned and compared field by field, so a partial rewrite cannot
// reach disk: either every matched inbound moves to NewUUID or the function
// fails and returns no bytes.
//
// The selector is the email (canonical) or the current UUID (alias). Indices
// are deliberately not accepted: remove shifts them, so a cached index would
// rotate somebody else's credential.
func SetUserUUID(raw []byte, ident, newUUID string, onlyInbound int, restrictInbound bool) ([]byte, UserUUIDChange, error) {
	ident = strings.TrimSpace(ident)
	change := UserUUIDChange{Ident: ident, NewUUID: strings.TrimSpace(newUUID)}
	if ident == "" {
		return nil, change, fmt.Errorf("email or current uuid required")
	}
	if change.NewUUID == "" {
		return nil, change, fmt.Errorf("--new-uuid is required")
	}
	if !validUUID(change.NewUUID) {
		return nil, change, fmt.Errorf("--new-uuid is not a valid RFC4122 value")
	}
	candidate, err := decode(raw)
	if err != nil {
		return nil, change, err
	}
	matches, err := matchUser(candidate, ident)
	if err != nil {
		return nil, change, err
	}
	if restrictInbound {
		filtered := matches[:0]
		for _, ref := range matches {
			if ref.Inbound == onlyInbound {
				filtered = append(filtered, ref)
			}
		}
		matches = filtered
		if len(matches) == 0 {
			return nil, change, fmt.Errorf("user %q not found in inbound %d", ident, onlyInbound)
		}
	}
	if len(matches) == 0 {
		return nil, change, fmt.Errorf("user %q not found; available users: %s", ident, describeUsers(candidate))
	}
	// A duplicate UUID would make two users indistinguishable for stats and
	// routing, and one of them would silently start using the other's identity.
	matched := map[string]bool{}
	for _, ref := range matches {
		matched[fmt.Sprintf("%d:%d", ref.Inbound, ref.User.Index)] = true
	}
	for inbound, item := range allInboundClients(candidate) {
		for index, client := range item {
			if matched[fmt.Sprintf("%d:%d", inbound, index)] {
				continue
			}
			if id, _ := client["id"].(string); id == change.NewUUID {
				return nil, change, fmt.Errorf("uuid already used by inbound %d client %d (%s)", inbound, index, clientEmail(client))
			}
		}
	}
	// Mutate every match on the clone, then prove that nothing else moved by
	// comparing against an independently built expectation. Re-encoding order is
	// irrelevant: both sides are decoded maps.
	for _, ref := range matches {
		clients := allInboundClients(candidate)[ref.Inbound]
		client := clients[ref.User.Index]
		previous := UserView{
			Index: ref.User.Index, UUID: asStringField(client["id"]),
			Email: asStringField(client["email"]), Flow: asStringField(client["flow"]),
			Level: asIntField(client["level"]), Primary: ref.User.Index == 0,
		}
		change.Previous = append(change.Previous, UserRef{Inbound: ref.Inbound, User: previous})
		client["id"] = change.NewUUID
		change.Updated = append(change.Updated, UserRef{
			Inbound: ref.Inbound,
			User: UserView{
				Index: previous.Index, UUID: change.NewUUID, Email: previous.Email,
				Flow: previous.Flow, Level: previous.Level, Primary: previous.Primary,
			},
		})
	}
	expected, err := decode(raw)
	if err != nil {
		return nil, change, err
	}
	for _, ref := range matches {
		allInboundClients(expected)[ref.Inbound][ref.User.Index]["id"] = change.NewUUID
	}
	change.NoChanges = true
	for _, ref := range change.Previous {
		if ref.User.UUID != change.NewUUID {
			change.NoChanges = false
		}
	}
	if !reflect.DeepEqual(expected, candidate) {
		return nil, change, fmt.Errorf("refusing mutation: fields outside clients[].id would change")
	}
	if change.NoChanges {
		return nil, change, nil
	}
	return encode(candidate), change, nil
}

// matchUser returns every client whose email or uuid equals ident. An inbound
// with two matching clients is refused: the caller must disambiguate by UUID,
// otherwise a single email would rotate two people at once.
func matchUser(root map[string]any, ident string) ([]UserRef, error) {
	byInbound := allInboundClients(root)
	out := []UserRef{}
	for inbound := 0; inbound < len(byInbound); inbound++ {
		seen := 0
		for index, client := range byInbound[inbound] {
			id := asStringField(client["id"])
			email := asStringField(client["email"])
			if strings.EqualFold(id, ident) || email == ident {
				seen++
				out = append(out, UserRef{Inbound: inbound, User: UserView{
					Index: index, UUID: id, Email: email,
					Flow: asStringField(client["flow"]), Level: asIntField(client["level"]),
					Primary: index == 0,
				}})
			}
		}
		if seen > 1 {
			return nil, fmt.Errorf("user %q matches %d clients in inbound %d; select by current UUID", ident, seen, inbound)
		}
	}
	return out, nil
}

func describeUsers(root map[string]any) string {
	parts := []string{}
	byInbound := allInboundClients(root)
	for inbound := 0; inbound < len(byInbound); inbound++ {
		for index, client := range byInbound[inbound] {
			parts = append(parts, fmt.Sprintf("[inbound %d index %d] %s %s", inbound, index,
				asStringField(client["email"]), asStringField(client["id"])))
		}
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, "; ")
}

func allInboundClients(root map[string]any) map[int][]map[string]any {
	inbounds, _ := root["inbounds"].([]any)
	out := make(map[int][]map[string]any, len(inbounds))
	for i, item := range inbounds {
		inbound, _ := item.(map[string]any)
		settings, _ := inbound["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		list := make([]map[string]any, 0, len(clients))
		for _, raw := range clients {
			client, _ := raw.(map[string]any)
			if client == nil {
				continue
			}
			list = append(list, client)
		}
		out[i] = list
	}
	return out
}

func asStringField(v any) string {
	s, _ := v.(string)
	return s
}

func asIntField(v any) int {
	if n, ok := v.(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

func clientEmail(client map[string]any) string {
	email := asStringField(client["email"])
	if email == "" {
		return "(no email)"
	}
	return email
}

// AddUserSpec is one new VLESS client plus an optional Reality shortId.
type AddUserSpec struct {
	UUID    string
	Email   string
	Flow    string
	Level   int
	ShortID string
}

// ListUsers returns the clients of one VLESS inbound. Index 0 is the primary
// user created by the installer and is protected from removal.
func ListUsers(raw []byte, inboundIndex int) ([]UserView, error) {
	root, err := decode(raw)
	if err != nil {
		return nil, err
	}
	in, err := inboundAt(root, inboundIndex)
	if err != nil {
		return nil, err
	}
	return clientsOf(in, inboundIndex)
}

// AddUser appends one client and optionally one Reality shortId. It refuses
// duplicate UUID/email and any change outside clients/shortIds.
func AddUser(raw []byte, inboundIndex int, spec AddUserSpec) ([]byte, UserView, error) {
	original, err := decode(raw)
	if err != nil {
		return nil, UserView{}, err
	}
	candidate, err := decode(raw)
	if err != nil {
		return nil, UserView{}, err
	}
	in, err := inboundAt(candidate, inboundIndex)
	if err != nil {
		return nil, UserView{}, err
	}
	if protocol, _ := in["protocol"].(string); !strings.EqualFold(protocol, "vless") {
		return nil, UserView{}, fmt.Errorf("inbound %d is not a VLESS inbound", inboundIndex)
	}
	settings, ok := in["settings"].(map[string]any)
	if !ok {
		return nil, UserView{}, fmt.Errorf("inbound %d has no settings object", inboundIndex)
	}
	clients, ok := settings["clients"].([]any)
	if !ok {
		return nil, UserView{}, fmt.Errorf("inbound %d has no clients array", inboundIndex)
	}
	if spec.UUID == "" {
		id, err := NewUUID()
		if err != nil {
			return nil, UserView{}, err
		}
		spec.UUID = id
	}
	if !validUUID(spec.UUID) {
		return nil, UserView{}, fmt.Errorf("uuid is not a valid RFC4122 value")
	}
	if spec.Email == "" {
		spec.Email = "user-" + strings.ReplaceAll(spec.UUID[:8], "-", "") + "@idleleo"
	}
	for i, item := range clients {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		if id, _ := m["id"].(string); strings.EqualFold(id, spec.UUID) {
			return nil, UserView{}, fmt.Errorf("uuid already exists at index %d", i)
		}
		if email, _ := m["email"].(string); email != "" && email == spec.Email {
			return nil, UserView{}, fmt.Errorf("email already exists at index %d", i)
		}
	}
	client := map[string]any{"id": spec.UUID, "level": spec.Level, "email": spec.Email}
	if spec.Flow != "" {
		client["flow"] = spec.Flow
	}
	settings["clients"] = append(clients, client)
	if spec.ShortID != "" {
		if !validShortID(spec.ShortID) {
			return nil, UserView{}, fmt.Errorf("shortId must be 1-16 hex characters with even length")
		}
		rs, _ := in["streamSettings"].(map[string]any)
		reality, _ := rs["realitySettings"].(map[string]any)
		if reality == nil {
			return nil, UserView{}, fmt.Errorf("--short-id requires a Reality inbound")
		}
		ids, _ := reality["shortIds"].([]any)
		for _, existing := range ids {
			if s, _ := existing.(string); s == spec.ShortID {
				return nil, UserView{}, fmt.Errorf("shortId already present")
			}
		}
		reality["shortIds"] = append(ids, spec.ShortID)
	}
	out := encode(candidate)
	if err := assertOnlyUsersChanged(original, candidate, inboundIndex); err != nil {
		return nil, UserView{}, err
	}
	view := UserView{
		Index: len(clients), UUID: spec.UUID, Email: spec.Email,
		Flow: spec.Flow, Level: spec.Level, Primary: false,
	}
	return out, view, nil
}

// RemoveUser removes one non-primary client identified by email or UUID.
func RemoveUser(raw []byte, inboundIndex int, ident string) ([]byte, UserView, error) {
	ident = strings.TrimSpace(ident)
	if ident == "" {
		return nil, UserView{}, fmt.Errorf("email or uuid required")
	}
	original, err := decode(raw)
	if err != nil {
		return nil, UserView{}, err
	}
	candidate, err := decode(raw)
	if err != nil {
		return nil, UserView{}, err
	}
	in, err := inboundAt(candidate, inboundIndex)
	if err != nil {
		return nil, UserView{}, err
	}
	settings, _ := in["settings"].(map[string]any)
	if settings == nil {
		return nil, UserView{}, fmt.Errorf("inbound %d has no settings object", inboundIndex)
	}
	clients, _ := settings["clients"].([]any)
	if len(clients) == 0 {
		return nil, UserView{}, fmt.Errorf("inbound %d has no clients", inboundIndex)
	}
	removeAt := -1
	for i, item := range clients {
		m, _ := item.(map[string]any)
		if m == nil {
			continue
		}
		id, _ := m["id"].(string)
		email, _ := m["email"].(string)
		if strings.EqualFold(id, ident) || email == ident {
			removeAt = i
			break
		}
	}
	if removeAt < 0 {
		return nil, UserView{}, fmt.Errorf("user not found: %s", ident)
	}
	if removeAt == 0 {
		return nil, UserView{}, fmt.Errorf("refusing to remove the primary user (index 0)")
	}
	removed := UserView{Index: removeAt}
	if m, _ := clients[removeAt].(map[string]any); m != nil {
		removed.UUID, _ = m["id"].(string)
		removed.Email, _ = m["email"].(string)
		removed.Flow, _ = m["flow"].(string)
		if level, ok := m["level"].(json.Number); ok {
			if n, err := level.Int64(); err == nil {
				removed.Level = int(n)
			}
		}
	}
	settings["clients"] = append(clients[:removeAt], clients[removeAt+1:]...)
	out := encode(candidate)
	if err := assertOnlyUsersChanged(original, candidate, inboundIndex); err != nil {
		return nil, UserView{}, err
	}
	return out, removed, nil
}

func clientsOf(in map[string]any, inboundIndex int) ([]UserView, error) {
	settings, _ := in["settings"].(map[string]any)
	if settings == nil {
		return nil, fmt.Errorf("inbound %d has no settings object", inboundIndex)
	}
	clients, _ := settings["clients"].([]any)
	out := make([]UserView, 0, len(clients))
	for i, item := range clients {
		m, _ := item.(map[string]any)
		v := UserView{Index: i, Primary: i == 0}
		if m != nil {
			v.UUID, _ = m["id"].(string)
			v.Email, _ = m["email"].(string)
			v.Flow, _ = m["flow"].(string)
			if level, ok := m["level"].(json.Number); ok {
				if n, err := level.Int64(); err == nil {
					v.Level = int(n)
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// assertOnlyUsersChanged restores the user-owned fields in the candidate and
// requires the rest of the document to be identical.
func assertOnlyUsersChanged(original, candidate map[string]any, inboundIndex int) error {
	oIn, _ := inboundAt(original, inboundIndex)
	cIn, _ := inboundAt(candidate, inboundIndex)
	cSettings, _ := cIn["settings"].(map[string]any)
	oSettings, _ := oIn["settings"].(map[string]any)
	cSettings["clients"] = oSettings["clients"]
	if cReality, ok := cIn["streamSettings"].(map[string]any); ok {
		if oStream, ok2 := oIn["streamSettings"].(map[string]any); ok2 {
			if oReality, ok3 := oStream["realitySettings"].(map[string]any); ok3 {
				if cRealityMap, ok4 := cReality["realitySettings"].(map[string]any); ok4 {
					cRealityMap["shortIds"] = oReality["shortIds"]
				}
			}
		}
	}
	if !reflect.DeepEqual(original, candidate) {
		return fmt.Errorf("refusing mutation: fields outside clients/shortIds would change")
	}
	return nil
}

func decode(raw []byte) (map[string]any, error) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("config is not valid JSON: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("config must be a JSON object")
	}
	return root, nil
}

func inboundAt(root map[string]any, index int) (map[string]any, error) {
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return nil, fmt.Errorf("config has no inbounds array")
	}
	if index < 0 || index >= len(inbounds) {
		return nil, fmt.Errorf("inbound index %d out of range", index)
	}
	in, ok := inbounds[index].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("inbound %d is not an object", index)
	}
	return in, nil
}

func encode(root map[string]any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(root); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
