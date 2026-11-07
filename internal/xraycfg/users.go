package xraycfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

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
