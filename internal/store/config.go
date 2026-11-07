package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// InboundView is a read-only projection; the original file is never re-encoded.
type InboundView struct {
	Index    int    `json:"index"`
	Tag      string `json:"tag,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Listen   string `json:"listen,omitempty"`
	Port     string `json:"port,omitempty"`
	Network  string `json:"network,omitempty"`
	Security string `json:"security,omitempty"`
}

// CustomView records user-owned sections that must be preserved.
type CustomView struct {
	DNS               bool     `json:"dns"`
	Routing           bool     `json:"routing"`
	Outbounds         bool     `json:"outbounds"`
	OtherTopLevelKeys []string `json:"otherTopLevelKeys"`
}

// ConfigView is the structured read-only view returned by `config inspect`.
type ConfigView struct {
	Path         string        `json:"path"`
	SHA256       string        `json:"sha256"`
	Bytes        int           `json:"bytes"`
	TopLevelKeys []string      `json:"topLevelKeys"`
	Inbounds     []InboundView `json:"inbounds"`
	Custom       CustomView    `json:"custom"`
}

var knownTopLevel = map[string]bool{
	"log": true, "dns": true, "routing": true, "inbounds": true,
	"outbounds": true, "policy": true, "stats": true, "api": true,
	"reverse": true, "observatory": true, "fakedns": true,
	"transport": true, "browserForwarder": true,
}

// LoadRuntimeView resolves and parses the runtime config read-only.
func LoadRuntimeView(paths host.Paths, override string) (ConfigView, error) {
	path, err := ResolveRuntimePath(paths, override)
	if err != nil {
		return ConfigView{}, err
	}
	return LoadConfig(path)
}

// ResolveRuntimePath picks the metadata runtime path unless overridden.
func ResolveRuntimePath(paths host.Paths, override string) (string, error) {
	if override != "" {
		if filepath.IsAbs(override) {
			return override, nil
		}
		return paths.Join(override, false)
	}
	return paths.Join(paths.RuntimeConfig(), false)
}

// LoadConfig reads and parses one Xray JSON file without modifying it.
func LoadConfig(path string) (ConfigView, error) {
	b, _, err := ReadRegular(path, "runtime config")
	if err != nil {
		return ConfigView{}, err
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return ConfigView{}, New(KindCorrupt, "runtime config is not valid JSON", err)
	}
	if root == nil {
		return ConfigView{}, New(KindCorrupt, "runtime config must be a JSON object", nil)
	}
	view := ConfigView{Path: path, SHA256: digest(b), Bytes: len(b)}
	view.TopLevelKeys = keysOf(root)
	view.Inbounds = inboundViews(root["inbounds"])
	view.Custom = CustomView{
		DNS:       presentNonEmpty(root["dns"]),
		Routing:   presentNonEmpty(root["routing"]),
		Outbounds: presentNonEmpty(root["outbounds"]),
	}
	for _, k := range view.TopLevelKeys {
		if !knownTopLevel[k] {
			view.Custom.OtherTopLevelKeys = append(view.Custom.OtherTopLevelKeys, k)
		}
	}
	return view, nil
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func presentNonEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case string:
		return strings.TrimSpace(t) != ""
	default:
		return true
	}
}

func inboundViews(v any) []InboundView {
	arr, ok := v.([]any)
	if !ok {
		return []InboundView{}
	}
	out := make([]InboundView, 0, len(arr))
	for i, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			out = append(out, InboundView{Index: i})
			continue
		}
		v := InboundView{Index: i, Tag: str(m["tag"]), Protocol: str(m["protocol"]), Listen: str(m["listen"]), Port: scalar(m["port"])}
		if ss, ok := m["streamSettings"].(map[string]any); ok {
			v.Network = str(ss["network"])
			v.Security = str(ss["security"])
		}
		out = append(out, v)
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

// RuntimeSnapshot is the exact pre-change state used by the change package.
type RuntimeSnapshot struct {
	Path  string
	Raw   []byte
	SHA   string
	Mode  os.FileMode
	UID   int
	GID   int
	Ino   uint64
	Nlink uint64
}

// ReadRuntimeSnapshot reads bytes plus ownership without following symlinks.
func ReadRuntimeSnapshot(path string) (RuntimeSnapshot, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return RuntimeSnapshot{}, ClassifyOS("runtime config", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return RuntimeSnapshot{}, New(KindUnsupported, "runtime config is a symlink; refusing to modify", nil)
	}
	if !fi.Mode().IsRegular() {
		return RuntimeSnapshot{}, New(KindUnsupported, "runtime config is not a regular file", nil)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return RuntimeSnapshot{}, ClassifyOS("runtime config read", err)
	}
	uid, gid := fileOwner(fi)
	return RuntimeSnapshot{
		Path: path, Raw: b, SHA: digest(b), Mode: fi.Mode().Perm(),
		UID: uid, GID: gid, Ino: inoOf(fi), Nlink: nlinkOf(fi),
	}, nil
}
