package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// ManagerSchemaVersion is the Phase 01 metadata schema.
const ManagerSchemaVersion = 1

var shaHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Metadata is the ownership record. It never stores UUIDs, private keys or
// shortIds; those remain in the native runtime config.
type Metadata struct {
	SchemaVersion     int      `json:"schemaVersion"`
	ActiveEngine      string   `json:"activeEngine"`
	Provenance        string   `json:"provenance,omitempty"`
	Role              string   `json:"role"`
	TLS               string   `json:"tls"`
	Transport         string   `json:"transport"`
	RuntimeConfigPath string   `json:"runtimeConfigPath"`
	RuntimeSHA256     string   `json:"runtimeSha256"`
	OwnedResources    []string `json:"ownedResources"`
	UpdatedAt         string   `json:"updatedAt"`
}

// LoadMetadata reads and validates metadata without writing.
func LoadMetadata(paths host.Paths) (Metadata, string, error) {
	p, err := paths.Join(paths.ManagerMetadata(), false)
	if err != nil {
		if os.IsNotExist(err) {
			return Metadata{}, "", New(KindNotFound, "manager metadata not installed", err)
		}
		return Metadata{}, "", ClassifyOS("manager metadata path", err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return Metadata{}, "", ClassifyOS("manager metadata read", err)
	}
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Metadata{}, "", New(KindCorrupt, "manager metadata is not valid JSON", err)
	}
	if err := rejectSecrets(raw, "metadata"); err != nil {
		return Metadata{}, "", err
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return Metadata{}, "", New(KindCorrupt, "manager metadata schema is invalid", err)
	}
	if m.SchemaVersion > ManagerSchemaVersion {
		return m, digest(b), New(KindSchemaHigh,
			fmt.Sprintf("manager metadata schema %d is newer than supported %d", m.SchemaVersion, ManagerSchemaVersion), nil)
	}
	if m.SchemaVersion != ManagerSchemaVersion {
		return m, digest(b), New(KindCorrupt, "manager metadata schemaVersion must be 1", nil)
	}
	if m.ActiveEngine != "xray" {
		return m, digest(b), New(KindUnsupported, "activeEngine is not xray", nil)
	}
	if m.Role != "node" && m.Role != "relay" {
		return m, digest(b), New(KindUnsupported, "role must be node or relay", nil)
	}
	switch m.TLS {
	case "Reality", "TLS", "None":
	default:
		return m, digest(b), New(KindUnsupported, "unsupported tls mode", nil)
	}
	if m.RuntimeSHA256 != "" && !shaHex.MatchString(m.RuntimeSHA256) {
		return m, digest(b), New(KindCorrupt, "runtimeSha256 must be 64 lowercase hex characters", nil)
	}
	return m, digest(b), nil
}

func rejectSecrets(v any, where string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			lower := strings.ToLower(k)
			switch lower {
			case "uuid", "privatekey", "private_key", "shortid", "shortids", "password", "secret":
				return New(KindCorrupt, fmt.Sprintf("%s must not store secret field %q; reference the native config instead", where, k), nil)
			}
			if err := rejectSecrets(child, where+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range t {
			if err := rejectSecrets(child, fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// HashBytes exposes the same SHA256 used for runtime fingerprints.
func HashBytes(b []byte) string { return digest(b) }

// ReadRegular reads a regular file, refusing symlinks and non-files.
func ReadRegular(path, label string) ([]byte, os.FileMode, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, 0, ClassifyOS(label, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, 0, New(KindUnsupported, label+" is a symlink; refusing", nil)
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, New(KindUnsupported, label+" is not a regular file", nil)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, ClassifyOS(label, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, 0, ClassifyOS(label, err)
	}
	return b, fi.Mode(), nil
}

// ValidateManagerPath prevents an absolute or traversing metadata runtime path.
func ValidateManagerPath(rel string) error {
	if rel == "" || strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
		return errors.New("runtimeConfigPath must be a relative path without ..")
	}
	return nil
}
