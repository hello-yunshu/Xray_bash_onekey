// Package componentupdate upgrades the managed Xray/Nginx artifacts with an
// explicit, digest-verified manifest and a backup/health/rollback transaction.
package componentupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// KindXray and KindNginx are the managed components this package updates.
	KindXray  = "xray"
	KindNginx = "nginx"

	maxManifestSize = 1 << 20
	maxAssetSize    = 64 << 20
)

var (
	// ErrManifest marks an unreadable or invalid manifest (exit 3).
	ErrManifest = errors.New("invalid component manifest")
	// ErrComponentMismatch marks a manifest for a different component (exit 3).
	ErrComponentMismatch = errors.New("manifest component mismatch")
	// ErrDowngrade refuses to install an older version (exit 4).
	ErrDowngrade = errors.New("refusing to downgrade")
	// ErrDigestMismatch marks a size or sha256 mismatch (exit 5).
	ErrDigestMismatch = errors.New("downloaded artifact does not match the manifest")
	// ErrHealth marks a failed post-activation health check (exit 6).
	ErrHealth = errors.New("new component failed its health check")
	// ErrRollback marks a failed rollback after activation (exit 10).
	ErrRollback = errors.New("rollback failed; manual recovery required")
)

var (
	dottedVersion = regexp.MustCompile(`^[vV]?[0-9]+(\.[0-9]+)*$`)
	hexDigest     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// Manifest is the upgrade contract. The component and digest are mandatory so a
// version string alone can never trigger a write.
type Manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Component     string `json:"component"`
	Version       string `json:"version"`
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"sizeBytes"`
	URL           string `json:"url"`
}

// LoadManifest reads and validates a manifest from an http(s) URL or an
// absolute local path.
func LoadManifest(ctx context.Context, source string) (Manifest, error) {
	data, err := readSource(ctx, source, maxManifestSize)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: invalid JSON: %v", ErrManifest, err)
	}
	m.Component = strings.ToLower(strings.TrimSpace(m.Component))
	if m.SchemaVersion != 1 {
		return Manifest{}, fmt.Errorf("%w: unsupported schemaVersion %d", ErrManifest, m.SchemaVersion)
	}
	if m.Component != KindXray && m.Component != KindNginx {
		return Manifest{}, fmt.Errorf("%w: component %q is not xray or nginx", ErrManifest, m.Component)
	}
	m.Version = normalizeVersion(m.Version)
	if !dottedVersion.MatchString(m.Version) {
		return Manifest{}, fmt.Errorf("%w: version %q is not a dotted version", ErrManifest, m.Version)
	}
	if !hexDigest.MatchString(m.SHA256) {
		return Manifest{}, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrManifest)
	}
	m.SHA256 = strings.ToLower(m.SHA256)
	m.URL = strings.TrimSpace(m.URL)
	if m.URL == "" {
		return Manifest{}, fmt.Errorf("%w: url is required", ErrManifest)
	}
	if m.SizeBytes <= 0 {
		return Manifest{}, fmt.Errorf("%w: sizeBytes must be positive", ErrManifest)
	}
	return m, nil
}

// FetchAsset downloads the artifact and verifies its declared size and digest.
func FetchAsset(ctx context.Context, m Manifest) ([]byte, error) {
	data, err := readSource(ctx, m.URL, maxAssetSize)
	if err != nil {
		return nil, err
	}
	if m.SizeBytes > 0 && int64(len(data)) != m.SizeBytes {
		return nil, fmt.Errorf("%w: size %d != %d", ErrDigestMismatch, len(data), m.SizeBytes)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return nil, fmt.Errorf("%w: sha256 %s != %s", ErrDigestMismatch, hex.EncodeToString(sum[:]), m.SHA256)
	}
	return data, nil
}

// CompareVersions compares two dotted versions numerically. Missing trailing
// components count as zero, so 1.8 == 1.8.0.
func CompareVersions(a, b string) (int, error) {
	a, b = normalizeVersion(a), normalizeVersion(b)
	if !dottedVersion.MatchString(a) || !dottedVersion.MatchString(b) {
		return 0, fmt.Errorf("%w: cannot compare %q and %q", ErrManifest, a, b)
	}
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
}

func readSource(ctx context.Context, source string, limit int64) ([]byte, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, errors.New("empty source")
	}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		client := &http.Client{
			Timeout: 60 * time.Second,
			// A digest-verified manifest must never be silently fetched over a
			// weaker transport: an https URL may not redirect down to http.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
					return fmt.Errorf("refusing to redirect %s to %s", via[0].URL, req.URL)
				}
				return nil
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: HTTP %d", source, resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("%s: larger than %d bytes", source, limit)
		}
		return data, nil
	}
	if !filepath.IsAbs(source) {
		return nil, fmt.Errorf("%s: source must be an absolute path or http(s) URL", source)
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", source, limit)
	}
	return data, nil
}
