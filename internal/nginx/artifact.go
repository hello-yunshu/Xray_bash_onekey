package nginx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Repository is the release repository that builds the managed Nginx artifact.
const Repository = "hello-yunshu/Xray_bash_onekey_Nginx"

// ReleaseBaseURL is the default GitHub Releases download root.
const ReleaseBaseURL = "https://github.com/" + Repository + "/releases/download"

// VersionsCDNURL and VersionsOriginURL mirror install.sh; the CDN is tried
// first and the raw origin is the fallback.
const (
	VersionsCDNURL    = "https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json"
	VersionsOriginURL = "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/xray_shell_versions.json"
)

const (
	maxVersionsSize = 1 << 20
	maxManifestSize = 1 << 20
	maxArtifactSize = 64 << 20
)

var dottedVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+$`)

// BuildVersion is the subset of xray_shell_versions.json the installer needs.
type BuildVersion struct {
	NginxBuildOnlineVersion string `json:"nginx_build_online_version"`
}

// Manifest is the Nginx release manifest. Every field that gates an install is
// kept so validation can fail closed instead of silently accepting a partial
// record.
type Manifest struct {
	SchemaVersion int      `json:"schema_version"`
	Tag           string   `json:"tag"`
	GeneratedAt   string   `json:"generated_at"`
	Versions      Versions `json:"versions"`
	Assets        []Asset  `json:"assets"`
}

// Versions records the upstream component versions baked into the artifact.
type Versions struct {
	NginxBuild string `json:"nginx_build"`
	Nginx      string `json:"nginx"`
	OpenSSL    string `json:"openssl"`
	Jemalloc   string `json:"jemalloc"`
	Pcre2      string `json:"pcre2"`
	Zlib       string `json:"zlib"`
}

// Asset is one architecture entry in the release manifest.
type Asset struct {
	Arch         string   `json:"arch"`
	Filename     string   `json:"filename"`
	SHA256       string   `json:"sha256"`
	SizeBytes    int64    `json:"size_bytes"`
	BinarySHA256 string   `json:"binary_sha256"`
	LinkMode     string   `json:"link_mode"`
	Versions     Versions `json:"versions"`
}

// Artifact is a resolved and digest-verified Nginx release.
type Artifact struct {
	Build       string
	Version     Versions
	Asset       Asset
	ManifestURL string
	AssetURL    string
	Data        []byte
}

// Options controls resolution. Zero values use the production endpoints and the
// current GOARCH.
type Options struct {
	VersionsURLs   []string
	ReleaseBaseURL string
	Arch           string
	Client         *http.Client
}

func (o Options) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (o Options) versionsURLs() []string {
	if len(o.VersionsURLs) > 0 {
		return o.VersionsURLs
	}
	return []string{VersionsCDNURL, VersionsOriginURL}
}

func (o Options) releaseBase() string {
	if o.ReleaseBaseURL != "" {
		return o.ReleaseBaseURL
	}
	return ReleaseBaseURL
}

func (o Options) arch() (string, error) {
	if o.Arch != "" {
		return o.Arch, nil
	}
	return Arch()
}

// Arch maps GOARCH onto the manifest's arch names.
func Arch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86", nil
	case "arm64":
		return "arm", nil
	default:
		return "", fmt.Errorf("no managed Nginx build for GOARCH %q", runtime.GOARCH)
	}
}

// Resolve fetches the online build version, validates the mandatory manifest,
// downloads the arch artifact and verifies its SHA256 before returning it.
func Resolve(ctx context.Context, opts Options) (Artifact, error) {
	arch, err := opts.arch()
	if err != nil {
		return Artifact{}, err
	}
	build, err := FetchBuildVersion(ctx, opts)
	if err != nil {
		return Artifact{}, err
	}
	manifestURL := strings.TrimRight(opts.releaseBase(), "/") + "/v" + build + "/release-manifest.json"
	manifest, err := FetchManifest(ctx, opts.client(), manifestURL)
	if err != nil {
		return Artifact{}, err
	}
	asset, err := manifest.AssetForArch(arch)
	if err != nil {
		return Artifact{}, err
	}
	if err := manifest.validate(build, asset); err != nil {
		return Artifact{}, err
	}
	assetURL := strings.TrimRight(opts.releaseBase(), "/") + "/v" + build + "/" + asset.Filename
	data, err := DownloadVerified(ctx, opts.client(), assetURL, asset)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Build:       build,
		Version:     manifest.Versions,
		Asset:       asset,
		ManifestURL: manifestURL,
		AssetURL:    assetURL,
		Data:        data,
	}, nil
}

// FetchBuildVersion reads nginx_build_online_version, trying each URL in order.
func FetchBuildVersion(ctx context.Context, opts Options) (string, error) {
	client := opts.client()
	var lastErr error
	for _, u := range opts.versionsURLs() {
		b, err := fetchLimited(ctx, client, u, maxVersionsSize)
		if err != nil {
			lastErr = err
			continue
		}
		var v BuildVersion
		if err := json.Unmarshal(b, &v); err != nil {
			lastErr = fmt.Errorf("%s: versions JSON is invalid: %w", u, err)
			continue
		}
		build := strings.TrimSpace(v.NginxBuildOnlineVersion)
		if !dottedVersion.MatchString(build) {
			lastErr = fmt.Errorf("%s: nginx_build_online_version %q is not a dotted version", u, build)
			continue
		}
		return build, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no versions URL configured")
	}
	return "", fmt.Errorf("Nginx build version unavailable: %w", lastErr)
}

// FetchManifest downloads and parses the release manifest.
func FetchManifest(ctx context.Context, client *http.Client, manifestURL string) (Manifest, error) {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	b, err := fetchLimited(ctx, client, manifestURL, maxManifestSize)
	if err != nil {
		return Manifest{}, fmt.Errorf("Nginx release manifest unavailable: %w", err)
	}
	return ParseManifest(b)
}

// ParseManifest decodes a release manifest.
func ParseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("Nginx release manifest is not valid JSON: %w", err)
	}
	if m.SchemaVersion != 1 {
		return Manifest{}, fmt.Errorf("unsupported Nginx manifest schema_version %d", m.SchemaVersion)
	}
	if !dottedVersion.MatchString(m.Versions.NginxBuild) {
		return Manifest{}, fmt.Errorf("manifest nginx_build %q is not a dotted version", m.Versions.NginxBuild)
	}
	if m.Tag != "v"+m.Versions.NginxBuild {
		return Manifest{}, fmt.Errorf("manifest tag %q does not match nginx_build %q", m.Tag, m.Versions.NginxBuild)
	}
	seen := map[string]bool{}
	for _, a := range m.Assets {
		if a.Arch == "" || a.Arch == "null" {
			return Manifest{}, errors.New("manifest asset without arch")
		}
		if seen[a.Arch] {
			return Manifest{}, fmt.Errorf("manifest has duplicate arch %q", a.Arch)
		}
		seen[a.Arch] = true
	}
	return m, nil
}

// AssetForArch returns the single asset for arch.
func (m Manifest) AssetForArch(arch string) (Asset, error) {
	var found []Asset
	for _, a := range m.Assets {
		if a.Arch == arch {
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		return Asset{}, fmt.Errorf("manifest has %d assets for arch %q, want exactly 1", len(found), arch)
	}
	return found[0], nil
}

func (m Manifest) validate(build string, a Asset) error {
	if m.Versions.NginxBuild != build {
		return fmt.Errorf("manifest build %q does not match requested %q", m.Versions.NginxBuild, build)
	}
	if a.Filename != "xray-nginx-custom-"+a.Arch+".tar.gz" {
		return fmt.Errorf("manifest filename %q does not match arch contract for %q", a.Filename, a.Arch)
	}
	if !isSHA256(a.SHA256) {
		return fmt.Errorf("manifest sha256 %q is invalid", a.SHA256)
	}
	if a.SizeBytes <= 0 {
		return fmt.Errorf("manifest size_bytes for %q is not positive", a.Arch)
	}
	if a.BinarySHA256 != "" && !isSHA256(a.BinarySHA256) {
		return fmt.Errorf("manifest binary_sha256 %q is invalid", a.BinarySHA256)
	}
	return nil
}

// DownloadVerified fetches one artifact and rejects size or digest mismatch.
func DownloadVerified(ctx context.Context, client *http.Client, assetURL string, a Asset) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 300 * time.Second}
	}
	if err := validateHTTPS(assetURL); err != nil {
		return nil, err
	}
	b, err := fetchLimited(ctx, client, assetURL, maxArtifactSize)
	if err != nil {
		return nil, fmt.Errorf("Nginx artifact download failed: %w", err)
	}
	if int64(len(b)) != a.SizeBytes {
		return nil, fmt.Errorf("Nginx artifact size mismatch: got %d want %d bytes", len(b), a.SizeBytes)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != strings.ToLower(a.SHA256) {
		return nil, fmt.Errorf("Nginx artifact sha256 mismatch: got %s want %s", got, a.SHA256)
	}
	return b, nil
}

func fetchLimited(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	if err := validateHTTPS(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", rawURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s read failed: %w", rawURL, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", rawURL, limit)
	}
	return b, nil
}

func validateHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("URL %q must use HTTPS (HTTP is allowed only for loopback tests)", rawURL)
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// Extract unpacks a verified artifact into dest. Only regular files and
// directories under the single "nginx/" root are accepted; links, devices and
// any path escape are rejected before anything is written.
func Extract(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("Nginx artifact is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	dest = filepath.Clean(dest)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("Nginx artifact tar is invalid: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if name == "." {
			continue
		}
		if strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("Nginx artifact contains unsafe path %q", hdr.Name)
		}
		if name != "nginx" && !strings.HasPrefix(name, "nginx/") {
			return fmt.Errorf("Nginx artifact entry %q is outside nginx/", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(name)), 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 || hdr.Size > maxArtifactSize {
				return fmt.Errorf("Nginx artifact entry %q has invalid size %d", hdr.Name, hdr.Size)
			}
			target := filepath.Join(dest, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if name == "nginx/sbin/nginx" {
				mode = 0o755
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, hdr.Size)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("Nginx artifact entry %q has forbidden type %d", hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}

// VerifyBinary checks the extracted binary against the manifest's
// binary_sha256 and ELF architecture. An empty digest skips only the digest
// check; the ELF check always runs.
func VerifyBinary(binPath, wantSHA, arch string) error {
	b, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}
	if wantSHA != "" {
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != strings.ToLower(wantSHA) {
			return fmt.Errorf("Nginx binary sha256 mismatch: got %s want %s", got, wantSHA)
		}
	}
	if len(b) < 20 || b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' {
		return errors.New("Nginx binary is not an ELF file")
	}
	want := map[string]uint16{"x86": 62, "arm": 183}[arch]
	if want == 0 {
		return fmt.Errorf("unsupported Nginx arch %q", arch)
	}
	if machine := uint16(b[18]) | uint16(b[19])<<8; machine != want {
		return fmt.Errorf("Nginx binary ELF machine %d does not match arch %q", machine, arch)
	}
	return nil
}
