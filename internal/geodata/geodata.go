// Package geodata downloads the GeoIP/GeoSite assets shared by the scheduler
// and the traffic blocker. Every asset is verified against the release's
// .sha256sum before anything is written, matching the Bash geo_update.sh.
package geodata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultURL is the release Bash also downloads from.
const DefaultURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

// DirRel is where Xray finds the assets (XRAY_LOCATION_ASSET).
const DirRel = "etc/idleleo/share/xray"

// Assets are the two files every consumer needs.
var Assets = []string{"geoip.dat", "geosite.dat"}

// MaxBytes bounds one download. Both assets are far below it.
const MaxBytes = 64 << 20

const maxChecksumBytes = 4 << 10

var client = &http.Client{Timeout: 120 * time.Second}

// Fetch downloads every asset and its checksum, verifies them, and returns the
// payloads. Nothing is returned unless all assets verified.
func Fetch(ctx context.Context, baseURL string) (map[string][]byte, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = DefaultURL
	}
	payloads := make(map[string][]byte, len(Assets))
	for _, asset := range Assets {
		want, err := fetchChecksum(ctx, base+"/"+asset+".sha256sum", asset)
		if err != nil {
			return nil, fmt.Errorf("%s checksum: %w", asset, err)
		}
		data, err := fetchAsset(ctx, base+"/"+asset)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", asset, err)
		}
		got := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(got[:]), want) {
			return nil, fmt.Errorf("%s: sha256 mismatch (downloaded %s, release says %s); keeping the previous file",
				asset, hex.EncodeToString(got[:]), want)
		}
		payloads[asset] = data
	}
	return payloads, nil
}

// fetchChecksum reads the release checksum file and extracts the line for
// asset. The usual format is "<hex>  <name>", optionally with a "*" marker.
func fetchChecksum(ctx context.Context, url, asset string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("origin returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumBytes+1))
	if err != nil {
		return "", fmt.Errorf("download interrupted: %w", err)
	}
	if len(body) > maxChecksumBytes {
		return "", errors.New("checksum file is larger than 4KiB")
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset && len(fields[0]) == sha256.Size*2 {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("release checksum file has no entry for %s", asset)
}

func fetchAsset(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("origin returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download interrupted: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("origin returned an empty asset")
	}
	if len(b) > MaxBytes {
		return nil, errors.New("origin asset is larger than the 64MiB limit")
	}
	if b[0] == '<' || b[0] == '{' {
		return nil, errors.New("origin returned HTML/JSON instead of a GeoData asset")
	}
	return b, nil
}
