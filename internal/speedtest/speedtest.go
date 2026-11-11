// Package speedtest measures downstream throughput against an HTTP endpoint.
// It exists so the Bash entry points can drop superspeed.sh: the measurement is
// a plain GET loop in this binary, with no downloaded script and no Ookla-style
// third-party binary.
package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultServer answers /__down?bytes=N with N bytes of payload.
	DefaultServer = "https://speed.cloudflare.com"
	// DefaultBytes is the payload size of one sample.
	DefaultBytes = 10_000_000
	// DefaultSamples is how many samples are averaged.
	DefaultSamples = 3
	// DefaultTimeout bounds one sample so a stalled peer cannot hang the CLI.
	DefaultTimeout = 15 * time.Second
)

// Options controls one measurement run.
type Options struct {
	Server  string
	Bytes   int
	Samples int
	Timeout time.Duration
}

// Result is the stable JSON shape printed by `idleleo speedtest --json`.
type Result struct {
	Server     string    `json:"server"`
	DownMbps   float64   `json:"downMbps"`
	Bytes      int64     `json:"bytes"`
	DurationMS int64     `json:"durationMs"`
	Samples    []float64 `json:"samplesMbps"`
	StartedAt  time.Time `json:"startedAt"`
}

func (o Options) normalized() (Options, error) {
	if o.Server == "" {
		o.Server = DefaultServer
	}
	parsed, err := url.Parse(o.Server)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return o, fmt.Errorf("invalid server URL %q: want http(s)://host", o.Server)
	}
	if o.Bytes <= 0 {
		o.Bytes = DefaultBytes
	}
	if o.Samples <= 0 {
		o.Samples = DefaultSamples
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	return o, nil
}

// Run samples the endpoint and returns the mean throughput of the samples that
// completed. It fails when every sample fails, so callers can rely on a nonzero
// exit instead of parsing output.
func Run(ctx context.Context, opts Options) (Result, error) {
	opts, err := opts.normalized()
	if err != nil {
		return Result{}, err
	}
	endpoint := strings.TrimRight(opts.Server, "/") + fmt.Sprintf("/__down?bytes=%d", opts.Bytes)
	client := &http.Client{Timeout: opts.Timeout}

	result := Result{Server: opts.Server, StartedAt: time.Now().UTC(), Samples: []float64{}}
	var failures []string
	var total float64
	for i := 0; i < opts.Samples; i++ {
		sampleCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		mbps, read, err := sample(sampleCtx, client, endpoint)
		cancel()
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		result.Samples = append(result.Samples, round(mbps))
		result.Bytes += read
		total += mbps
	}
	if len(result.Samples) == 0 {
		return Result{}, fmt.Errorf("speedtest failed: %s", strings.Join(failures, "; "))
	}
	result.DownMbps = round(total / float64(len(result.Samples)))
	result.DurationMS = time.Since(result.StartedAt).Milliseconds()
	return result, nil
}

func sample(ctx context.Context, client *http.Client, endpoint string) (float64, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	read, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return 0, read, err
	}
	if read == 0 || elapsed <= 0 {
		return 0, read, errors.New("empty measurement")
	}
	return float64(read) * 8 / elapsed / 1e6, read, nil
}

func round(value float64) float64 {
	return float64(int64(value*100+0.5)) / 100
}
