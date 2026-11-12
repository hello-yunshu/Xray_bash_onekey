package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

// statsCommand implements the read-only `--stats` replacement. It queries the
// running Xray API with reset=false, so it never mutates counters or files.
func statsCommand(ctx context.Context, opts Options, cfg config, args []string) int {
	if rc, ok := checkFlags(opts, cfg, args, "stats"); ok && rc != 0 {
		return rc
	}
	cfg.json = cfg.json || hasFlag(args, "--json")
	// The legacy `--stats` flag required root; keeping the same exit code and
	// boundary avoids silently widening what a non-root caller can query on a
	// real installation.
	if cfg.root == "/" && os.Geteuid() != 0 {
		fmt.Fprint(opts.Err, "stats query requires root\n")
		return 5
	}
	timeout := 30 * time.Second
	if v := flagValue(args, "--timeout"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			fmt.Fprint(opts.Err, "invalid --timeout\n")
			return 2
		}
		timeout = d
	}
	paths, err := host.NewPaths(cfg.root)
	if err != nil {
		return fail(opts, cfg, err)
	}
	rel := paths.RuntimeConfig()
	if v := flagValue(args, "--path"); v != "" {
		// --path follows the same rule as every other read-only override: it is
		// relative to --root, never an absolute host path, and ".." is refused.
		rel = v
	}
	cfgPath, err := paths.Join(rel, false)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(opts.Err, "stats unavailable: no runtime config at %s\n", filepath.Join(cfg.root, filepath.Clean(rel)))
			return 3
		}
		fmt.Fprintf(opts.Err, "stats --path must be a relative path inside --root (%s)\n", err)
		return 2
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(opts.Err, "stats unavailable: no runtime config at %s\n", cfgPath)
			return 3
		}
		fmt.Fprint(opts.Err, err.Error()+"\n")
		return 1
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		fmt.Fprint(opts.Err, "runtime config is not valid JSON\n")
		return 3
	}
	server := statsListen(doc)
	if server == "" {
		fmt.Fprint(opts.Err, "stats unavailable: stats/api.listen is not configured\n")
		return 3
	}
	pattern := flagValue(args, "--pattern")
	if pattern == "" {
		pattern = "inbound>>>"
	}
	res, err := host.Run(ctx, host.ExecSpec{
		Path:    "xray",
		Args:    []string{"api", "statsquery", "--server=" + server, "-pattern", pattern, "-reset=false"},
		Timeout: timeout,
	})
	if err != nil {
		fmt.Fprint(opts.Err, "stats query failed: "+err.Error()+"\n")
		return 8
	}
	if res.ExitCode != 0 {
		fmt.Fprintf(opts.Err, "stats query failed (exit %d): %s\n", res.ExitCode, strings.TrimSpace(res.Stderr))
		return 8
	}
	if cfg.json {
		var parsed any
		if err := json.Unmarshal([]byte(res.Stdout), &parsed); err != nil {
			fmt.Fprint(opts.Err, "stats query returned invalid JSON\n")
			return 8
		}
		return writeJSON(opts, parsed)
	}
	var out struct {
		Stat []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		fmt.Fprint(opts.Err, "stats query returned invalid JSON\n")
		return 8
	}
	if len(out.Stat) == 0 {
		fmt.Fprintf(opts.Out, "server=%s stats=empty\n", server)
		return 0
	}
	for _, s := range out.Stat {
		fmt.Fprintf(opts.Out, "%s=%v\n", s.Name, s.Value)
	}
	return 0
}

func statsListen(doc map[string]any) string {
	api, _ := doc["api"].(map[string]any)
	if api == nil {
		return ""
	}
	switch v := api["listen"].(type) {
	case string:
		return v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				return s
			}
		}
	}
	return ""
}
