package cli

import (
	"fmt"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/legacybridge"
)

// rillCommand exposes the Rill handover state without copying agent contents.
func rillCommand(opts Options, cfg config, args []string) int {
	if len(args) == 0 || args[0] != "status" {
		return usage(opts, cfg.lang, "help")
	}
	cfg.json = cfg.json || hasFlag(args[1:], "--json")
	info := legacybridge.RillStatus(cfg.root)
	if cfg.json {
		return writeJSON(opts, map[string]any{"schemaVersion": 1, "rill": info})
	}
	fmt.Fprintf(opts.Out, "installed=%t status=%s enabled=%t mode=%s observationAge=%ds\n",
		info.Installed, info.Status, info.Enabled, info.Mode, info.ObservationAgeSeconds)
	if info.Binary != "" {
		fmt.Fprintf(opts.Out, "binary=%s config=%s observation=%s\n", info.Binary, info.ConfigPath, info.ObservationPath)
	}
	if info.Warning != "" {
		fmt.Fprintf(opts.Out, "warning=%s\n", info.Warning)
	}
	return 0
}
