package cli

import (
	"fmt"
	"path/filepath"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/legacybridge"
)

// metadataCommand owns import/export of the single source of truth. Neither
// subcommand writes runtime config, certificates or user data.
func metadataCommand(opts Options, cfg config, args []string) int {
	if len(args) == 0 {
		return usage(opts, cfg.lang, "help")
	}
	sub, rest := args[0], args[1:]
	cfg.json = cfg.json || hasFlag(rest, "--json")
	switch sub {
	case "import":
		if from := flagValue(rest, "--from"); from != "" {
			want := filepath.Join(cfg.root, "etc/idleleo/conf/install_config.json")
			if from != "install_config.json" && from != want {
				fmt.Fprintf(opts.Err, "metadata import only reads %s; it never imports an arbitrary file\n", want)
				return 2
			}
		}
		report, err := legacybridge.ImportMetadata(legacybridge.ImportOptions{
			Root:                 cfg.root,
			AllowContainerWrites: hasFlag(rest, "--container"),
		})
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "state=%s provenance=%s role=%s tls=%s transport=%s\n",
			report.State, report.Provenance, report.Role, report.TLS, report.Transport)
		fmt.Fprintf(opts.Out, "metadata=%s sha256=%s\n", report.MetadataPath, report.MetadataSHA256)
		fmt.Fprintf(opts.Out, "source=%s sha256=%s (unchanged)\n", report.SourcePath, report.SourceSHA256)
		for _, w := range report.Warnings {
			fmt.Fprintf(opts.Out, "warning=%s\n", w)
		}
		return 0
	case "export":
		out := flagValue(rest, "--out")
		report, err := legacybridge.ExportMetadata(legacybridge.ExportOptions{Root: cfg.root, Out: out})
		if err != nil {
			return bridgeFail(opts, cfg, err)
		}
		if cfg.json || out == "" {
			return writeJSON(opts, report)
		}
		fmt.Fprintf(opts.Out, "exported=%s\n", report.Out)
		fmt.Fprintf(opts.Out, "metadata=%s sha256=%s\n", report.MetadataPath, report.MetadataSHA256)
		fmt.Fprintf(opts.Out, "runtime=%s sha256=%s matchesMetadata=%t\n",
			report.RuntimeConfigPath, report.RuntimeSHA256, report.MatchesMetadata)
		if !report.MatchesMetadata {
			fmt.Fprintln(opts.Out, "warning=metadata 与运行配置摘要不一致；deactivate 会拒绝该导出文件")
		}
		return 0
	default:
		return usage(opts, cfg.lang, "help")
	}
}
