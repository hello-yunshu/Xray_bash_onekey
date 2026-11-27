package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hello-yunshu/Xray_bash_onekey/internal/host"
)

const languagePreferencePath = "etc/idleleo/language.conf"

var languageLocales = map[string]string{
	"zh": "",
	"en": "en_US.UTF-8",
	"fr": "fr_FR.UTF-8",
	"fa": "fa_IR.UTF-8",
	"ru": "ru_RU.UTF-8",
	"ko": "ko_KR.UTF-8",
}

// readLanguagePreference shares Bash's language.conf format but treats it as
// data, never shell input. A malformed, unsupported, or unsafe file leaves the
// documented Chinese default in place.
func readLanguagePreference(paths host.Paths) string {
	path, err := paths.Join(languagePreferencePath, false)
	if err != nil {
		return "zh"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "zh"
	}
	values := map[string]string{}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "LANG" && key != "LC_MESSAGES") || strings.ContainsAny(value, "'$`;|<>&") {
			return "zh"
		}
		value = strings.Trim(strings.TrimSpace(value), "\"'")
		if _, duplicate := values[key]; duplicate {
			return "zh"
		}
		values[key] = value
	}
	if values["LANG"] == "" || values["LANG"] != values["LC_MESSAGES"] {
		return "zh"
	}
	for code, locale := range languageLocales {
		if locale != "" && locale == values["LANG"] {
			return code
		}
	}
	return "zh"
}

func languageCommand(opts Options, cfg config, paths host.Paths, args []string) int {
	if len(args) == 1 && args[0] == "show" {
		fmt.Fprintf(opts.Out, "%s\n", readLanguagePreference(paths))
		return 0
	}
	if (len(args) != 2 && len(args) != 3) || args[0] != "set" ||
		(len(args) == 3 && args[2] != "--container") {
		return usage(opts, cfg.lang, "help")
	}
	lang := args[1]
	locale, ok := languageLocales[lang]
	if !ok {
		return usage(opts, cfg.lang, "help")
	}
	if paths.Root == "/" && os.Geteuid() != 0 {
		return fail(opts, cfg, fmt.Errorf("root required"))
	}
	if err := host.RequireSystemWrite(paths.Root, hasFlag(args, "--container")); err != nil {
		return fail(opts, cfg, err)
	}
	dir, err := paths.Join("etc/idleleo", false)
	if err != nil {
		return fail(opts, cfg, err)
	}
	path, err := paths.Join(languagePreferencePath, true)
	if err != nil && !os.IsNotExist(err) {
		return fail(opts, cfg, err)
	}
	if lang == "zh" {
		if err == nil {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				return fail(opts, cfg, removeErr)
			}
		}
		fmt.Fprintln(opts.Out, "zh")
		return 0
	}
	content := "LANG=" + locale + "\nLC_MESSAGES=" + locale + "\n"
	tmp, err := os.CreateTemp(dir, ".language.conf-*")
	if err != nil {
		return fail(opts, cfg, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o644); err == nil {
		_, err = tmp.WriteString(content)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fail(opts, cfg, err)
	}
	// Resolve the destination again after writing the temporary file so a
	// symlink inserted at the preference path cannot redirect the rename.
	path, err = paths.Join(languagePreferencePath, true)
	if err != nil && !os.IsNotExist(err) {
		return fail(opts, cfg, err)
	}
	if err = os.Rename(tmpName, filepath.Join(dir, "language.conf")); err != nil {
		return fail(opts, cfg, err)
	}
	fmt.Fprintln(opts.Out, lang)
	return 0
}
