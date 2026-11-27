# F23 persistent language preference verification

The first fixture attempt tried to execute a Linux/arm64 Go binary directly on the macOS host and stopped with `Exec format error` before running any behavior checks. That failed attempt is preserved at the start of `commands.log` with host paths redacted; `redaction-map.json` records the pre/post hashes.

The same fixture then ran inside the real `golang:1.27.4` Linux/arm64 container. It executed the Go CLI and Bash baseline and completed **106 checks with 0 failures**. It verified the persistent `language.conf` default, explicit `--lang` precedence, safe fallback behavior, sandbox marker requirement for writes, no writes from read operations, and the existing six-catalog Bash comparison. The tested binary SHA256 is in `fixture-result.json`.

Additional verification on the modified Go tree:

- `go test ./...`: exit 0; full output in `go-test-all.log`.
- `go vet ./...`: exit 0; output in `go-vet.log`.
- `gofmt -l cmd internal`: exit 0, no files listed; output in `gofmt.log`.
- Running `language set en` as UID 65534 against the real root returned `root required`, exit 1; no system file was written.

OPS-30 remains unresolved as a full migration row: Go now supports persistent selection and a per-command override, but its Go catalogs are complete only for zh/en and its TTY menu is not localized or adaptive like Bash. This evidence does not approve that remaining difference.
