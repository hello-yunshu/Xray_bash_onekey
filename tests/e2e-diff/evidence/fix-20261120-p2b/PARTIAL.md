# fix-20261120-p2b — partial run (stopped)

Commit `f217a2fa8656c86471f18c4d8b0b858d438f5a87`.

This run is **not** a full-matrix verdict. It was stopped after OPS-31 because the
container network could not download packages:

- OPS-19 `BLOCKER`: GitHub Nginx package download stalled (same item PASSed in 96s
  in `fix-20261120-p2`).
- OPS-31 bash install `rc=124`: `apt-get update` / Nginx download stalled, then
  `curl: (18) Transferred a partial file`; the interactive menu session then hit
  the expect timeout. The Go side was never started.
- OPS-31/32 therefore have no verdict here.

Valid results kept from this run: M1-M10, E1-E7 `allPassed`, OPS-09 `PASS`.
E8 failed only `oldLinkCaptured` / `backupHasOldShareUri` (driver host choice,
later fixed in `go_edit_reality.sh`), and OPS-21 `HARNESS-ERROR` (share refused a
directly edited config; product behaviour fixed afterwards). Both are re-run in
the follow-up targeted run.
