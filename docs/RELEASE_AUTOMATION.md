# Cross-repository release automation

The release chain is split across three repositories, but synchronization is automatic:

1. A same-repository Xray PR passes `Test Install`.
2. `Sync Rill Canonical` loads its automation code from protected `main`, compares the PR's five `rill_xray_agent_*.sh` integration files, rebuilds and verifies the canonical payload when needed, opens a Rill PR, waits for its checks, merges it, and commits the canonical bundle and SHA back to the same Xray branch.
3. After the Xray PR reaches `main`, `Publish Shell Version` reads `shell_version` from `install.sh`, opens a version API PR, waits for its checks, merges it, and refreshes the CDN cache.

## One-time credential

Add an Actions secret named `RELEASE_AUTOMATION_TOKEN` to `Xray_bash_onekey`. Use a fine-grained token restricted to these repositories:

- `hello-yunshu/Xray_bash_onekey`
- `hello-yunshu/rill-xray-agent`
- `hello-yunshu/Xray_bash_onekey_api`

Grant repository permissions `Contents: Read and write`, `Pull requests: Read and write`, and permission to update workflow files. For a classic token, include the `workflow` scope. The workflows fail closed before checkout or mutation when the secret is absent.

The token is used only for cross-repository branches and pull requests. Each generated PR is merged only after all of its checks complete successfully. A failed or timed-out check leaves the PR open and stops the chain.

## Manual recovery

Re-run the affected PR's `Test Install` workflow to retry canonical synchronization. `Publish Shell Version` also supports `workflow_dispatch` from `main`. All transforms are idempotent, so an already synchronized repository produces no commit.
