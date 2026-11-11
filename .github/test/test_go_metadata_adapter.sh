#!/usr/bin/env bash
# S1: Bash must derive config state from Go metadata read-only, fail loudly on
# a missing field, and never fall back to install_config.json defaults.
set -uo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
export _TEST_MODE=1
source "${repo}/install.sh" >/dev/null 2>&1 || true

tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
idleleo_dir="${tmp}/idleleo"
mkdir -p "${idleleo_dir}/v1"
idleleo_go_metadata_file="${idleleo_dir}/v1/metadata.json"
gettext() { printf '%s' "${1:-}"; }
has_jq_binary() { command -v jq >/dev/null 2>&1; }

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# 1. No metadata file: presence is false and every field read fails loudly.
idleleo_go_metadata_present && fail "presence must be false without metadata"
out=$(idleleo_go_metadata_field role 2>&1)
rc=$?
[[ ${rc} -ne 0 ]] || fail "a missing metadata file must fail the read"
[[ ${out} == *"来自 Go 元数据、字段缺失"* ]] || fail "missing-field message not printed: ${out}"

# 2. Transport values are a deliberate mapping, never a guess.
[[ $(idleleo_go_transport_to_shell_mode onlyws) == "onlyws" ]] || fail "onlyws mapping"
[[ $(idleleo_go_transport_to_shell_mode ws) == "onlyws" ]] || fail "ws mapping"
[[ $(idleleo_go_transport_to_shell_mode grpc) == "onlygRPC" ]] || fail "grpc mapping"
[[ $(idleleo_go_transport_to_shell_mode onlyxhttp) == "onlyxhttp" ]] || fail "xhttp mapping"
[[ $(idleleo_go_transport_to_shell_mode multi) == "wsgRPCxhttp" ]] || fail "multi mapping"
[[ $(idleleo_go_transport_to_shell_mode raw) == "None" ]] || fail "raw mapping"
[[ $(idleleo_go_transport_to_shell_mode stream) == "None" ]] || fail "stream mapping"
if idleleo_go_transport_to_shell_mode tcp; then
    fail "an unknown transport must fail instead of defaulting"
fi

# 3. With jq available, a complete record loads; a missing field aborts.
if has_jq_binary; then
    printf '%s' '{"role":"node","tls":"Reality","transport":"onlyws"}' >"${idleleo_go_metadata_file}"
    idleleo_go_mode_load || fail "a complete metadata record must load"
    [[ ${node_role} == "node" ]] || fail "role=${node_role}"
    [[ ${tls_mode} == "Reality" ]] || fail "tls=${tls_mode}"
    [[ ${transport_mode} == "onlyws" ]] || fail "transport=${transport_mode}"

    printf '%s' '{"role":"node","tls":"Reality"}' >"${idleleo_go_metadata_file}"
    out=$(idleleo_go_mode_load 2>&1)
    rc=$?
    [[ ${rc} -ne 0 ]] || fail "a missing transport must abort the load"
    [[ ${out} == *"字段缺失: transport"* ]] || fail "missing transport message: ${out}"
else
    echo "SKIP: jq not installed, field-read branch not exercised"
fi

echo "PASS: go metadata adapter"
