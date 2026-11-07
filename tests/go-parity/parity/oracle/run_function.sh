#!/usr/bin/env bash
# Invokes real repo functions if BASH_REPO was supplied. Otherwise pinned subset.
# subprocess process per case; no modifications to server. _TEST_MODE bypasses main entry.
set -uo pipefail
if [[ -n "${BASH_REPO:-}" ]]; then
  if [[ ! -f "${BASH_REPO}/install.sh" ]]; then echo "BASH_REPO install.sh missing" >&2;exit 99;fi
  export _TEST_MODE=1
  source "${BASH_REPO}/install.sh" >/dev/null || exit 98
else
  source "$(dirname "$0")/pinned-extract.sh" || exit 97
fi
fn="${1:-}";shift || :
case "$fn" in
  version_compare|version_series_difference|relay_is_valid_host|format_uri_authority_host|yaml_quote_scalar|format_xhttp_path|vless_urlquote) "$fn" "$@" ;;
  *) echo "unknown function" >&2;exit 4;;
esac
