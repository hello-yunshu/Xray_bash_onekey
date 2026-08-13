#!/usr/bin/env bash
set -euo pipefail

repo=${1:?repository is required}
pr=${2:?pull request number is required}
minimum_checks=${3:-1}
attempts=${PR_CHECK_ATTEMPTS:-90}
interval=${PR_CHECK_INTERVAL:-10}

for ((attempt = 1; attempt <= attempts; attempt++)); do
    payload=$(gh pr view "${pr}" --repo "${repo}" \
        --json state,mergeable,statusCheckRollup)
    state=$(jq -r '.state' <<<"${payload}")
    [[ "${state}" == "OPEN" ]] || {
        [[ "${state}" == "MERGED" ]] && exit 0
        echo "PR ${repo}#${pr} entered unexpected state ${state}" >&2
        exit 1
    }

    count=$(jq '.statusCheckRollup | length' <<<"${payload}")
    pending=$(jq '[.statusCheckRollup[] | select(.status != "COMPLETED")] | length' <<<"${payload}")
    failed=$(jq '[.statusCheckRollup[] | select(
        .status == "COMPLETED" and
        (.conclusion != "SUCCESS" and .conclusion != "NEUTRAL" and .conclusion != "SKIPPED")
    )] | length' <<<"${payload}")
    mergeable=$(jq -r '.mergeable' <<<"${payload}")

    if ((failed > 0)); then
        gh pr checks "${pr}" --repo "${repo}" || true
        echo "PR ${repo}#${pr} has a failed check" >&2
        exit 1
    fi
    if ((count >= minimum_checks && pending == 0)) && [[ "${mergeable}" == "MERGEABLE" ]]; then
        gh pr merge "${pr}" --repo "${repo}" --merge --delete-branch
        [[ "$(gh pr view "${pr}" --repo "${repo}" --json state --jq .state)" == "MERGED" ]]
        exit 0
    fi
    sleep "${interval}"
done

echo "timed out waiting for PR ${repo}#${pr}" >&2
exit 1
