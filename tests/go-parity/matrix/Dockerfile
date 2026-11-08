# Bash install metadata + relay render vs the current Go CLI.
#
# The default base can build its own toolchain from the network. Set
# MATRIX_BASE_IMAGE to a locally cached image that already has go, python3,
# jq and git (for example an existing density test image) when the network
# cannot reach deb.debian.org. The test logic is identical either way.
ARG BASE_IMAGE=golang:1.23-bookworm
FROM ${BASE_IMAGE}
RUN if ! command -v go >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1 \
       || ! command -v jq >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1; then \
        apt-get update && apt-get install -y --no-install-recommends python3 jq git ca-certificates \
        && rm -rf /var/lib/apt/lists/*; \
    fi
COPY run_matrix.py /audit/run_matrix.py
ENV HOME=/tmp GOCACHE=/tmp/gocache GOTOOLCHAIN=local GOPROXY=off
ENTRYPOINT ["python3", "/audit/run_matrix.py"]
