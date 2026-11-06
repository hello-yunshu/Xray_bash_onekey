FROM golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=local
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 jq git ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
