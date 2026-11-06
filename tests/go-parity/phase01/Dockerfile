FROM golang:1.24

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=local
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 jq git ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
