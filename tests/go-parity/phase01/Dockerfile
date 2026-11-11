FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=local
ENV GOPROXY=off
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 jq git ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
