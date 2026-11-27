FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash coreutils git grep procps python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
