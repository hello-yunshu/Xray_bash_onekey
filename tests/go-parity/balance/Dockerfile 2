# Disposable systemd container used to generate the REAL Bash balance artifacts
# and to exercise the Nginx stream front locally. Derived from the A2 image so
# the Bash behaviour is produced by the same base as the real-install evidence.
FROM idleleo-a2-bash:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nginx libnginx-mod-stream \
    && rm -rf /var/lib/apt/lists/*
