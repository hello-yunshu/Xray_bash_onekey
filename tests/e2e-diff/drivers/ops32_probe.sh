#!/usr/bin/env bash
# OPS-32 client probe. Sends <count> sequential GETs through the managed Nginx
# TLS front and records one TSV line per request:
#
#   <epoch>  <phase>  <seq>  <curl rc>  <http code>  <body>
#
# Usage:
#   ops32_probe.sh <host> <path> <out> <phase> <count> <interval> [stop_body]
#
# <host> is resolved to 127.0.0.1 with --resolve, <path> is the ws location the
# install generated, <interval> is a sleep between requests (0 = back-to-back),
# <stop_body> stops the loop as soon as that body is seen (used by recovery).
set -uo pipefail

host=$1
path=$2
out=$3
phase=$4
count=$5
interval=$6
stop_body=${7:-}

seq=0
while (( seq < count )); do
    seq=$((seq + 1))
    ts=$(date +%s.%N)
    resp=$(curl -skS --max-time 5 --resolve "$host:443:127.0.0.1" \
        -w $'\n%{http_code}' "https://$host$path?phase=$phase&seq=$seq" 2>/dev/null)
    rc=$?
    code=$(printf '%s\n' "$resp" | tail -n1)
    body=$(printf '%s\n' "$resp" | sed '$d' | tr -d '\r\n')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$ts" "$phase" "$seq" "$rc" "${code:-000}" "$body" >>"$out"
    if [[ -n "$stop_body" && "$body" == "$stop_body" ]]; then
        exit 0
    fi
    if [[ "$interval" != "0" ]]; then
        sleep "$interval"
    fi
done
