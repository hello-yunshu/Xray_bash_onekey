# Phase 00 legacy fixtures

Synthetic, offline samples used by the Phase 00 baseline and by later Bridge
work. They are **test inputs, not production implementation**.

## Provenance

| Item | Value |
|---|---|
| Behaviour baseline | `4752f77c58028ac169c429fe7674c20060b30c9e` |
| Current `main` when Phase 00 was executed | `59a87c6` (install.sh/scripts/config unchanged from the baseline) |
| `install.sh` SHA-256 | `0af8e8f222f26f02904f80bfd0e3cf5cd119b24bbde462019f0b582e1b79cfa6` |
| Config field source | [install.sh `install_config_tls_ws`/`install_config_reality`/`install_config_ws_only`](../../../install.sh#L9065-L9188) |
| Relay renderer source | [install.sh `relay_render_stream_conf`](../../../install.sh#L11212-L11242) |
| Xray templates | [config/vless_reality.json](../../../config/vless_reality.json), [config/vless_tls.json](../../../config/vless_tls.json) |
| Regenerate | `bash tests/fixtures/legacy/generate.sh` |
| Verify hashes | `cd tests/fixtures/legacy && shasum -a 256 -c SHA256SUMS` (`sha256sum -c` on Linux) |

## Redaction / synthetic markers

All values are deliberately non-production:

- UUIDs `1111…` / `6666…`, email `*@example.invalid`.
- Hosts use documentation ranges `203.0.113.0/24`, `198.51.100.0/24` and `.invalid` domains.
- The Reality key pair is a throwaway pair generated once with `xray x25519`; it is never used on a real host.
- Ports are fixture-local (`9443`, `10086–10088`, `8443`) and never 443/80.

No user configuration, certificate, private key or credential is copied into
this directory.

## Samples

| Sample | Represents | Key fields | Validation |
|---|---|---|---|
| `reality-direct/` | F01 Reality without Nginx | `tls=Reality`, `net=raw`, `privateKey`, `shortIds`, `spiderx_path` | `xray -test` **pass** (Xray 26.10.31) |
| `reality-nginx/` | F01 Reality + Nginx front, SNI guard | adds `reality_add_nginx=on`, `reality_nginx_sni_guard=on`, `unknown_sni_policy=reject`, `nginx_build_version` | `xray -test` **pass** (config identical to direct) |
| `tls-multi/` | F02 TLS ws+gRPC+xHTTP, F06/F07 multi-user / loopback | three 127.0.0.1 inbounds, two ws clients, `transport_mode=wsgRPCxhttp` | `xray -test` **pass** |
| `custom-dns-routing/` | F19/F21 user-owned DNS and routing | custom DoH server, extra `socks` outbound, extra routing rule | `xray -test` **pass** |
| `relay/` | F05 relay role (no Xray binary/config/UUID/cert) | `role=relay`, `relay_backend_host/port`, `relay_listen_addr/port`, rendered `relay-stream.conf` | Nginx syntax **未验证** (no Nginx binary in the Phase 00 environment) |
| `xtls-only/` | F26 removed legacy mode, read-only reject | `tls=XTLS`, old `shell_version` | Detect-only; intentionally **no runnable Xray config** |

`xtls-only/` demonstrates the distinction required by the matrix: it marks the
removed install mode (`tls=XTLS`), not the still-supported `xtls-rprx-vision`
flow used by Reality.

## Reproduction commands

```bash
# Regenerate deterministically (requires jq + shasum/sha256sum)
bash tests/fixtures/legacy/generate.sh

# Run the real Xray parser against the supported samples
docker run --rm \
  -v "$PWD/tests/fixtures/legacy":/fx:ro \
  -v /path/to/linux-amd64/xray:/usr/local/bin/xray:ro \
  ubuntu:24.04 bash -c 'mkdir -p /var/log/xray; \
    for f in reality-direct reality-nginx tls-multi custom-dns-routing; do \
      /usr/local/bin/xray -test -config "/fx/$f/xray-config.json"; \
    done'
```

Fixture regeneration is not part of the release pipeline; changing the
templates under `config/` requires re-running the generator and reviewing the
hash diff.
