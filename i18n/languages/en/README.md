# Xray management script

> A one-stop Xray deployment and management tool for Debian, Ubuntu, and CentOS Stream, covering Reality, TLS, ws/gRPC/xHTTP, relay nodes, and Docker.

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE) [![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)](https://github.com/hello-yunshu/Xray_bash_onekey) [![Shell: Bash](https://img.shields.io/badge/shell-Bash-4EAA25)](https://github.com/hello-yunshu/Xray_bash_onekey)

Simplified Chinese | [English](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/en/README.md) | [Français](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fr/README.md) | [Русский](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ru/README.md) | [فارسی](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fa/README.md) | [한국어](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ko/README.md)

## Overview

This is a Bash-based Xray deployment and operations script. It brings installation, certificates, the Nginx front end, client configuration, service management, backup and restore, and routine troubleshooting into one menu, making it suitable for users who want a quick single-server proxy without hand-maintaining the entire configuration stack.

The script generates configuration and orchestrates services, while Xray performs the actual proxying. Reality and TLS modes work best with an Nginx front end. Every critical write is preceded by a syntax check or backup, and failures are rolled back where possible so a running service is not left half-configured.

## Features

| Capability | Description |
|---|---|
| Installation modes | Reality + Nginx, Nginx + TLS, ws/gRPC/xHTTP ONLY, relay node, Docker |
| Transport protocols | WebSocket, gRPC, and xHTTP, individually or combined as `ws+gRPC+xHTTP` |
| Dual-stack networking | Detects IPv4/IPv6 egress, validates domain A/AAAA records separately, and generates matching client endpoints |
| Client output | Share links, QR codes, and Clash profiles; Clash does not currently support xHTTP |
| Security management | fail2ban, traffic blocking, SNI Guard, firewall, and certificate management |
| Daily operations | Service management, configuration changes, log cleanup, port traffic inspection, backup and restore |
| Traffic statistics | Reads uplink, downlink, and total bytes per inbound, with JSON, reset, and live refresh |
| Intelligent assistant | RillML local AI operations assistant for monitoring, diagnosis, and remediation advice |
| Maintenance | Script, Xray, Nginx, and certificate updates, with backup and rollback for critical changes |

## System support

| System | Version | Notes |
|---|---|---|
| Debian | 12, 13 | Uses `apt`; CI covers `debian:12-slim` and `debian:13-slim` |
| Ubuntu | 24.04, 26.04 | Uses `apt`; CI covers `ubuntu:24.04` and `ubuntu:26.04` |
| CentOS Stream | 10 | Uses the RPM package manager; CI covers `quay.io/centos/centos:stream10` |
| Rocky / AlmaLinux | 10+ | Treated as RPM family; major version must be at least 10 |

The script requires root, systemd, a public IP address, and working outbound network access. Installation automatically fills in dependencies such as `curl`, `jq`, `openssl`, `qrencode`, and `nmap`. Reality/TLS modes also require a domain with correct A and/or AAAA records for the server's network.

> Unsupported systems are rejected before installation. CentOS templates vary widely; if compilation or dependency problems occur, use Debian or Ubuntu instead.

## Quick start

Prepare a supported Linux server and run the following command as root:

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

When installation finishes, run `idleleo` to open the management menu. You can also run `idleleo --install-reality`, `idleleo --install-tls`, or `idleleo --install-none` to enter a specific mode directly.

On first use, follow the installation wizard and press Enter to accept defaults for anything you are unsure about. After installation, configure the client from the share link or QR code printed by the script.

## Installation modes

| Mode | Use case | Key details |
|---|---|---|
| Reality + Nginx | Recommended single-server entry point | Optional ws/gRPC/xHTTP simple protocols can be added for load balancing |
| Nginx + TLS | Standard TLS entry point | Automatically requests and renews Let's Encrypt certificates |
| ws/gRPC/xHTTP ONLY | Backend or load-balancing node | No TLS; listens only on `127.0.0.1` by default |
| Relay node | Independent TCP forwarding | Uses Nginx Stream for single-target forwarding and does not install Xray |
| Docker | Containerized deployment | The image includes Xray, Nginx, and the main script |

When installing a ws/gRPC/xHTTP mode, choose `ws`, `gRPC`, `xHTTP`, or `ws+gRPC+xHTTP`. The script generates a port, path, share link, and QR code for each transport. Clash profiles skip xHTTP and the script prints a notice in the output.

## Management menu

Run `idleleo` to open the main menu:

| Option | Function |
|---|---|
| `1` | Installation wizard |
| `2` | Configuration changes |
| `3` | View information |
| `4` | Xray / TLS services and certificates |
| `5` | Update wizard |
| `6` | Additional options (TCP acceleration, Fail2ban, traffic statistics, traffic blocking, logs, network speed) |
| `7` | Backup, restore, and uninstall |
| `8` | Change language |
| `9` | Rill Xray AI operations assistant |
| `0` | Exit |

The "Additional options → Xray traffic statistics" entry provides four actions: enable or disable statistics, view statistics, reset statistics, and live monitoring.

## Common commands

| Action | Command |
|---|---|
| Open the management menu | `idleleo` |
| Show help | `idleleo --help` |
| Install Reality mode | `idleleo --install-reality` |
| Install TLS mode | `idleleo --install-tls` |
| Install ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Install a relay node | `idleleo --install-relay` |
| Show installation information | `idleleo --show` |
| Show Xray access information | `idleleo --xray-access` |
| Show Xray error information | `idleleo --xray-error` |
| Show real-time port traffic | `idleleo --port-traffic` |
| Update the script | `idleleo --update` |
| Update Xray | `idleleo --xray-update` |
| Update Nginx | `idleleo --nginx-update` |
| Configure Fail2ban | `idleleo --set-fail2ban` |
| Configure traffic blocking | `idleleo --traffic-blocker` |
| Back up script-managed files | `idleleo --backup` |
| Restore script-managed files | `idleleo --restore` |
| Uninstall the script with Xray/Nginx | `idleleo --purge` |
| View traffic statistics | `idleleo --stats` / `idleleo --stats --json` |
| Reset traffic statistics | `idleleo --stats-reset` (asks for confirmation; `--yes` skips it) |
| Monitor traffic statistics live | `idleleo --stats-watch` [seconds] |

## Xray traffic statistics

When statistics are enabled, the stats API listens only on `127.0.0.1:10085` by default. Reading is handled by the standalone script `/etc/idleleo/scripts/xray_stats.sh` with `0600 root:root` permissions. The main script only provides the entry point, download, SHA256 verification, and delegation; it does not duplicate query logic.

```bash
idleleo --stats                  # Table: uplink, downlink, and total per inbound
idleleo --stats --json           # Machine-readable JSON
idleleo --stats-reset            # Clear counters after interactive confirmation
idleleo --stats-reset --yes      # Automation confirmation
idleleo --stats-watch 5          # Refresh every 5 seconds; Ctrl-C exits
```

If the stats script is missing, the main script downloads `xray_stats.sh` from the current Release and verifies it with `statsScriptSha256` from `release-manifest.json`. A verification failure affects only reading, not the statistics toggle. If statistics are enabled but `api.listen` is missing, the first `--stats` run explicitly asks whether to add it and restart Xray; refusing leaves the configuration unchanged.

### Exit codes

| Exit code | Meaning |
|---|---|
| `0` | Query succeeded; zero counters are still success |
| `1` | User cancelled reset |
| `2` | Missing prerequisite: statistics disabled, no `api.listen`, Xray not running, API unreachable, script missing, or verification failed |
| `3` | API call or JSON parsing failed |
| `4` | Invalid arguments |
| `5` | Not root or insufficient permissions |
| `130` | Watch interrupted by Ctrl-C |

Failures never print a fake zero: disabled statistics or an unreachable API returns `2`, bad JSON returns `3`, and a non-root user returns `5`.

### Security boundary

> The stats API binds to the loopback address but has no authentication. Other local users can theoretically access the port and read or reset counters. Use it on a single-user VPS and never expose `10085` to the public internet; `--stats-reset` always requires explicit confirmation.

Xray StatsService provides only inbound uplink/downlink and Uptime counters; it does **not provide active connection counts**. For connection counts, use system-level tools or a separate observability solution instead of expecting `--stats` to report them.

## Backup and restore

`idleleo --backup` backs up only script-managed files: `/etc/idleleo`, `/usr/local/nginx`, the Xray binary, systemd units, the root crontab, and ACME state. It is not a full-host backup and does not automatically include data you placed elsewhere.

`idleleo --restore` selects the backup with the newest timestamp. Backups with a checksum manifest verify the SHA256 of every archived file and remove script-managed configuration absent from the backup; older backups without a manifest only receive structural validation and skip cross-mode pruning. User-created files are preserved and services are not started automatically. After restoring across modes, inspect leftover configuration and restart services as needed. If an old backup has no `/usr/local/share/xray` symlink, restore creates it or merges the legacy GeoData directory into `/etc/idleleo/share/xray`, then validates with a real `xray run -test`; a failed self-heal is rolled back, so old backups still restore to a new host without reinstalling.

Backup archives may contain certificates, private keys, and client configuration. Treat them as sensitive files and do not upload them to public locations.

## Upgrade and updates

Update from "Update wizard → Update script" in the management menu, or run:

```bash
idleleo --update                  # Interactive confirmation
idleleo --update --yes            # Non-interactive, auto-confirm within the same release series
idleleo --update --yes --allow-major  # Cross-series update; explicitly lift the restriction
```

`--yes` auto-confirms only updates within the same release series; a cross-series update also requires `--allow-major`. `--allow-major` only lifts the series restriction and does not replace confirmation, so non-interactive use still needs `--yes`. A script update replaces `/etc/idleleo/install.sh` as a whole, recalculates Release URLs for the new script, and synchronizes helper assets.

`--xray-update` updates only the Xray core, while `--nginx-update` updates only Nginx; neither upgrades the script itself. Automatic updates upgrade the script only within the same release series; Xray and Nginx automatic updates still follow API metadata. Run `idleleo --backup` before upgrading.

The legacy XTLS mode no longer offers new-install or reinstall entry points. Existing XTLS services can keep running, but the script cannot reinstall them or switch modes. To continue managing them, back up and uninstall first, then redeploy Reality, TLS, or relay mode.

## Reconfiguration

When the installer runs again on an installed system, it automatically backs up the running configuration and offers three paths:

| Path | Description | Limitation |
|---|---|---|
| Keep configuration and redeploy | Keeps custom routing, outbounds, DNS, and multi-user settings; changes only the fields you select | Does not support transport structure changes, such as ws to gRPC |
| Rebuild from the standard template | Generates a standard template using reusable parameters | Custom routing, outbounds, and DNS may be removed |
| Mode switch | Switches to a different protocol mode, such as Reality to TLS | Reuses only the primary user's UUID/email by default; other users are not migrated |

If any step fails (configuration write, service start, health check, and so on), the script rolls back to the backed-up original configuration. Backup directories use unique timestamps, so repeated reconfigurations do not collide.

## Go manager (experimental, not enabled)

The repository already contains the source of the future Go manager and the migration bridge code, but **the current release does not provide a Go binary and does not enable migration**:

- Fresh installs, `-u`, full reinstall, the menu, `auto_update`, and cron never probe, prompt for, or download any Go asset, and never request the bridge manifest.
- While the manifest URL stays absent, no migration entry point appears; ordinary users see no Go option at all.
- The only entry point is the explicit `--internal-bridge-offer`, used solely for maintainer verification and not exposed to ordinary users.
- The Go manager will only be explicitly enabled in a later release once it is stable enough to switch; until then, keep using the existing Bash management script.

## Troubleshooting

| Symptom | Check first | Suggested action |
|---|---|---|
| Installation rejected | `/etc/os-release` and the system support matrix | Upgrade to a supported system version, or use Debian/Ubuntu |
| Xray is not running | `systemctl status xray`, `idleleo --xray-error` | Check `journalctl -u xray`, the configuration, and port usage |
| Configuration syntax error | `xray run -test -config /etc/idleleo/conf/xray/config.json` | Fix the reported issue, or roll back with `idleleo --restore` |
| Port already in use | `ss -ltnp` | Free the port, or change the listening port from the menu |
| Certificate problem | `idleleo --cert-status` | Check DNS, ports 80/443, and ACME state, then run `idleleo --cert-update` |
| Conflict with existing Nginx | `/usr/local/nginx/sbin/nginx -V`, `systemctl status nginx` | Do not mix with Nginx installed by LNMP or similar scripts; remove the conflict first |
| Statistics return `2` | Statistics toggle, Xray status, `127.0.0.1:10085` | Enable statistics, start Xray, or check `api.listen` |
| Statistics return `3` | API response and JSON structure | Check Xray logs and configuration, and confirm StatsService is available |
| Statistics return `5` | Current user | Run as root, or check file permissions |
| Clash is missing nodes | Protocol type | Clash does not support xHTTP; use a client that supports it |

Logs and diagnostics: `/etc/idleleo/logs/`, `/var/log/xray/`, `idleleo --show`, `idleleo --xray-access`, and `idleleo --xray-error`.

## Frequently asked questions

**Can statistics show active connection counts?** No. StatsService provides inbound uplink/downlink and Uptime counters only; it does not provide connection counts.

**When should Cloudflare users enable the CDN?** Enable the CDN only after installation, certificates, and direct connectivity have been verified. Otherwise the CDN proxy can interfere with certificate issuance.

**Can IPv4 and IPv6 be used together?** Yes. The script detects public egress capability and validates domain A/AAAA records separately. In dual-stack environments, configure both A and AAAA records correctly.

**How do I change the port, UUID, or transport?** Open "Configuration changes" in the menu, or rerun the installation wizard and choose a reconfiguration path. Use the standard template rebuild when changing the transport structure.

**How do I uninstall?** Run `idleleo --purge`. Before uninstalling, run `idleleo --backup` and decide whether to keep configuration and certificates.

**What are the requirements for mapping a custom string to a UUID?** The script uses UUIDv5 mapping, which requires client support. If the client does not support it, use a standard UUID.

**Can I use this directly in production?** First verify connectivity, certificate renewal, backup and restore, and the upgrade path in a test environment before using it in production.

## Security notes

- The stats API binds only to `127.0.0.1` and has no authentication. Do not expose `10085` to the public internet, and do not let untrusted local users access it.
- Reality + Nginx mode enables SNI Guard by default: unknown SNI, empty SNI, and abnormal TLS never reach the Xray Reality backend; `ssl_reject_handshake` isolation is used by default.
- Fail2ban, the firewall, and traffic blocking are optional hardening features. Before enabling them, make sure they cannot lock out your own management access.
- Backup archives, certificates, and client configuration contain sensitive information. Restrict file permissions and avoid sharing them publicly.
- The script requires root; do not use it in production before verifying availability.

## Directories and services

| Item | Path |
|---|---|
| Main directory | `/etc/idleleo` |
| Xray configuration | `/etc/idleleo/conf/xray/config.json` |
| Nginx configuration | `/etc/idleleo/conf/nginx/` |
| Script state configuration | `/etc/idleleo/conf/install_config.json` |
| Certificate files | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Log directories | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Nginx installation directory | `/usr/local/nginx` |
| Management command | `/usr/bin/idleleo` |
| Installation information text | `/etc/idleleo/info/xray_info.inf` |

| Action | Command |
|---|---|
| Start Xray | `systemctl start xray` |
| Stop Xray | `systemctl stop xray` |
| Start Nginx | `systemctl start nginx` |
| Stop Nginx | `systemctl stop nginx` |

## Docker and AI Skill

The Docker image includes Xray, Nginx, and the main script, and the original script features are available inside the container. See the [Docker deployment guide](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/docker/DOCKER.md).

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

AI Skill lets an AI tool that supports Skills complete deployment automatically without answering each interactive question. See [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill).

The script supports Reality, TLS, ws/gRPC/xHTTP ONLY, and the Nginx Stream relay node. The AI Skill auto-deployment templates currently cover Reality and TLS only; use idleleo on the server for ws/gRPC/xHTTP ONLY and relay.

## RillML Xray AI operations assistant

RillML (Rill for short) provides local adaptive intelligent operations for Xray: it monitors Xray/Nginx health in real time, diagnoses failures automatically, and offers remediation advice without an external API. Enter `9` in the main menu or run `idleleo --rill-agent`.

| Action | Command |
|---|---|
| Open the AI operations assistant menu | `idleleo --rill-agent` |
| Install or repair the AI decision engine | `idleleo --rill-agent-install` |
| Show AI decision status | `idleleo --rill-agent-status` |
| Run AI fault diagnosis | `idleleo --rill-agent-diagnose` |
| Verify the AI decision engine | `idleleo --rill-agent-verify` |
| Safely disable AI decisions | `idleleo --rill-agent-safe-disable` |
| Uninstall the Rill AI engine | `idleleo --rill-agent-uninstall` |

Rill focuses on diagnostic advice by default and does not change the system before automatic changes are enabled.

## Further reading

- Why the command is called `idleleo`: [The true face behind the mist](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
- Reality installation guide: [Build an Xray Reality server](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
- Reality protocol risks: [Risks of the Xray Reality protocol](https://hey.run/posts/reality-xie-yi-de-feng-xian)
- Reality acceleration: [Using a Reality protocol "vulnerability" to accelerate a server](https://hey.run/posts/use-reality)
- Community: [Telegram](https://t.me/+48VSqv7xIIFmZDZl)
- Official documentation: [Xray documentation](https://xtls.github.io)

## License and acknowledgements

This project is licensed under [GPL-3.0](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE). Thanks to JetBrains for the non-commercial open-source development license.

- Based on [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey).
- The TCP acceleration script is derived from [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed).
- The share-link format follows [@DuckSoft](https://github.com/DuckSoft)'s [proposal](https://github.com/XTLS/Xray-core/issues/91); UUIDv5 and REALITY details follow the [XTLS](https://github.com/XTLS/Xray-core/issues/158) proposal.
- Thanks to Xray-core, Nginx, Let's Encrypt, and other upstream projects.

Author: Yunshu. The project offers limited support; read the documentation and keep a backup before operating on production systems.
