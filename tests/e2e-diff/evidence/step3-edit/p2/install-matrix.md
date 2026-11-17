# P2 install matrix — p2

Generated 2026-11-15 01:21:20. Round 1 is primary; round 2 is the idempotency round.

| 场景 | bash rc / L4 / rc2 / L6 | go rc / L4 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M2 reality-nginx | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M3 reality-transport | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M4 tls-ws | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M5 tls-grpc | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M6 tls-xhttp | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M7 tls-ws-grpc-xhttp | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M8 tls-acme | - / - / - / - | - / - / - / - | **HARNESS-BLOCKED** | scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED |
| M9 none-ws | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |
| M10 relay-stream | - / - / - / - | - / - / - / - | **HARNESS-ERROR** | bash: missing evidence directory |

## 未验 / 阻塞项

- **M1 reality-standard** — HARNESS-ERROR：bash: missing evidence directory
- **M2 reality-nginx** — HARNESS-ERROR：bash: missing evidence directory
- **M3 reality-transport** — HARNESS-ERROR：bash: missing evidence directory
- **M4 tls-ws** — HARNESS-ERROR：bash: missing evidence directory
- **M5 tls-grpc** — HARNESS-ERROR：bash: missing evidence directory
- **M6 tls-xhttp** — HARNESS-ERROR：bash: missing evidence directory
- **M7 tls-ws-grpc-xhttp** — HARNESS-ERROR：bash: missing evidence directory
- **M8 tls-acme** — HARNESS-BLOCKED：scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED
- **M9 none-ws** — HARNESS-ERROR：bash: missing evidence directory
- **M10 relay-stream** — HARNESS-ERROR：bash: missing evidence directory

## L1 布局差异（未抑制）

无。

## EXPECTED-DIFF 登记表

| ED | 场景 | 层 | 路径 | 状态 |
|---|---|---|---|---|
| ED-001 | OPS-09 | L2 | /usr/local/nginx/conf | BLOCKER(pending) |
| ED-002 | OPS-19 | L1 | /etc/fail2ban | BLOCKER(pending) |
| ED-003 | OPS-21 | L3 | nftables/iptables ruleset | BLOCKER(pending) |
| ED-004 | OPS-22 | L1 | /var/log | BLOCKER(pending) |
| ED-005 | OPS-29 | L5 | rill agent output | BLOCKER(pending) |
| ED-006 | M1 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-007 | M1 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-008 | M1 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-009 | M1 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-010 | M1 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-011 | M1 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-012 | M1 | L1 | /etc/idleleo/cert | BLOCKER(pending) |
| ED-013 | M1 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-014 | M1 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-015 | M1 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-016 | M1 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-017 | M1 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-018 | M1 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-019 | M1 | L1 | /etc/idleleo/conf/nginx | BLOCKER(pending) |
| ED-020 | M2 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-021 | M2 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-022 | M2 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-023 | M2 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-024 | M2 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-025 | M2 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-026 | M2 | L1 | /etc/idleleo/cert | BLOCKER(pending) |
| ED-027 | M2 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-028 | M2 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-029 | M2 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-030 | M2 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-031 | M2 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-032 | M2 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-033 | M3 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-034 | M3 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-035 | M3 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-036 | M3 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-037 | M3 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-038 | M3 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-039 | M3 | L1 | /etc/idleleo/cert | BLOCKER(pending) |
| ED-040 | M3 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-041 | M3 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-042 | M3 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-043 | M3 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-044 | M3 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-045 | M3 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-046 | M3 | L1 | /etc/idleleo/conf/nginx | BLOCKER(pending) |
| ED-047 | M4 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-048 | M4 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-049 | M4 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-050 | M4 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-051 | M4 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-052 | M4 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-053 | M4 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-054 | M4 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-055 | M4 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-056 | M4 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-057 | M4 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-058 | M4 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-059 | M5 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-060 | M5 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-061 | M5 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-062 | M5 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-063 | M5 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-064 | M5 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-065 | M5 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-066 | M5 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-067 | M5 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-068 | M5 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-069 | M5 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-070 | M5 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-071 | M6 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-072 | M6 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-073 | M6 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-074 | M6 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-075 | M6 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-076 | M6 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-077 | M6 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-078 | M6 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-079 | M6 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-080 | M6 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-081 | M6 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-082 | M6 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-083 | M7 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-084 | M7 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-085 | M7 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-086 | M7 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-087 | M7 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-088 | M7 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-089 | M7 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-090 | M7 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-091 | M7 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-092 | M7 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-093 | M7 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-094 | M7 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-095 | M9 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-096 | M9 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-097 | M9 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-098 | M9 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-099 | M9 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-100 | M9 | L1 | /etc/idleleo/share | BLOCKER(pending) |
| ED-101 | M9 | L1 | /etc/idleleo/cert | BLOCKER(pending) |
| ED-102 | M9 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-103 | M9 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-104 | M9 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-105 | M9 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-106 | M9 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-107 | M9 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |
| ED-108 | M10 | L1 | /etc/idleleo/scripts | BLOCKER(pending) |
| ED-109 | M10 | L1 | /etc/idleleo/info | BLOCKER(pending) |
| ED-110 | M10 | L1 | /etc/idleleo/languages | BLOCKER(pending) |
| ED-111 | M10 | L1 | /etc/idleleo/logs | BLOCKER(pending) |
| ED-112 | M10 | L1 | /etc/idleleo/tmp | BLOCKER(pending) |
| ED-113 | M10 | L1 | /etc/idleleo/conf/install_config.json | BLOCKER(pending) |
| ED-114 | M10 | L1 | /etc/idleleo/install.sh | BLOCKER(pending) |
| ED-115 | M10 | L1 | /etc/idleleo/versions.json | BLOCKER(pending) |
| ED-116 | M10 | L1 | /etc/idleleo/release-managed.version | BLOCKER(pending) |
| ED-117 | M10 | L1 | /var/spool/cron/crontabs/root | BLOCKER(pending) |
| ED-118 | M10 | L1 | /etc/idleleo/v1 | BLOCKER(pending) |

## 配置编辑场景（xray config edit，Go）

| 场景 | 编辑 rc | 检查项 | L4 改前/改后 | 判定 | 说明 |
|---|---|---|---|---|---|
| E1 config-edit-before-after | 0 | editRcZero:ok, configChanged:ok, uuidApplied:ok, shareUriUpdated:fail, serviceActive:ok, backupExists:ok | - / ok | **BLOCKER** | 改前 L4 未通过 |
| E2 config-edit-restart-rollback | 1 | editRcNonZero:ok, rollbackReported:ok, configRestored:ok, serviceActive:ok | - / ok | **BLOCKER** | 改前 L4 未通过 |

## 未覆盖/未验证

- M8（ACME）：`eligible:false`，按计划记 HARNESS-BLOCKED。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
