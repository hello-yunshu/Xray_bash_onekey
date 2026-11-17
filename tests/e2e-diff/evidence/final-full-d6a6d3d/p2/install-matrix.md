# P2 install matrix — p2

Generated 2026-11-15 01:55:42. Round 1 is primary; round 2 is the idempotency round.

| 场景 | bash rc / L4 / rc2 / L6 | go rc / L4 / rc2 / L6 | 判定 | 说明 |
|---|---|---|---|---|
| M1 reality-standard | 0 / reality:ok / 0 / ok | 0 / reality:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 27 L1 paths |
| M2 reality-nginx | 0 / reality:ok / 0 / ok | 0 / reality:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 27 L1 paths |
| M3 reality-transport | 0 / reality:ok,ws:ok / 0 / ok | 0 / reality:ok,ws:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 27 L1 paths |
| M4 tls-ws | 0 / ws:ok / 0 / ok | 0 / ws:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 26 L1 paths |
| M5 tls-grpc | 0 / grpc:ok / 0 / ok | 0 / grpc:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 26 L1 paths |
| M6 tls-xhttp | 0 / xhttp:ok / 0 / fail | 0 / xhttp:ok / 0 / ok | **BLOCKER** | bash idempotency failed |
| M7 tls-ws-grpc-xhttp | 0 / grpc:ok,ws:ok,xhttp:ok / 0 / ok | 0 / grpc:ok,ws:ok,xhttp:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 26 L1 paths |
| M8 tls-acme | - / - / - / - | - / - / - / - | **HARNESS-BLOCKED** | scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED |
| M9 none-ws | 0 / ws:ok / 0 / ok | 0 / ws:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 26 L1 paths |
| M10 relay-stream | 0 / relay:ok / 0 / ok | 0 / relay:ok / 0 / ok | **BLOCKER** | ED still pending/expired for 23 L1 paths |

## 未验 / 阻塞项

- **M8 tls-acme** — HARNESS-BLOCKED：scenario ineligible: 前置：Pebble 的 HTTP-01/TLS-ALPN 在本容器网络的解析方案；方案未定前不判过，标 HARNESS-BLOCKED

## L1 布局差异（未抑制）

### M1（bash 有 / go 无 25；go 有 / bash 无 2）
- bash-only roots: /etc/idleleo/cert(1), /etc/idleleo/conf(2), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8)
  samples: /etc/idleleo/cert, /etc/idleleo/conf/install_config.json, /etc/idleleo/conf/nginx, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf
- go-only roots: /etc/idleleo/v1(2)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json

### M2（bash 有 / go 无 24；go 有 / bash 无 3）
- bash-only roots: /etc/idleleo/cert(1), /etc/idleleo/conf(1), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8)
  samples: /etc/idleleo/cert, /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/info/xray_info_clash.yaml
- go-only roots: /etc/idleleo/v1(3)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json, /etc/idleleo/v1/nginx.json

### M3（bash 有 / go 无 25；go 有 / bash 无 2）
- bash-only roots: /etc/idleleo/cert(1), /etc/idleleo/conf(2), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8)
  samples: /etc/idleleo/cert, /etc/idleleo/conf/install_config.json, /etc/idleleo/conf/nginx, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf
- go-only roots: /etc/idleleo/v1(2)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json

### M4（bash 有 / go 无 23；go 有 / bash 无 3）
- bash-only roots: /etc/idleleo/conf(1), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8), /etc/idleleo/share(2)
  samples: /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/info/xray_info_clash.yaml, /etc/idleleo/install.sh
- go-only roots: /etc/idleleo/v1(3)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json, /etc/idleleo/v1/nginx.json

### M5（bash 有 / go 无 23；go 有 / bash 无 3）
- bash-only roots: /etc/idleleo/conf(1), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8), /etc/idleleo/share(2)
  samples: /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/info/xray_info_clash.yaml, /etc/idleleo/install.sh
- go-only roots: /etc/idleleo/v1(3)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json, /etc/idleleo/v1/nginx.json

### M6（bash 有 / go 无 23；go 有 / bash 无 3）
- bash-only roots: /etc/idleleo/conf(1), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8), /etc/idleleo/share(2)
  samples: /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/info/xray_info_clash.yaml, /etc/idleleo/install.sh
- go-only roots: /etc/idleleo/v1(3)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json, /etc/idleleo/v1/nginx.json

### M7（bash 有 / go 无 23；go 有 / bash 无 3）
- bash-only roots: /etc/idleleo/conf(1), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8), /etc/idleleo/share(2)
  samples: /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/info/xray_info_clash.yaml, /etc/idleleo/install.sh
- go-only roots: /etc/idleleo/v1(3)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json, /etc/idleleo/v1/nginx.json

### M9（bash 有 / go 无 24；go 有 / bash 无 2）
- bash-only roots: /etc/idleleo/cert(1), /etc/idleleo/conf(1), /etc/idleleo/info(3), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8)
  samples: /etc/idleleo/cert, /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/info/xray_info_clash.yaml
- go-only roots: /etc/idleleo/v1(2)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json

### M10（bash 有 / go 无 20；go 有 / bash 无 3）
- bash-only roots: /etc/idleleo/conf(1), /etc/idleleo/info(2), /etc/idleleo/install.sh(1), /etc/idleleo/languages(1), /etc/idleleo/logs(2), /etc/idleleo/release-managed.version(1), /etc/idleleo/scripts(8), /etc/idleleo/tmp(2)
  samples: /etc/idleleo/conf/install_config.json, /etc/idleleo/info, /etc/idleleo/info/xray_info.inf, /etc/idleleo/install.sh, /etc/idleleo/languages
- go-only roots: /etc/idleleo/v1(3)
  samples: /etc/idleleo/v1, /etc/idleleo/v1/metadata.json, /etc/idleleo/v1/nginx.json


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

| 场景 | 编辑 rc | SHA 改前 → 改后 | 检查项 | L4 改前/改后 | 判定 | 说明 |
|---|---|---|---|---|---|---|
| E1 config-edit-before-after | 0 | 7c28f4c0e189 → 74528a6300d3 | editRcZero:ok, configChanged:ok, uuidApplied:ok, shareUriUpdated:ok, serviceActive:ok, backupExists:ok | ok / ok | **PASS** | Go 独有能力，bash 侧无 UUID 非交互入口；判定只看 Go 改前/改后与 L4。 |
| E2 config-edit-restart-rollback | 1 | 23aaf911f2c3 → 23aaf911f2c3 | editRcNonZero:ok, rollbackReported:ok, configRestored:ok, serviceActive:ok | ok / ok | **PASS** | 回滚后 SHA 还原 |

- E1 SHA：改前 `7c28f4c0e189b61a5358670c9e433da37dba1a703dfd8ad21ce8b8df314ac860` → 改后 `74528a6300d3572e64dbe753e7c4d57a961edc5cf06c03e629ba16bda7dd8060`（已变更）
- E2 SHA：改前 `23aaf911f2c3f390f6f22c3dc0a9b75f551e8e49ed1f58c7c83c4ef21aa9d188` → 改后 `23aaf911f2c3f390f6f22c3dc0a9b75f551e8e49ed1f58c7c83c4ef21aa9d188`（已还原）

## 与基线对比（p2）

| 场景 | 基线（bash / go / 判定） | 本轮（bash / go / 判定） | 变化格子 |
|---|---|---|---|
| M1 | 0 / reality:ok / 0 / ok / 0 / reality:ok / 0 / ok / BLOCKER | 0 / reality:ok / 0 / ok / 0 / reality:ok / 0 / ok / BLOCKER | — |
| M2 | 0 / reality:ok / 0 / ok / 0 / reality:ok / 0 / ok / BLOCKER | 0 / reality:ok / 0 / ok / 0 / reality:ok / 0 / ok / BLOCKER | — |
| M3 | 0 / reality:ok,ws:ok / 0 / ok / 0 / reality:ok,ws:ok / 0 / ok / BLOCKER | 0 / reality:ok,ws:ok / 0 / ok / 0 / reality:ok,ws:ok / 0 / ok / BLOCKER | — |
| M4 | 0 / ws:ok / 0 / ok / 0 / ws:ok / 0 / ok / BLOCKER | 0 / ws:ok / 0 / ok / 0 / ws:ok / 0 / ok / BLOCKER | — |
| M5 | 0 / grpc:ok / 0 / ok / 0 / grpc:ok / 0 / ok / BLOCKER | 0 / grpc:ok / 0 / ok / 0 / grpc:ok / 0 / ok / BLOCKER | — |
| M6 | 0 / xhttp:ok / 0 / ok / 0 / xhttp:ok / 0 / ok / BLOCKER | 0 / xhttp:ok / 0 / fail / 0 / xhttp:ok / 0 / ok / BLOCKER | bash.l6 True→False |
| M7 | 0 / grpc:ok,ws:ok,xhttp:ok / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / 0 / ok / BLOCKER | 0 / grpc:ok,ws:ok,xhttp:ok / 0 / ok / 0 / grpc:ok,ws:ok,xhttp:ok / 0 / ok / BLOCKER | — |
| M8 | - / - / - / - / - / - / - / - / HARNESS-BLOCKED | - / - / - / - / - / - / - / - / HARNESS-BLOCKED | — |
| M9 | 0 / ws:ok / 0 / ok / 0 / ws:ok / 0 / ok / BLOCKER | 0 / ws:ok / 0 / ok / 0 / ws:ok / 0 / ok / BLOCKER | — |
| M10 | 0 / relay:ok / 0 / ok / 0 / relay:ok / 0 / ok / BLOCKER | 0 / relay:ok / 0 / ok / 0 / relay:ok / 0 / ok / BLOCKER | — |
| E1,E2 | 无 | 已执行 | E1 新增; E2 新增 |

本轮预期变化：G8 → M10 文件集合；G9 → M3/M7 端口；G10 → M4/M7 重启；G11 → E1/E2 新增。

## 未覆盖/未验证

- M8（ACME）：`eligible:false`，按计划记 HARNESS-BLOCKED。
- L2 仅记录 sanitized config 摘要，未做全字段语义 diff；L3/L5 以采集件为准。
