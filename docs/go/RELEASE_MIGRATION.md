# Phase 00 — 发布与迁移契约

> 依据：`4752f77` 的 `scripts/auto_update.sh`、`.github/workflows/publish-shell-version.yml`、
> 线上 API `xray_shell_versions.json`（2026-11-06 读取）。
> 本文件定义 Go 发布通道如何与既有 Bash 通道共存；Phase 00 不发布任何版本。

## 1. 线上事实（只读读取）

| 字段 | 当前值 |
|---|---|
| `shell_online_version` | `3.3.4` |
| `shell_release_sha256` | `0af8e8f222f26f02904f80bfd0e3cf5cd119b24bbde462019f0b582e1b79cfa6` |
| `shell_tested_version` | `3.3.0` |
| `xray_online_version` | `26.10.31` |
| `nginx_build_online_version` | `2026.10.15.7679` |
| `nginx_online_version` | `1.30.6` |
| API 更新时间 | `2026-11-06 05:28` |

`shell_release_sha256` 与基线 `install.sh` 的 SHA-256 **一致**，说明当前 API 指向的正是本基线。

## 2. 两条发布链

```
Bash 通道（现状）
main ──tag v3.3.4──► GitHub Release
                     ├─ install.sh
                     ├─ rill-xray-agent-xray-bundle.tar.gz
                     ├─ xray_stats.sh
                     ├─ SHA256SUMS
                     ├─ release-manifest.json
                     └─ details
                          │
                          ▼
              publish-shell-version.yml
                          │ 写 shell_online_version / shell_release_sha256 …
                          ▼
              hello-yunshu/Xray_bash_onekey_api
                          │
                          ▼
              raw.githubusercontent.com / jsDelivr CDN
```

```
Go 通道（Phase 04+ 设计）
go-vX.Y.Z ──► 独立 Release（独立 tag 命名空间）
                  ├─ idleleo-linux-amd64 / arm64（+ 校验和）
                  ├─ go-release-manifest.json
                  ├─ provenance / SBOM（可选）
                  └─ 不得覆盖 Bash 的 vX.Y.Z 资产
                        │
                        ▼
              独立 API 字段/文件（不得复用 shell_online_version）
```

### 2.1 命名与字段

| 项 | Bash 约定 | Go 约定（建议） |
|---|---|---|
| tag | `v3.3.4` | `go-v1.0.0`（或 `v1.0.0-go`，二选一后固定） |
| 渠道字段 | `shell_online_version` | `go_manager_online_version` |
| 资产哈希 | `shell_release_sha256` | `go_manager_release_sha256`（或 per-asset） |
| 平台资产 | 单脚本 + 捆包 | `idleleo-linux-amd64`、`idleleo-linux-arm64`、可选 `idleleo-darwin-*` |
| 清单 | `release-manifest.json` | `go-release-manifest.json`，`schemaVersion` 独立 |
| 发布门禁 | `test-install.yml` + `release-gate` | `go-release-qualification.yml` |

**硬规则**：Go 发布不得写入 `shell_online_version`；Bash 管理器也不得把
`go_manager_*` 当作可执行版本。两边对未知字段必须忽略而不是报错。

## 3. 兼容性

### 3.1 Bash `-u` 自更新（现状）

- `-u` 只替换 `install.sh`，并通过 `shell_online_version` / `shell_release_sha256` 校验；
- 不安装 Go 二进制，不迁移 `install_config.json`；
- `--auto-update` 的 cron 仍调用 Bash `auto_update.sh`；
- 因此 **Go 安装必须是独立、显式、可回滚的动作**，不能借道 `-u`。

### 3.2 迁移矩阵

| 起点 | 目标 | 允许方式 | 禁止 |
|---|---|---|---|
| Bash 3.3.4，Reality/TLS/Relay | Go | 显式 `migrate`，备份 + 健康检查 + journal | 静默替换、删除 Bash 回退 |
| Bash 3.3.4，`tls=XTLS` | Go | **拒绝**，只读诊断 | 任何写操作 |
| Go 已接管 | Bash `-u` | 不自动回退；检测到 Go metadata 时 Bash 更新必须提示冲突 | 双管理器同时写同一配置 |
| Go 已接管，迁移失败 | Go → Bash | 使用迁移前备份恢复，保留 Bash `install.sh` | 半迁移状态 |
| 旧 GeoData 布局 | 任意 | 启动钩子/菜单触发的 fail-closed 迁移 | 先删旧 cron 再尝试原生刷新 |

### 3.3 迁移前置与回滚

1. 保留 `/usr/local/bin/idleleo`、`/etc/idleleo/conf/install_config.json`、Bash 备份，直到 Go 健康检查通过。
2. 迁移写入前生成 journal；任一步失败恢复原文件、原服务状态、原 cron。
3. 健康检查至少包含：进程 active、监听端口、`--json` 统计、入口配置 `xray -test`。
4. 回滚不得删除用户证书、密钥、DNS/routing、Nginx 用户片段。

## 4. 发布门禁（Phase 00 现状）

| 门禁 | 触发 | 现状 |
|---|---|---|
| `go-parity-stage.yml` | `pull_request` / `workflow_dispatch`（`legacy/**`、`current/go/**`、`tests/go-parity/**` 变更时） | 新增；本地等价通过 |
| `go-release-qualification.yml` | `workflow_call` / `workflow_dispatch` | 新增；**按设计红灯**：需要生产 Go 目录与 28 个功能测试，Phase 00 不存在 |
| `tests/go-parity/parity/scripts/check_release_gate.py` | 本地/CI | Phase 00 返回 **RED**（`BUNDLED_TOY_GO_DEMO`、28×PENDING、无生产迁移测试、无回滚测试） |
| Bash `release-gate` / `release-candidate-gate` | 既有 | 不受影响；R20 仍成立（单 job 绿不等于整体绿） |

**不得**为了让门禁变绿而：把 PENDING 改成 VERIFIED、把原型当生产、删除失败用例、
或给 `go-release-qualification.yml` 一个伪造的 `workflow_call` 成功。

## 5. 旧版本资产保护

- 不修改 `v3.3.2` / `v3.3.3` 的 tag、Release 与资产；
- 不修改 `shell_online_version`、`shell_release_sha256`，除非用户明确发布；
- Go 发布使用独立 tag 命名空间，避免覆盖 Bash 资产；
- 发布前必须核对：manifest、SHA256SUMS、API 字段、CDN 三者一致。

## 6. 遗留风险

| 编号 | 风险 | Phase 00 结论 |
|---|---|---|
| R14 | Bash `-u` 与 cron 仍在跑，Go 接管后会双写 | 仍成立；迁移必须停用旧 cron 并保留回退 |
| R15 | API 只有 Bash 字段 | 仍成立；Go 需独立字段 |
| R24 | 多仓发布链（主仓 / API 仓 / Nginx 仓 / Xray 仓） | 仍成立；Go 发布不得假设单仓原子性 |

Phase 01 不得开始 Go 服务/菜单实现，直到本契约与 `CONFIG_BRIDGE_CONTRACT.md` 被用户确认。
