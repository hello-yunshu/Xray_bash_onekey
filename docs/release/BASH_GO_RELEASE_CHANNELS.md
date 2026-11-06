# Phase 04 — Bash / Go 双发布通道与自动更新断言

> 结论：两条通道**物理与契约隔离**。Go 通道不会读取或写入 Bash 的
> `shell_online_version` / `shell_release_sha256`，也不会把 Bash 用户自动切到 Go。
> 证据等级：`CONTAINER_VERIFIED`。

## 1. 两条通道对照

| 项 | Bash 通道（现状，未改） | Go 通道（本轮实现） |
|---|---|---|
| 版本来源 | API `shell_online_version` = `3.3.4` | Go release manifest `channel=go` |
| 资产 | `install.sh` + 固定捆包 | `idleleo-linux-amd64` / `linux-arm64` |
| 校验 | `shell_release_sha256` = `0af8e8f2…cfa6`（与基线一致） | manifest 内 per-asset `sha256` + `size` |
| 管理器状态 | Bash `install_config.json` / `auto_update` cron | `etc/idleleo/release/channel.json`、`var/lib/idleleo/release/state.json` |
| 更新执行者 | `scripts/auto_update.sh` | `idleleo schedule` 的 `auto-update` job → `internal/release` |
| 发布门禁 | `test-install.yml` + Bash `release-gate` | `check_release_gate.py` / `go-release-qualification.yml`（当前红灯） |
| 本轮是否改动 | **否** | 新增，但**未发布** |

来源：[RELEASE_MIGRATION.md](../go/RELEASE_MIGRATION.md) 第 1–2 节。

## 2. 隔离实现（代码事实）

[`internal/release/release.go`](../../internal/release/release.go) 的包注释与校验硬规则：

- manifest 的 `channel` 必须**恰好**等于 `go`，否则拒绝；
- `version` 必须匹配 `^\d+\.\d+\.\d+([-+].*)?$`，因此 Bash 的 `v3.3.4` 不会被当成 Go 版本；
- 资产 key 只接受 `linux-amd64` / `linux-arm64`；
- 只读取 `etc/idleleo/release/channel.json`，不读取 Bash 的 `install_config.json` 或任何 `shell_*` 字段；
- 默认安装路径 `opt/idleleo/bin/idleleo`，与 Bash 的 `install.sh` 资产互不覆盖；
- 没有已配置通道时**不会猜测 URL**，直接返回显式降级。

## 3. 自动更新行为矩阵（真实容器结果）

容器：`idleleo-phase04-test:24.04`，image ID
`sha256:8737d13b89f8bf8d8b5e0136ef9f9c020876a4ac9edf146511659535894b6924`，
`ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`，
`--privileged --cgroupns=host`，systemd `running`，真实 `xray 26.10.31` / `nginx 1.24`。

| 场景 | 真实输出 | 退出码 | 旧二进制 |
|---|---|---|---|
| 未配置通道，定时任务运行 | `job=auto-update result=degraded detail=no Go release channel is configured; no automatic update runs…` | 0（job 记录 degraded） | 保留 |
| 已配置通道，`0.3.0 → 0.4.0` | `job=auto-update result=ok … detail=updated 0.3.0-phase04 -> 0.4.0-phase04 sha256=727d01e9… health=idleleo 0.4.0-phase04 (go)` | 0 | 原子替换，SHA 与 manifest 一致 |
| 错误 SHA | `PASS bad sha rejected rc=1` / `PASS bad sha kept old binary` | 1 | 保留 |
| 下载截断（Content-Length 正确、body 只写一半） | `PASS interrupted download rejected rc=1` / `kept old binary` | 1 | 保留 |
| 非 ELF 资产 | `PASS non-ELF asset rejected rc=1` / `kept old binary` | 1 | 保留 |
| 降级 manifest | `PASS downgrade refused exit=4` / `kept old binary` | 4 | 保留 |
| tmpfs 磁盘满（20m） | `PASS disk full rejected rc=1` / `kept old binary (idleleo 0.3.0-phase04 (go))` | 1 | 保留 |
| 重复 apply | `PASS second apply is up-to-date` | 0 | 不变 |
| 安装后校验 | `installed-binary-sha=af93f7f5… expected=af93f7f5…` / `PASS installed sha matches manifest` | 0 | 新版本 |

完整日志：`/tmp/phase04-c.log`，末尾 `phase04-end 2026-11-06T17:34:52Z pass=42 fail=0`。

## 4. 自动更新不会触发 Bash → Go 迁移

- Bash 的 `auto_update.sh` / `-u` 路径本轮**未修改**，仍在 `main`/`legacy` 侧按原契约工作；
- Go 的 `AutoUpdate` 只更新 `idleleo` 自身二进制，不写 `/usr/bin/idleleo` 以外的入口，
  不安装/移除 Bash 文件，不修改 `shell_online_version`；
- Bridge 迁移仍只在 `idleleo --update` 的真实 TTY 手动路径触发（Phase 03 实证：
  `auto_update=YES` 与 `--yes` 均 `requests=0`、入口不变）；
- 已 `COMMITTED` 的 Go 安装不会因 Bash `-u` 自动反向迁移。

## 5. 两个通道共用的安全原语

- 共享更新锁 `run/lock/idleleo-update.lock`：scheduler 已持锁时通过 `held *host.UpdateLock`
  复用，避免同进程二次 `flock` 死锁；锁冲突的 job 记录 `skipped`，不静默失败。
- 安装顺序固定：download → size → SHA-256 → ELF magic/machine → 备份旧二进制 →
  原子写新二进制 → 健康检查（输出必须含 `idleleo` 与 manifest 版本）→ 失败恢复；
  恢复失败返回 `RECOVERY_REQUIRED`（CLI exit 10）。
- 真实 root 写入需要 `--container` + `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY` +
  容器标记（`/.dockerenv` 或 `/run/.containerenv`），见
  [`internal/host/gate.go`](../../internal/host/gate.go)。

## 6. 未验证事实（不得当作已满足）

| 缺口 | 为什么没做 | 用户影响 | 解锁条件 |
|---|---|---|---|
| 真实 GitHub Release 下载 Go 资产 | 未发布、无 tag；本轮只用固定本地 origin | 用户无法从公网自动升级 Go 管理器 | 28 项门禁全绿 + 受保护 CI 出包 + 独立 tag 命名空间 |
| 旧 Bash 更新器真正读到双字段 | Bash 侧代码未改，API 只有 Bash 字段 | 旧 Bash 用户仍只收到 Bash 更新（符合预期） | 发布 `go_manager_*` 字段并通过旧更新器回归 |
| `latest/download` 公网链路 | 同上 | Go 通道只能手工配置 manifest URL | 正式发布后以固定 URL + SHA 复验 |
