# Phase 04 — Bash / Go 双发布通道与自动更新断言

> 结论：两条通道**物理与契约隔离**。Go 通道不会读取或写入 Bash 的
> `shell_online_version` / `shell_release_sha256`，也不会把 Bash 用户自动切到 Go。
> 证据等级：`CONTAINER_VERIFIED`。

## 1. 两条通道对照

| 项 | Bash 通道（现状，未改） | Go 通道（本轮实现） |
|---|---|---|
| 版本来源 | API `shell_online_version` = `3.3.4`（线上）；本分支 `3.3.5` 待发布 | Go release manifest `channel=go` |
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

- Bash `install.sh -u` 的**手动 TTY 路径**增加了迁移入口（版本 3.3.5，待发布）；
  `auto_update=YES`、`--yes` 与非 TTY 不进入该入口（Phase 03 实证：三类路径
  `bridge_requests=0`，入口不变）；
- 「已是最新」分支同样只在手动 TTY 下提示，从不自动切换；
- Go 的 `AutoUpdate` 只更新 `idleleo` 自身二进制，不写 `/usr/bin/idleleo` 以外的入口，
  不安装/移除 Bash 文件，不修改 `shell_online_version`；
- Bridge 迁移仍只在 `install.sh -u` 的真实 TTY 手动路径触发（Phase 03 实证：
  `auto_update=YES` 与非 TTY 均 `requests=0`、入口不变）；
- 已 `COMMITTED` 的 Go 安装不会因 Bash `-u` 自动反向迁移；保留的
  `auto_update.sh` cron 即使刷新 Bash 脚本，检测到 Go 入口/journal `COMMITTED`
  时也不会重写 `/usr/bin/idleleo`（Phase 03 回归覆盖）。

### 4.1 Nginx xHTTP 上行限制（历史模板缺陷）

- 缺陷引入于 `335f4d8c`：xhttp location 的 `client_max_body_size 0;` 被注释，
  Nginx 回落默认 `1m`，`stream-one` 上行单请求体超过约 1MB 时返回 `413`；
  ws location 不受影响。本版模板已把它改为生效行，并在同一处说明
  `proxy_buffering` 对 `grpc_pass` 无效（该 location 实际使用 `grpc_pass`），
  不再保留“看起来对齐、实际无效”的配置。
- **`-u` 只替换主脚本与 helper，不会重写
  `/etc/idleleo/conf/nginx/00-xray.conf`**；已部署的 xhttp 节点必须重新运行
  安装脚本重建 Nginx 配置，或手工放开该行。`-u` 成功后会检测到旧模板并
  打印这条提示。
- 回归：`.github/test/test_nginx_xhttp_limits.sh` 断言生成的 xhttp location
  必须是生效的 `client_max_body_size 0;`，且不得出现被注释的同名指令。

## 5. 两个通道共用的安全原语

- 共享更新锁 `run/lock/idleleo-update.lock`：scheduler 已持锁时通过 `held *host.UpdateLock`
  复用，避免同进程二次 `flock` 死锁；锁冲突的 job 记录 `skipped`，不静默失败。
- 安装顺序固定：download → size → SHA-256 → ELF magic/machine → 备份旧二进制 →
  原子写新二进制 → 健康检查（输出必须含 `idleleo` 与 manifest 版本）→ 失败恢复；
  恢复失败返回 `RECOVERY_REQUIRED`（CLI exit 10）。
- root 写入门禁：容器内真实 root 需要 `--container` +
  `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY` + 容器标记；
  **真机 root 放行**，但每次写入先追加到 `/var/log/idleleo/system-writes.log`
  （mode/uid/pid/argv，0600），审计不可写则拒绝，见
  [`internal/host/gate.go`](../../internal/host/gate.go)。

## 6. 未验证事实（不得当作已满足）

| 缺口 | 为什么没做 | 用户影响 | 解锁条件 |
|---|---|---|---|
| 真实 GitHub Release 下载 Go 资产 | 未发布、无 tag；本轮只用固定本地 origin | 用户无法从公网自动升级 Go 管理器 | 28 项门禁全绿 + 受保护 CI 出包 + 独立 tag 命名空间 |
| 旧 Bash 更新器真正读到双字段 | Bash 侧代码未改，API 只有 Bash 字段 | 旧 Bash 用户仍只收到 Bash 更新（符合预期） | 发布 `go_manager_*` 字段并通过旧更新器回归 |
| `latest/download` 公网链路 | 同上 | Go 通道只能手工配置 manifest URL | 正式发布后以固定 URL + SHA 复验 |

## 7. Bridge 资产清单的生产链路（P0-2）

| 环节 | 实现 | 状态 |
|---|---|---|
| 生成 | [`packaging/bridge_asset.py`](../../packaging/bridge_asset.py)：只接受 ELF、非空文件、40 位 commit、HTTPS origin；输出 `schemaVersion/version/sourceCommit/arch/url/sha256/size/recoveryUrl/recoverySha256/recoverySize` | 已实现，本地实跑 |
| 打包 | [`packaging/build-go-release.sh`](../../packaging/build-go-release.sh)：主/恢复二进制各两架构；`SHA256SUMS` 4 项；`BRIDGE_BASE_URL` 设置时生成两份清单，未设置显式 SKIP | 已实现，本地实跑 |
| 发布 | [`.github/workflows/publish-go-bridge.yml`](../../.github/workflows/publish-go-bridge.yml)：`workflow_dispatch` + `check_release_gate.py` 门禁；创建 `go-v<version>` Release；把清单推到 API 仓库 `bridge/asset-linux-<arch>.json` | 已实现，**零 run**（门禁红） |
| 消费 | `install.sh` 的 `bridge_install_manifest`：手动 TTY 守卫全部通过后才 fetch；校验 schema/arch/URL 协议/SHA 形状；原子写入 `/etc/idleleo/bridge/asset.json`（0600）；失败静默跳过 | 已实现，Phase 03 容器实证 |

清单固定 URL（Bash 默认读取，测试可用 `IDLELEO_BRIDGE_MANIFEST_URL` 覆盖）：

```
https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/bridge/asset-linux-amd64.json
https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/bridge/asset-linux-arm64.json
```

未发布事实不变：上述 Release 与 API 清单在本轮均**未产生**；`publish-go-bridge.yml`
在当前 28 项 PENDING 状态下会以 exit 2 拒绝发布，因此不存在“已发布但不可用”的清单。

