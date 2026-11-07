# Phase 03 报告 — Bridge 旧用户迁移

> 分支：`develop/go-native`　基线：`bc16c1c`　首轮实现提交：`807ebcb`
> 收尾提交：见 `git log`（本报告所在提交）　日期：2026-11-06
> 证据等级：`CONTAINER_VERIFIED`

## 0. 结论

Phase 03 的首轮 Bridge（审计、快照、journal、激活、恢复、Bash 手动发现路径）已在固定
digest 的 `ubuntu:24.04` 特权 systemd 容器内用真实 Xray 26.10.31、真实 nginx 1.24、
真实 crontab 和真实 TTY 验证。本轮按 `PHASE_03_REPORT.md` 首轮列出的缺口逐条收口，
新增原生 Go 定时入口、Rill 契约、权限/软链修复、自定义内容确认、候选 `status` 预验收、
磁盘满/下载中断故障注入和 `latest/download` 本地固定 origin 路径。

最终容器 E2E：**201 / 201** 项通过，`phase03-exit=0`（`/tmp/phase03-run5.log`）。

- 满足 2026-11-06 用户授权口径：**`CONTAINER_VERIFIED` 视为门槛满足**；
  本轮**不是** `REAL_VPS_VERIFIED`，不得表述为“真实 VPS 已验证”。
- 真实 ACME 签发/续期仍**不纳入本轮验收**；Go 侧的证书任务只做到期监控，并在
  到期/即将到期时给出**显式产品降级**日志，不伪造续期。
- 未合并 `main`、未打 tag、未发 Release；`.workbuddy/`、`docs/plans/` 未提交。

## 1. 缺口关闭清单

| # | Phase 03 首轮缺口 | 本轮结果 | 关键证据 |
|---|---|---|---|
| 1 | Go 定时入口缺失 | **关闭**。新增 `internal/schedule`：systemd timer + 4 个原生 job，迁移时安装、回滚时移除；`DeferredTasks` 恒为空 | 容器内 30s timer **真实触发**，`schedule.log` 时间戳 `2026-11-06T16:15:49Z`；`geodata-refresh ok`、`stats-collect ok`、`auto-update degraded` |
| 2 | Rill 状态未纳入审计/交接/预验收 | **关闭**。`RillInfo` 进入 audit / 快照 / prepare / validate / activate / recover / status；观测漂移 → validate exit 6；回滚前后比对 | 11 项 `PASS rill:*` |
| 3 | 03-B 权限/软链、自定义内容人工确认 | **关闭**。文件级权限修复（config 0644、privkey 0640 + xray 组）、runtime symlink 阻断、自定义项 `--acknowledge-custom` 门禁与完整摘要 | 22 项 `PASS permissions:*` / `PASS symlink:*`；TLS 场景无 ack → exit 6 |
| 4 | 03-D 未用转换后 manager.json 加载候选 status | **关闭**。validate 运行 `candidate --root <root> status --json`，解析 `installed`/`config.matchesMetadata`；relay 允许无 runtime | `PASS reality: validate` 新增 candidateStatus/installed/matchesMetadata 断言；relay 无 Xray 全链通过 |
| 5 | 03-A 变更摘要不完整、`latest/download/install.sh` 未实跑 | **关闭**。`audit --summary` 输出完整变更摘要；`packaging/install.sh` 用本地固定 origin 的 `latest/download` 目录结构跑通 `--fetch-only` | `PASS release:*` 8 项；`requests.log` 恰好 `/latest/download/install.sh` + `/latest/download/idleleo` |
| 6 | 03-F 只有 3 个故障点 | **关闭**。新增磁盘满（ENOSPC → exit 13、零 journal/plan）与传输中断（Bash 下载截断、Go GeoData 截断） | 7 项 `PASS disk-full:*`；6 项 `PASS interrupt:*`；2 项 `PASS scheduler: interrupted*` |
| 7 | README / CHANGELOG 无迁移说明 | **关闭**。README 增加「Go 管理器迁移（实验）」，CHANGELOG 增加未发布迁移条目 | 本提交 |

### 1.1 定时任务的迁移口径（不再静默暂停）

| 旧 cron 任务 | Go 侧实现 | 结果 |
|---|---|---|
| `auto_update.sh` | 保留 timer 周期，job 记录 `degraded` | **显式产品降级**：没有已发布的 Go release 通道，迁移后不再自动更新；每轮仍记录原因 |
| `ssl_update.sh` | 解析证书到期时间 | 未到期 → `ok`；无证书 → `skipped`；到期/<30 天 → `degraded`（**ACME 未实现，显式降级**） |
| `geo_update.sh` | 下载 `geoip.dat`/`geosite.dat` → 内存校验 → 原子替换 → 重启 Xray | **完整实现**（截断下载不覆盖旧文件） |
| `xray_stats.sh` | `xray api statsquery --server=<api.listen>`，结果写 `stats.json` | **完整实现**（真实 Xray API 返回） |

迁移后 journal 仍保留 `ScheduledJobs` 与 `DegradedJobs` 两个字段用于状态展示，
但 **`DeferredTasks` 恒为空**：四类任务都有明确的接管者（两个完整实现、两个显式降级），
不再存在“任务被暂停却无人接管”的状态。

## 2. 固定环境与工件

| 项目 | 值 |
|---|---|
| 基础镜像 | `ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` |
| 构建镜像 | `idleleo-phase03-test:24.04`，本次 image ID `sha256:169a9a951de37b9b1a4803e3696271f073e23583d827a67b8eb8eb138658ee56` |
| 容器 | `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw`，PID1 `/usr/lib/systemd/systemd` |
| 宿主内核 | `7.2.12-orbstack-00394-gbecdd6130068`（`linux/arm64`） |
| systemd | `systemctl is-system-running` = `running` |
| Xray | `26.10.31 a4a3dff (go1.27.3 linux/arm64)`；sha256 `5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328` |
| nginx | `nginx/1.24.0 (Ubuntu)` + `libnginx-mod-stream` |
| Go 二进制 | `GOOS=linux GOARCH=arm64`；`idleleo` sha256 `3af4932666a1967285e426c375339d2fda46f0e3e7507ed0b831c73e9c73ee71`，`idleleo-recover` sha256 `1e6492d8ff7be86ba85bcd340c38a5d2d6a10b345e00922e16aa15c5828d4373` |
| 版本 | 候选 `idleleo 0.1.0-phase01 (go)` |

> 镜像 ID 每次 `docker build` 会因 apt 元数据层变化而不同；基础镜像 digest 固定。

## 3. 工作包逐条完成情况

### 03-A 发布链与迁移发现 — 完成（容器级）

| 项 | 状态 | 证据/说明 |
|---|---|---|
| 双版本通道隔离 | 完成 | Bash `-u` 只用 `XRAY_VERSIONS_FILE` 的 shell 字段；Go 资产来自独立 manifest |
| Bridge-aware Bash 小版本 | 完成 | `bridge_migration_offer`、`--internal-bridge-offer`、`-u` 手动 TTY 挂钩 |
| 旧版手动 `--update` 衔接 | 完成（容器级） | M14：手动 TTY 两次确认后下载 2 个固定资产并 `COMMITTED`；`-u --yes` 零 Go 请求 |
| 三条件授权（TTY+命令+同意） | 完成 | M16/M01/M02/M03：非 TTY、`auto_update=YES`、`-u --yes`、拒绝全部 `requests=0` |
| 同意前变更摘要 | **完成** | 下载后、prepare 前执行 `bridge audit --summary`，展示 verdict/role/tls/users/runtime/certs/nginx/旧 cron/Rill/自定义项/权限修复/接管任务/降级项/findings |
| 固定资产 + SHA256/ELF 校验 | 完成 | 本地 HTTPS origin 记录请求；sha256 + ELF magic；缺 manifest/缺写入门禁零请求 |
| 与 Go 新安装器区分 | **完成（容器级）** | `packaging/install.sh` 用本地 `latest/download/` 固定 origin：`--fetch-only` exit 0、输出 `/opt/idleleo/bin/idleleo`、二进制可执行、只发 2 个请求；未发真实 Release |

### 03-B 只读审计与差异计划 — 完成（容器级）

- 完成：读取 `install_config.json`、Xray JSON、relay 片段、unit 的 `User/Group/ExecStart`、
  active/enabled、证书指纹、旧 GeoData、项目/用户 cron、entry 状态；输出 `plan.json`
  与 verdict `convertible` / `needs-fix` / `blocked`。
- 完成：`already-migrated`、XTLS、缺 metadata、坏 JSON、runtime 用户为空、Reality 缺
  privateKey、端口冲突、缺 relay 片段、缺恢复旧脚本 → `blocked`。
- **完成：Rill 审计**。读取 `/etc/rill-xray-agent/config.json`、
  `/var/lib/rill-xray-agent-xray/status/xray-observation.json`、二进制；输出
  `installed/binary/configHash/observationHash/age/status/mode/enabled`；
  `active|stale|installed-unobserved|absent`；stale/缺失为显式 warn findings。
- **完成：权限/软链**。runtime config world-writable → 修复为 0644；私钥组/其他可读 →
  0640 且 group 改为 xray 组；仅修文件不修目录（避免 xray 用户无法遍历）。
  runtime config 为 symlink → `blocked`（`runtime-config-symlink`）；entry symlink
  越界 → `blocked`（`entry-symlink-escape`）。
- **完成：自定义内容**。未知 Xray 顶层键与 `relay-stream.conf` 之外的 nginx 片段进入
  `customItems`；未带 `--acknowledge-custom` 时 `prepare` 返回 **exit 6**，不写 journal。

### 03-C 快照准备与 Journal — 完成

- 兼容旧锁 `/run/lock/idleleo-update.lock`（非阻塞 flock）；容器实测持锁时 prepare
  **exit 13**，释放后 exit 0。
- 快照含入口目标/哈希、旧脚本副本、unit 与配置哈希、证书与密钥指纹、cron 精确行、
  服务 active/enabled、**Rill 状态**、**自定义项清单**、**待执行的权限修复**；
  不复制私钥明文。
- 独立恢复器 `/opt/idleleo/recovery/idleleo-recover`（仅标准库）；缺失时激活被拒（exit 3）。
- `PREPARED` 原子写 + `fsync`；metadata 只引用运行路径，不含密钥明文。
- 漂移 → exit 6（M12）；Rill 观测漂移 → exit 6。

### 03-D 候选 Go 的真实预验收 — 完成

- candidate SHA256 一致且可执行（`version` exit 0）。
- **用转换后的 `manager.json` 真实加载候选 `status --json`**：解析
  `installed`、`config.matchesMetadata`；JSON/退出码失败 → validate exit 4；
  node 要求 `matchesMetadata=true`，relay 允许无 runtime 配置。
- 节点用真实 `xray -test -config`；TLS/relay 用真实 `nginx -t -c`；relay 不要求 Xray。
- **Rill 交接契约纳入预验收**：快照与当前观测不一致 → exit 6。

### 03-E 入口与任务切换 — 完成

- `ACTIVATING` journal 先落盘；Go 二进制写入 `/opt/idleleo/bin/idleleo`，
  `/usr/bin/idleleo` 原子 symlink 切换；旧 Bash 保留在
  `/opt/idleleo/recovery/legacy-install.sh`。
- 只精确移除本项目 4 条 cron；用户 certbot 与自定义 geo 刷新 cron 逐字节保留。
- **接管定时任务**：激活时安装 `idleleo-schedule.service` + `.timer`（默认 1h），
  journal 记录 `ScheduledJobs`（4 项）与 `DegradedJobs`（2 项）；`DeferredTasks=[]`。
- 迁移后 `xray`/`nginx` 仍 `active/enabled`；runtime 配置、用户数、证书、私钥、
  自定义片段、unit 文件逐字节不变。

### 03-F 强杀/重启后的继续或恢复 — 完成（覆盖 6 个故障点）

| 故障点 | 注入 | 结果 |
|---|---|---|
| `after-activating` | `activate --fault` → exit 70 | journal 保持 `ACTIVATING`，入口仍 Bash；恢复器 exit 0 → `ROLLED_BACK` |
| `after-entry-switch` | 同上 | 入口已指向 Go；恢复器还原 Bash 入口 |
| `after-cron` | 同上 | 项目 cron 已移除；恢复器恢复**精确原集合** |
| `after-schedule` | 同上 | schedule units 已安装、权限已收紧；恢复器先移除 timer、再还原权限与入口 |
| `disk-full` | `prepare --fault disk-full` → `syscall.ENOSPC` | **exit 13**，无 journal、无 plan，runtime/cron/entry 不变；随后正常 prepare 成功 |
| 下载中断 | Bash offer `/interrupt/idleleo`（Content-Length 截断）；Go GeoData `/interrupt` | Bash：非 0、`下载或校验失败`、零 journal/candidate；Go：`geodata-refresh failed`，旧 asset 字节不变 |

均验证：runtime 逐字节不变、用户 certbot cron 保留、xray 仍 active/enabled。
已 `COMMITTED` 后调用恢复器 → exit 3，不做隐式逆向迁移（M13）。

## 4. 原生定时入口的实现与真实运行证据

### 4.1 实现

- `internal/schedule/schedule.go`：config/state/log、4 个 job、systemd unit 模板、
  共享更新锁、原子写、sandbox 模式。
- `internal/cli/schedule.go`：`idleleo schedule install|remove|run|status`
  （`--interval`、`--geodata-url`、`--jobs`、`--json`）。
- Timer 语义：`OnActiveSec=<interval>` + `OnUnitActiveSec=<interval>`
  （不用 `OnBootSec`，避免迁移完成即触发、长时间持有更新锁）。
- 锁冲突：每 job 记 `skipped`，不静默失败。
- 失败隔离：GeoData 先全部下载到内存并校验，再原子替换；失败不覆盖旧文件。

### 4.2 容器内真实触发（不是单测声明）

同一 E2E 内：迁移完成后给 runtime 配置加入真实 Xray API
（`api.tag/listen/services` + `stats`），安装 30s timer 并重启 timer，轮询
`/var/log/idleleo/schedule/schedule.log`。真实输出：

```text
--- scheduler timer evidence (real timestamps) ---
now=2026-11-06T16:15:50Z
NEXT                        LEFT LAST                        PASSED UNIT                   ACTIVATES
Fri 2026-11-06 16:16:19 UTC  28s Fri 2026-11-06 16:15:49 UTC 1s ago idleleo-schedule.timer idleleo-schedule.service

○ idleleo-schedule.service - idleleo Go scheduled maintenance (Bridge migration takeover)
     Loaded: loaded (/etc/systemd/system/idleleo-schedule.service; static)
     Active: inactive (dead) since Fri 2026-11-06 16:15:50 UTC; 589ms ago
TriggeredBy: ● idleleo-schedule.timer
    Process: 4983 ExecStart=/usr/bin/idleleo schedule run (code=exited, status=0/SUCCESS)
   Main PID: 4983 (code=exited, status=0/SUCCESS)
        CPU: 51ms

2026-11-06T16:15:49Z job=auto-update result=degraded detail=no Go release channel is published; the legacy Bash auto-update cron is removed and no automatic update is performed (explicit product degradation, see README migration notes)
2026-11-06T16:15:49Z job=cert-renew result=skipped detail=no certificate files to monitor
2026-11-06T16:15:49Z job=geodata-refresh result=ok detail=geoip.dat=25 bytes geosite.dat=16 bytes; xray restarted
2026-11-06T16:15:49Z job=stats-collect result=ok detail=server=127.0.0.1:10085 bytes=4
--- end scheduler evidence ---
```

对应断言：timer 真实运行 geodata/stats、GeoData 与固定 origin 字节一致、
`stats.json` 非空、xray 重启后仍 active；随后把 GeoData origin 改为 `/interrupt`，
手动 `schedule run --jobs geodata-refresh` 返回 exit 1 且旧 asset 不变。

## 5. M01–M16 覆盖

| ID | 覆盖 | 容器内证据 |
|---|---|---|
| M01 | 是 | `auto_update=YES` + TTY：`requests=0`，入口不变 |
| M02 | 是 | 真实 `-u --yes`：`requests=0`，入口不变 |
| M03 | 是 | TTY 拒绝：零请求、不变；同意：2 次下载并 `COMMITTED`；截断下载：失败关闭、零改动 |
| M04 | 是 | XTLS fixture：audit `legacy-xtls-removed`、prepare exit 3、无 journal |
| M05 | 是 | Reality direct：runtime 逐字节不变、用户不变、metadata/journal 无密钥 |
| M06 | 部分 | TLS 多用户 4 人逐字节保留；fixture 无 shortId/spiderX，未单列 |
| M07 | 是 | 证书/私钥/自定义片段逐字节不变；`nginx -t` 与 `reload` 成功；无 ack → exit 6 |
| M08 | 是 | relay 无 Xray unit：prepare/validate/activate 全通过，nginx active |
| M09 | 部分 | 项目 `geo_update.sh` 精确移除、用户 `my-geo-refresh.sh` 保留；旧 GeoData 只做标记 |
| M10 | 是 | `after-entry-switch` 故障 + 独立恢复 |
| M11 | 是 | `after-cron` 故障 + 精确 cron 恢复 |
| M12 | 是 | 追加 1 字节后 validate exit 6，activate 拒绝，文件不被覆盖 |
| M13 | 是 | 重复 audit `already-migrated`；重复 prepare 与 recover 均 exit 3 |
| M14 | 是 | 真实 `-u` 自动路径零请求；手动 TTY 路径提交成功 |
| M15 | 是 | 缺恢复器：activate exit 3，journal 停在 `VALIDATED`，recover → `ROLLED_BACK` |
| M16 | 是 | 非 TTY / 缺写入确认 / 缺 manifest：零请求、零改动 |
| M17（新增） | 是 | Rill 审计/漂移/交接/回滚 |
| M18（新增） | 是 | 权限修复与回滚、symlink 阻断、自定义内容确认 |
| M19（新增） | 是 | 磁盘满、下载中断、`latest/download` 本地 origin |
| M20（新增） | 是 | 原生 timer 真实触发 GeoData/Stats/降级记录 |

## 6. 真实缺陷修复

### 6.1 Bash 侧：manifest 解析括号错误（首轮已修）

- 修前 `json.load(open(path).get(...))` 对 dict 调用 `.get` 后再 `json.load`，
  `AttributeError` 被 `2>/dev/null` 吞掉，4 个字段全空。
- 修后 `json.load(open(path)).get(...)`；`requests=2`、entry 切换、`COMMITTED`。

### 6.2 Go 侧：Reality direct 被误判需要 nginx（首轮已修）

- 改用 `a.NginxRequired` 后，Reality direct 为 `convertible`，M05 全链通过。

### 6.3 Go 侧：故障恢复后 crontab 多出空行（首轮已修）

- `restoreCron` 丢弃尾部空元素后重建；三处故障恢复逐项 count=1。

### 6.4 Go 侧：目录权限修复会锁死 xray 用户（本轮）

- 首轮方案把 `/etc/idleleo/cert` 目录改为 0750，xray 用户无法遍历，
  `xray restart` 失败（run1 暴露）。
- 修正：只修复**文件**权限；runtime config 0644（去掉 world-write，保留可读）；
  privkey 0640 + group 改为 xray 组；回滚恢复原 mode 与 group。

### 6.5 Go 侧：relay 无 runtime 配置时 `status` 报错（本轮）

- `app.Status` 对 `RuntimeSHA256==""` 的 relay metadata 提前返回
  `installed=true` + `metadata-has-no-runtime-sha` 警告，不再尝试加载不存在的配置；
  否则 relay 的 03-D 预验收永远 exit 4。
- 容器断言：`PASS relay: validate` 全链通过。

### 6.6 Go 侧：新增定时任务 stuck（无）

- 首轮 `DeferredTasks` 机制已删除；改为 `ScheduledJobs`/`DegradedJobs`，
  两个降级项每轮记录原因，不存在无人接管的任务。

## 7. 改动文件（本轮）

- 新增 `internal/schedule/schedule.go`、`internal/schedule/schedule_test.go`、
  `internal/cli/schedule.go`。
- `internal/legacybridge/audit.go`：Rill、自定义项、权限修复、symlink 阻断。
- `internal/legacybridge/bridge.go`：`--acknowledge-custom`、`--fault disk-full|after-schedule`、
  candidate `status --json` 预验收、schedule 安装/回滚、权限修复/回滚、Rill 契约。
- `internal/legacybridge/journal.go`：`ScheduledJobs`/`DegradedJobs`。
- `internal/cli/bridge.go`、`internal/cli/cli.go`：`audit --summary`、schedule 命令、
  新报告字段。
- `internal/app/app.go`：relay 无 runtime 时的 `status` 兼容。
- `internal/i18n/i18n.go`：新命令/子命令帮助。
- `install.sh`：`audit --summary`、`--acknowledge-custom`、迁移后任务接管提示。
- `packaging/install.sh`：manifest 解析修复。
- `tests/go-parity/phase03/run_phase03.sh` / `run_phase03_container.sh`：新增场景与断言。
- `README.md`、`CHANGELOG.md`：迁移说明。

## 8. 验证命令与结果

```text
$ bash tests/go-parity/phase03/run_phase03_container.sh > /tmp/phase03-run5.log 2>&1
image: idleleo-phase03-test:24.04
image-id: sha256:169a9a951de37b9b1a4803e3696271f073e23583d827a67b8eb8eb138658ee56
xray-bin: /tmp/xray-26/xray sha256=5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328
idleleo: 3af4932666a1967285e426c375339d2fda46f0e3e7507ed0b831c73e9c73ee71
idleleo-recover: 1e6492d8ff7be86ba85bcd340c38a5d2d6a10b345e00922e16aa15c5828d4373
systemd: running
xray: Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 linux/arm64)
nginx: nginx version: nginx/1.24.0 (Ubuntu)
== Result: 201 passed, 0 failed ==
phase03-exit=0
```

质量门禁：

```text
$ /tmp/gotoolchain/go/bin/gofmt -l cmd internal        # 无输出
$ /tmp/gotoolchain/go/bin/go vet ./...                # 通过
$ /tmp/gotoolchain/go/bin/go test ./...               # 全部 ok
$ bash -n install.sh packaging/install.sh tests/go-parity/phase03/*.sh   # 通过
$ shellcheck -S error tests/go-parity/phase03/*.sh packaging/install.sh # 无 error
```

## 9. F01–F28 状态变化

| ID | 变化 | 依据 |
|---|---|---|
| F14 | 未实现 → **部分实现（容器级）** | 原生 systemd timer 真实触发；GeoData/统计完整实现；auto-update/cert-renew 显式降级并每周记录 |
| F15 | 未实现 → **部分实现（容器级）** | `stats-collect` 用真实 Xray `api statsquery` 写入 `stats.json`；`--stats/--json/watch/reset` CLI 仍未实现 |
| F16 | 未实现 → **部分实现（容器级）** | `geodata-refresh` 下载双文件→内存校验→原子替换→重启 Xray；截断下载不覆盖旧文件 |
| F22 | 未实现 → **部分实现（容器级）** | Rill 状态审计、快照、漂移拒绝、回滚验证；Rill 自身管理命令仍未实现 |
| F19/F27 | 部分实现加强 | 迁移安装/回滚 schedule units、权限修复与 group 恢复；backup/restore、purge 仍缺 |
| F12 | 未实现（保持） | 只做到期监控与显式降级；真实 ACME 不纳入本轮 |
| F13 | 未实现（保持） | 自动更新无 Go release 通道，显式降级 |
| F26 | 部分实现（保持） | XTLS 只读阻断证据不变 |

其余项保持原状态：F01/F02/F03/F05/F06/F07/F08/F11/F18/F23/F28 为部分实现（容器级）；
F04/F09/F10/F17/F20/F21/F24/F25 未实现。

## 10. 仍未验证项与原因

1. **真实 VPS 迁移/重启**：按授权不阻塞；本轮为 `CONTAINER_VERIFIED`。
2. **真实 Release 与签名资产**：未打 tag、未发 Release；`latest/download` 只用本地
   固定 origin 模拟目录结构与 `--fetch-only`，未验证真实 GitHub 带宽/缓存。
3. **真实 ACME 签发/续期**：不纳入本轮；Go 侧只做到期监控 + 显式降级。
4. **Go 自动更新通道**：没有已发布 release，显式降级；不自动下载/替换二进制。
5. **M06 shortId/spiderX**：fixture 不含这些字段。
6. **旧 GeoData 布局迁移**：只做只读标记，未执行迁移动作。
7. **宿主 systemd/cron 资源竞争、重启持久性、长时间稳定性**：容器无法覆盖。
8. **Rill 自身安装/诊断/授权命令**：只读状态与交接已纳入，管理命令未迁移。

## 11. 能否进入 Phase 04

**可以进入 Phase 04（有条件）**。Phase 03 的缺口已逐条关闭，`CONTAINER_VERIFIED`
按授权满足门槛。Phase 04 必须继续处理：

- Go 自动更新 release 通道（当前显式降级）；
- 真实 ACME 或明确的外部续期契约（当前显式降级）；
- Rill 自身管理命令（`--rill-agent-*`）迁移；
- `--stats/--json/watch/reset` 与 backup/restore/purge 等服务命令迁移；
- 可选的真实 VPS 复验（更高等级，不阻塞）。

## 12. 复现入口

```bash
# 需要本机 Docker、arm64、真实 Xray 26.10.31 二进制
IDLELEO_XRAY_BIN=/tmp/xray-26/xray bash tests/go-parity/phase03/run_phase03_container.sh
```

脚本会构建固定基础镜像、交叉编译 `idleleo`/`idleleo-recover`、启动特权 systemd 容器，
逐个 fixture 重置状态，并在结束前删除容器。容器内使用本地 HTTPS origin
（`127.0.0.1:18443` 自签 CA）提供 GeoData、`latest/download` 与截断下载，不访问公网 Release。

## 13. 提交

- 首轮实现与测试：`807ebcb`（`develop/go-native`）
- 本轮收尾：见本报告所在提交（`git log -1`）
