# Phase 03 报告 — Bridge 旧用户迁移

> 分支：`develop/go-native`　基线：`bc16c1c`　实现提交：`807ebcb`
> 日期：2026-11-06　证据等级：`CONTAINER_VERIFIED`

## 0. 结论

Phase 03 的 Bridge 实现、Bash 手动更新发现路径和独立恢复器已完成，并在固定 digest 的
`ubuntu:24.04` 特权 systemd 容器内用真实 Xray 26.10.31、真实 nginx 1.24、真实 crontab
和真实 TTY 跑通 **136 / 136** 项检查，`phase03-exit=0`。

- 满足 2026-11-06 用户授权口径：**`CONTAINER_VERIFIED` 视为门槛满足**；
  本轮**不是** `REAL_VPS_VERIFIED`，不得表述为“真实 VPS 已验证”。
- 真实 ACME 签发/续期仍**不纳入本轮验收**（容器内无公网域名与真实 CA）。
- 未合并 `main`、未打 tag、未发 Release；`.workbuddy/`、`docs/plans/` 未提交。

## 1. 固定环境与工件

| 项目 | 值 |
|---|---|
| 基础镜像 | `ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` |
| 构建镜像 | `idleleo-phase03-test:24.04`，image ID `sha256:a7090c72d05c3e848262a3607847d564a6406e55e0ae7562d4548cc884fd96bf` |
| 容器 | `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw`，PID1 `/usr/lib/systemd/systemd` |
| 宿主内核 | `7.2.12-orbstack-00394-gbecdd6130068`（`linux/arm64`） |
| systemd | `systemctl is-system-running` = `running` |
| Xray | `26.10.31 a4a3dff (go1.27.3 linux/arm64)`；sha256 `5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328` |
| nginx | `nginx/1.24.0 (Ubuntu)` + `libnginx-mod-stream`（`ngx_stream_module.so`） |
| Go 二进制 | 交叉编译 `GOOS=linux GOARCH=arm64`；`idleleo` sha256 `bfd6974bebef9021693a8e3dd5b8011c0cee9641d5273efced4c923d09aa1b12`，`idleleo-recover` sha256 `47d4213c163b3268f6510a80b72200a650a47d7b489ce346f44bd1f9746b2c4d` |
| 版本 | 候选 `idleleo 0.1.0-phase01 (go)` |

> 镜像 ID 每次 `docker build` 会因 apt 元数据层变化而不同；基础镜像 digest 固定，apt
> 与真实 systemd/nginx 均来自固定发行版。`run_phase03_container.sh` 每次新建容器，
> 不复用调试容器。

## 2. 工作包逐条完成情况

### 03-A 发布链与迁移发现 — 部分完成

| 项 | 状态 | 证据/说明 |
|---|---|---|
| 双版本通道隔离 | 部分 | Bash `-u` 只使用 `XRAY_VERSIONS_FILE` 的 shell 字段；Go 资产来自独立 manifest（`/etc/idleleo/bridge/asset.json`）。尚未有真实 Release 站点 |
| Bridge-aware Bash 小版本 | 完成 | `install.sh` 新增 `bridge_migration_offer`、`--internal-bridge-offer`、`-u` 手动 TTY 挂钩；`bash -n` 通过 |
| 旧版手动 `--update` 衔接 | 完成（容器级） | M14：真实 `-u` 手动 TTY 两次确认后下载 2 个固定资产并 `COMMITTED`；`-u --yes` 路径零 Go 请求 |
| 三条件授权（TTY+命令+同意） | 完成 | M16/M01/M02/M03 共 10 项断言：非 TTY、`auto_update=YES`、`-u --yes`、拒绝全部 `requests=0` |
| 同意前变更摘要 | 部分 | 只提示“检测到可迁移的 Bash 安装…是否继续”；未展示完整的旧版本/模式/空间/资产摘要 |
| 固定资产 + SHA256/ELF 校验 | 完成 | 容器内本地 HTTPS origin 记录每次请求；sha256 + ELF magic 校验；缺 manifest/缺写入门禁均零请求 |
| 与 Go 新安装器区分 | 完成（代码） | `packaging/install.sh` 走 `--manifest` 固定 URL+SHA、`--proto '=https,file'`、ELF、`version` 自检后 `exec idleleo xray install --container`；**未在容器内执行该脚本**（无 Release 资产） |

### 03-B 只读审计与差异计划 — 部分完成

- 完成：读取 `install_config.json`、实际 Xray JSON、relay 片段、xray/nginx unit 的
  `User/Group/ExecStart`、active/enabled、证书指纹、旧 GeoData、项目/用户 cron 区分、
  entry 是否已指向 Go；输出 `plan.json`（机器可读）与 verdict
  `convertible` / `needs-fix` / `blocked`。
- 完成：`already-migrated`、XTLS、缺 metadata、坏 JSON、runtime 用户为空、
  Reality 缺 privateKey、端口冲突、缺 relay 片段、缺恢复用旧脚本 → `blocked`。
- 未完成：**Rill 状态审计**、**目录权限/软链异常的修复项**、**自定义内容无法安全合并的
  人工确认项**。审计在容器内只读运行，未下载、未写 `/etc`、未重启服务（M05/M07/M08/M04 断言）。

### 03-C 快照准备与 Journal — 基本完成

- 完成：兼容旧锁路径 `/run/lock/idleleo-update.lock`（`host.AcquireUpdate`，非阻塞 flock，
  进程死亡自动释放）。容器内实测：Bash 同类锁被持有 → `bridge prepare` **exit 13**；
  释放后同一命令 exit 0（3 项断言）。
- 完成：快照含入口目标/哈希、旧脚本可执行副本、unit 与配置哈希、证书与密钥指纹、
  cron 精确行、服务 active/enabled；不复制私钥明文、不整份复制 `/root` 或整张 crontab。
- 完成：独立恢复器 `/opt/idleleo/recovery/idleleo-recover`（仅标准库），准备阶段校验收录
  的 candidate/recovery SHA256；M15 证明恢复器缺失时激活被拒（exit 3）。
- 完成：`PREPARED` 原子写 + `fsync`；受控 metadata `/etc/idleleo/v1/metadata.json`
  只引用运行路径，实测不含 privateKey/UUID/shortId 明文。
- 完成：Go 规范状态与原生 Xray JSON 对照（用户数、Reality 私钥、端口、relay role）；
  漂移 → exit 6（M12）。

### 03-D 候选 Go 的真实预验收 — 部分完成

- 完成：candidate SHA256 一致且可执行（`version` exit 0）。
- 完成：节点用真实 Xray `-test -config`；TLS/relay 用真实 `nginx -t -c`；relay 无 Xray 时
  不要求 Xray（M08）。
- 未完成：未以“转换后的 manager.json”加载 candidate 的 `status` 只读视图；
  Rill 交接契约未纳入。

### 03-E 入口与任务切换 — 完成（有功能缺口）

- 完成：`ACTIVATING` journal 先落盘；Go 二进制写入 `/opt/idleleo/bin/idleleo`，
  `/usr/bin/idleleo` 原子 symlink 切换；旧 Bash 保留在 `/opt/idleleo/recovery/legacy-install.sh`。
- 完成：只精确移除本项目 4 条 cron（`auto_update`/`ssl_update`/`geo_update`/`xray_stats`），
  用户 certbot 与自定义 geo 刷新 cron 逐字节保留；故障恢复后每条项目 cron 恰好一次、无空行。
- 完成：迁移后 `xray`/`nginx` 仍 `active/enabled`，`systemctl restart xray` 与
  `systemctl reload nginx` 真实成功；runtime 配置、用户数、证书、私钥、自定义片段、
  unit 文件逐字节不变。
- **缺口**：Go 侧尚未提供 `auto_update`/证书续期/GeoData/统计的定时入口。迁移会移除这些
  旧 cron 并把它们记入 `DeferredTasks` 警告；迁移后这些自动化功能暂停，直到 Phase 04 的
  Go 调度实现。这是有意的“只能有一套正式管理器”取舍，但属于功能回退，必须记录。
- 未完成：README/CHANGELOG 的旧用户迁移步骤与回滚说明（无 Release，暂未编写）。

### 03-F 强杀/重启后的继续或恢复 — 完成（覆盖 3 个故障点）

| 故障点 | 注入 | 结果 |
|---|---|---|
| `after-activating` | `activate --fault` → exit 70 | journal 保持 `ACTIVATING`，入口仍 Bash；独立恢复器 exit 0 → `ROLLED_BACK` |
| `after-entry-switch` | 同上 | 入口已指向 Go；恢复器还原 Bash 入口 |
| `after-cron` | 同上 | 项目 cron 已移除；恢复器恢复**精确原集合**（逐项 count=1） |

均验证：runtime 逐字节不变、用户 certbot cron 保留、xray 仍 active/enabled。
已 `COMMITTED` 后调用恢复器 → exit 3，不做隐式逆向迁移（M13）。

## 3. M01–M16 覆盖

| ID | 覆盖 | 容器内证据 |
|---|---|---|
| M01 | 是 | `auto_update=YES` + TTY：`requests=0`，入口不变 |
| M02 | 是 | 真实 `-u --yes`：`requests=0`，入口不变（注：`--allow-major` 未单列，同一代码路径） |
| M03 | 是 | TTY 拒绝：零请求、入口/cron/runtime 不变；同意：2 次下载并 `COMMITTED` |
| M04 | 是 | XTLS fixture：audit `legacy-xtls-removed`、prepare exit 3、无 journal |
| M05 | 是 | Reality direct：runtime 逐字节不变、用户不变、metadata/journal 无密钥 |
| M06 | 部分 | TLS 多用户 4 人逐字节保留；**fixture 无 shortId/spiderX，未单列验证** |
| M07 | 是 | 证书/私钥/自定义片段逐字节不变；`nginx -t` 与 `reload` 成功 |
| M08 | 是 | relay 无 Xray unit：prepare/validate/activate 全通过，nginx active |
| M09 | 部分 | 项目 `geo_update.sh` 被精确移除、用户自定义 `my-geo-refresh.sh` 保留；旧 GeoData 目录只做标记 |
| M10 | 是 | `after-entry-switch` 故障 + 独立恢复 |
| M11 | 是 | `after-cron` 故障 + 精确 cron 恢复 |
| M12 | 是 | 追加 1 字节后 validate exit 6，activate 拒绝，文件不被覆盖 |
| M13 | 是 | 重复 audit `already-migrated`；重复 prepare 与 recover 均 exit 3 |
| M14 | 是 | 真实 `-u` 自动路径零请求；手动 TTY 路径提交成功 |
| M15 | 是 | 缺恢复器：activate exit 3，journal 停在 `VALIDATED`，recover → `ROLLED_BACK` |
| M16 | 是 | 非 TTY / 缺写入确认 / 缺 manifest：零请求、零改动；真实 TTY 不永久阻塞（150s 超时兜底） |

## 4. 真实缺陷修复

### 4.1 Bash 侧：`bridge_migration_offer` manifest 解析括号错误（真实缺陷，已修）

- 修前（真实容器，run6/run7 原始日志）：合法 manifest 下仍输出
  `Go 迁移清单不完整，跳过（未下载、未改动`，`requests=0`，入口与 journal 均未变化。
  根因：`json.load(open(sys.argv[1]).get(...))` 对 dict 调用 `.get` 后再 `json.load`，
  抛 `AttributeError` 并被 `2>/dev/null` 吞掉，4 个字段全为空。
- 修后：`json.load(open(sys.argv[1])).get(...)`；同一 manifest 下 offer 两次确认，
  `requests=2`，`entry=/opt/idleleo/bin/idleleo`，journal `COMMITTED`。
- 容器断言：`PASS M03/M05: TTY consent downloads exactly 2 pinned assets`、
  `PASS M03/M05: consented TTY offer switched the entry`、`PASS offer: journal COMMITTED`。

### 4.2 Go 侧：Reality direct 被误判需要 nginx（已修）

- 修前条件：`a.TLS != "None" && a.Role == "node"` 时追加 `nginx-unit-missing`，
  而无 nginx 的 Reality direct 合法安装因此落入 `needs-fix`。
  （该缺陷在提交前的容器调试运行中暴露；当时的原始日志未保留为仓库工件。）
- 修后：改用 `a.NginxRequired`（由 role/TLS/reality_add_nginx 计算），
  容器断言 `PASS reality: audit convertible, 1 user, no nginx`，且 M05 全链通过。

### 4.3 Go 侧：故障恢复后 crontab 多出空行（已修）

- 修前（run5 原始日志）：`FAIL after-activating: cron mismatch`、
  `FAIL after-entry-switch: cron mismatch`、`FAIL after-cron: cron mismatch`；
  `diff -u` 显示 `my-geo-refresh.sh` 与 `auto_update.sh` 之间多一空行。
- 根因：`restoreCron` 保留原文件切分后的尾部空元素，再追加项目行。
- 修后：丢弃尾部空元素后重建；三处故障恢复均
  `PASS after-*: exact cron set restored`，并逐项断言每条项目 cron 恰好一次。

## 5. 改动文件

实现提交 `807ebcb`（12 files, +3406）：

- `install.sh`：`bridge_migration_offer`、`--internal-bridge-offer`、`-u` 手动 TTY 挂钩、`-u` 设置 `bridge_manual_invocation=on`。
- `internal/cli/cli.go`、`internal/cli/bridge.go`：`bridge audit|prepare|validate|activate|recover|status`，顶层 `recover` 别名。
- `internal/legacybridge/{audit,bridge,journal}.go`、`bridge_test.go`：审计/计划、快照、journal、激活、恢复、锁。
- `cmd/idleleo-recover/main.go`：仅标准库的独立恢复器。
- `packaging/install.sh`：新用户受控 Go 引导。
- `tests/go-parity/phase03/{Dockerfile,run_phase03_container.sh,run_phase03.sh}`：固定 digest systemd 容器 E2E。

## 6. 验证命令与结果

```text
$ bash tests/go-parity/phase03/run_phase03_container.sh > /tmp/phase03-run11.log 2>&1
launcher rc=0
image: idleleo-phase03-test:24.04
image-id: sha256:a7090c72d05c3e848262a3607847d564a6406e55e0ae7562d4548cc884fd96bf
xray-bin: /tmp/xray-26/xray sha256=5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328
idleleo: bfd6974bebef9021693a8e3dd5b8011c0cee9641d5273efced4c923d09aa1b12
idleleo-recover: 47d4213c163b3268f6510a80b72200a650a47d7b489ce346f44bd1f9746b2c4d
systemd: running
kernel: 7.2.12-orbstack-00394-gbecdd6130068
xray: Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 linux/arm64)
nginx: nginx version: nginx/1.24.0 (Ubuntu)
idleleo candidate: idleleo 0.1.0-phase01 (go)
== Result: 136 passed, 0 failed ==
phase03-exit=0
```

新增锁断言（本报告对应的最终一轮）：

```text
PASS lock: prepare refused while the Bash update lock is held (exit 13)
PASS lock: no journal written under contention
PASS lock: prepare succeeds after the lock is released
```

质量门禁：

```text
$ /tmp/gotoolchain/go/bin/gofmt -l cmd internal        # 无输出，rc=0
$ /tmp/gotoolchain/go/bin/go vet ./...                # 通过
$ /tmp/gotoolchain/go/bin/go test ./...               # 全部 ok（internal/legacybridge 1.915s）
$ bash -n install.sh packaging/install.sh tests/go-parity/phase03/*.sh   # 全部通过
$ shellcheck -S warning tests/go-parity/phase03/*.sh packaging/install.sh   # 0.11.0，无告警
```

## 7. F01–F28 状态变化

本轮只依据真实容器证据更新，未升格任何“仅有夹具/原型”的项。

| ID | 变化 | 依据 |
|---|---|---|
| F26 | 未实现 → **部分实现（容器级）** | 容器内真实 XTLS-only fixture：audit `blocked`+`legacy-xtls-removed`，prepare exit 3，入口/cron 不变、无 journal |
| F19 | 状态不变（部分实现） | 新增 Bridge 快照与回滚证据（入口/配置哈希、故障恢复）；backup/restore CLI 仍未实现 |
| F27 | 状态不变（部分实现） | 新增迁移中 systemd active/enabled 保持、精确 cron 接管/恢复证据；purge/service CLI 仍未实现 |
| F06/F07 | 状态不变（部分实现） | 迁移保留 4 用户与配置逐字节；shortId/spiderX 未单列验证 |
| F14 | 状态不变（未实现） | 仅“精确移除旧 cron + 故障恢复”，Go 定时入口未实现，迁移后相关自动化暂停 |

其余项保持原状态（F01/F02/F03/F05/F08/F11/F18/F23/F28 仍为部分实现（容器级）；
F04/F09/F10/F12/F13/F15/F16/F17/F20/F21/F22/F24/F25 仍未实现）。

## 8. 仍未验证项与原因

1. **真实 VPS 迁移/重启**：按授权不阻塞；本轮为 `CONTAINER_VERIFIED`。
2. **真实 Release `latest/download/install.sh` 与签名资产**：未打 tag、未发 Release，
   用户明确禁止；`packaging/install.sh` 只做了语法与代码层验证，未在容器内实跑。
3. **Rill 状态审计与交接**：未实现。
4. **迁移后 Go 定时任务**：未实现；`auto_update`/证书续期/GeoData/统计 cron 被移除并
   记为 `DeferredTasks`，属于已知功能回退。
5. **M06 shortId/spiderX**：fixture 不含这些字段，只有“多用户逐字节保留”证据。
6. **真实 ACME**：不纳入本轮验收（无公网域名/CA），未伪造结果。
7. **空间不足、下载中断、manifest 错误**：本轮只测“缺 manifest / 缺写入门禁”，
   未注入磁盘满与半途断网。
8. **旧 GeoData 旧布局迁移**：只做只读标记，未执行迁移动作。

## 9. 能否进入 Phase 04

**可以进入 Phase 04（有条件）**：Phase 03 的全部代码路径与故障恢复已在容器内真实验证，
且 `CONTAINER_VERIFIED` 按授权满足门槛。Phase 04 必须把以下项作为发布前硬性工作：

- Go 侧定时入口（auto update / 证书续期 / GeoData / 统计）或明确的产品降级说明；
- Rill 状态审计与交接契约；
- 真实 Release 资产的生成、`latest/download` 验证与 README/CHANGELOG 迁移说明；
- 下载中断/磁盘满/manifest 错误注入；
- 可选的真实 VPS 复验（更高等级，不阻塞）。

## 10. 复现入口

```bash
# 需要本机 Docker、arm64、真实 Xray 26.10.31 二进制
IDLELEO_XRAY_BIN=/tmp/xray-26/xray bash tests/go-parity/phase03/run_phase03_container.sh
```

脚本会构建固定基础镜像、交叉编译 `idleleo`/`idleleo-recover`、启动特权 systemd 容器，
逐个 fixture 重置 `/etc/idleleo`、`/opt/idleleo`、`/var/lib/idleleo`、crontab 与 unit，
并在结束前删除容器。容器内使用本地 HTTPS origin（127.0.0.1 自签 CA）记录每个资产请求，
不访问公网 Release。

## 11. 提交

- 实现与测试：`807ebcb`（`develop/go-native`）
- 本报告与矩阵/审计更新：本报告所在提交（见 `git log`）
