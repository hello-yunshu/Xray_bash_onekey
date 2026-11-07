# Phase 04 — 迁移 E2E 结果

> 证据等级：`CONTAINER_VERIFIED`。**不是真实 VPS**，也没有在真实重启后验证。
> 真实 VPS 按 2026-11-06 用户授权不作为本轮阻塞项，但不得写成已验证。

## 1. 环境

| 项 | 值 |
|---|---|
| 基础镜像 | `ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` |
| Phase 04 构建镜像 | `idleleo-phase04-test:24.04`，image ID `sha256:8737d13b89f8bf8d8b5e0136ef9f9c020876a4ac9edf146511659535894b6924` |
| 容器模式 | `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw`，PID1 systemd |
| 宿主 | macOS / OrbStack，`linux/arm64`（另做 amd64 单测复现） |
| systemd | `systemctl is-system-running` = `running` |
| Xray | `26.10.31`（容器内真实运行，统计 API 可查询） |
| nginx | `nginx/1.24.0 (Ubuntu)` + `libnginx-mod-stream` |
| Phase 04 E2E | `tests/go-parity/phase04/run_phase04_container.sh` |
| Phase 03 E2E | `tests/go-parity/phase03/run_phase03.sh` |

## 2. Phase 03 迁移链（本轮未重写，作为前置证据）

Phase 03 容器 E2E：**201 / 201 PASS**，`phase03-exit=0`（`/tmp/p05-phase03.log`，P0-5 修改后重跑）。
迁移链覆盖：只读审计 → 自定义内容确认 → 快照/journal → 预验收 → 原子入口切换 →
仅移除 Go 已有执行器的两条 cron（`geo_update.sh`、`xray_stats.sh`），保留
`auto_update.sh` 与 `ssl_update.sh` 以便证书续期和 Xray/Nginx 更新不中断 →
安装 `idleleo-schedule.timer` → `COMMITTED`。

拒绝路径（真实容器）：

| ID | 场景 | 实测结果 |
|---|---|---|
| M01 | `auto_update=YES` + TTY | `requests=0`，入口不变 |
| M02 | 真实 `-u --yes` | `requests=0`，入口不变 |
| M03 | TTY 拒绝 / 同意 / 截断下载 | 拒绝：零请求；同意：2 次下载并 `COMMITTED`；截断：失败关闭、零改动 |
| M04 | 旧 XTLS fixture | audit `legacy-xtls-removed`，prepare exit 3，无 journal |
| M05 | Reality direct | runtime 逐字节不变、用户不变、journal 无密钥 |
| M07 | 证书/私钥/自定义 nginx 片段 | `nginx -t` + `reload` 成功；未确认自定义项 → exit 6 |
| M13 | 已 `COMMITTED` 后调用恢复器 | exit 3，不做隐式逆向迁移 |

## 3. 中断点与恢复（Phase 03 真实故障注入）

6 个故障点的真实结果（`--fault` 在指定步骤以 exit 70 模拟进程中断）：

| 故障点 | 结果 |
|---|---|
| `after-activating` | journal 保持 `ACTIVATING`，入口仍 Bash；恢复器 exit 0 → `ROLLED_BACK` |
| `after-entry-switch` | 入口已指向 Go；恢复器还原 Bash 入口 |
| `after-cron` | 项目 cron 中 `geo_update.sh`/`xray_stats.sh` 已移除，`auto_update.sh`/`ssl_update.sh` 保留；恢复器恢复**精确原集合** |
| `after-schedule` | schedule units 已安装、权限已收紧；恢复器先移除 timer、再还原权限与入口 |
| `disk-full` | `syscall.ENOSPC` → exit 13，无 journal、无 plan；runtime/cron/entry 不变 |
| 下载中断 | Bash 非 0 且零 journal/candidate；Go GeoData 旧 asset 字节不变 |

均验证：runtime 逐字节不变、用户 certbot cron 保留、`xray` 仍 `active/enabled`。

**必须如实说明**：这些中断是**受控故障注入**，不是随机 `kill -9`，也没有在真实
机器重启后重新挂载/启动验证；容器不能证明宿主重启后的持久性。

## 4. Phase 04 在已迁移安装上的回归

同一容器内，Phase 04 E2E：**42 / 42 PASS**，`phase04-end 2026-11-06T17:34:52Z pass=42 fail=0`。
与本轮新增能力直接相关的真实断言：

```text
PASS scheduled auto-update applied 0.4.0 at=2026-11-06T17:34:48Z
PASS schedule status sees the release channel
PASS unconfigured auto-update is an explicit degradation
PASS degraded run kept binary
PASS cert baseline recorded without restart
PASS changed certificate restarted xray once and reloaded nginx
PASS unchanged certificate did not restart services
PASS world-readable private key blocked the reload
PASS short-lived unchanged certificate reports explicit degradation
PASS service status xray=active nginx=active
PASS service restart restarted xray (starts 3->4)
PASS service stop left xray inactive
PASS service start restored xray
PASS service logs returned journal lines
PASS unmanaged unit rejected rc=2
PASS service status refuses a sandbox root rc=2
PASS rill status reports absent on a clean system
PASS rill status active mode=observe-only
PASS rill status detects a stale observation
PASS stats --json returned a real inbound counter
PASS non-root stats preserves the legacy exit 5
PASS stats with API down reports exit 8
PASS read-only commands wrote nothing under /etc/idleleo
```

其中 `service restart restarted xray (starts 3->4)` 通过 systemd 计数变化证明是真重启，
不是只改状态文件；证书用例通过“只重启一次 / 不再重启”的计数差证明指纹契约生效。

## 5. 迁移后仍待验证

| 项 | 状态 | 说明 |
|---|---|---|
| 真实 VPS 上的 Bash 3.3.4 → Go | **未做** | 容器级证据替代，按授权不阻塞 |
| 更早 Bash 版本迁移 | **未做** | 只有 `tests/fixtures/legacy` 的代表性安装 |
| 真实断电/重启后的自动恢复 | **未做** | 容器内无真实内核重启；journal 恢复逻辑只在同进程生命周期内验证 |
| 迁移后 Bash 备份被 cron 再启动 | **已覆盖（容器）** | 移除 `geo_update.sh`/`xray_stats.sh`，保留 `auto_update.sh`/`ssl_update.sh`；用户 cron 保留 |
| 已接管后 Go 二进制被替换/损坏 | **部分覆盖** | 更新失败保留旧二进制；未覆盖人工删除后的自愈 |
