# Phase 04 — F01–F28 功能迁移结果

> 本文件只记录**证据变化**，不改变授权账本。
> `tests/go-parity/parity/cases/feature_contracts.json` 仍为 **28 ×
> `PENDING_GO_IMPLEMENTATION`**，`evidence=null`；本轮**没有**因为夹具或容器通过而升格。
> 状态标签含义见 [FUNCTION_PARITY.md](../go/FUNCTION_PARITY.md) 第 1 节。

## 1. 总览

| 结论 | 数量 |
|---|---|
| 状态标签发生变化 | **0** |
| 证据加强、标签不变 | 7（F11、F12、F14、F15、F22、F27、F28） |
| 完全不变 | 21 |
| 升格为「已验证」 | **0** |
| 授权账本 `VERIFIED_GO_PARITY` | **0 / 28** |

容器 E2E 全量：`42 / 42 PASS`（`/tmp/phase04-c.log`）。
Phase 02/03 的 201/201、83/83 L0 等证据仍只在其原范围内有效。

## 2. F01–F28 逐项

| ID | 功能 | Phase 04 后 Go 状态 | 本轮证据 / 变化 |
|---|---|---|---|
| F01 | Reality 安装（普通/加 Nginx） | 部分实现（容器级） | 无新增；沿用 Phase 02 容器内 systemd + Reality 数据面证据 |
| F02 | TLS ws/gRPC/xHTTP/组合 | 部分实现（容器级） | 无新增；TLS 真实证书仍不纳入 |
| F03 | ws ONLY | 部分实现（容器级） | 无新增 |
| F04 | Reality primary/secondary 负载均衡 | 未实现 | 无变化 |
| F05 | 独立 relay（Nginx Stream） | 部分实现（容器级） | 无新增；沿用 Phase 02 真实 TCP 转发 |
| F06 | 用户查看/添加/删除、UUIDv5 | 部分实现（容器级） | 无新增；UUIDv5 仍未实现 |
| F07 | shortId / spiderX / 用户映射 | 部分实现（容器级） | 无新增 |
| F08 | 端口、target、serverNames、SNI Guard | 部分实现（容器级） | 无新增；SNI Guard 未实现 |
| F09 | `--add-upstream` | 未实现 | 无变化 |
| F10 | `--tls` 版本变更 | 未实现 | 无变化 |
| F11 | 服务状态/启停/日志 | 部分实现（容器级） | **证据加强**：`service status/start/stop/restart/reload/logs` 全部真机执行；日志读取从“未实现”变为已实现；非法 unit exit 2、sandbox root 拒绝 exit 2 |
| F12 | 证书状态/签发/续期/清理 | 未实现（有到期监控） | **证据加强**：证书 DER 指纹基线、变化才重启 Xray / reload Nginx、未变不重启、world-readable 私钥拒绝、<30 天显式降级；**ACME 签发/续期/清理仍未实现**，标签不升格 |
| F13 | `--update`、`--xray-update`、`--nginx-update` | 未实现 | 无变化。本轮 Go 自更新只更新 `idleleo` 自身，不等于 Xray/Nginx 更新 |
| F14 | `--auto-update` 与 cron | 部分实现（容器级） | **证据加强**：配置 Go 通道后真实 `0.3.0 → 0.4.0` 定时升级；未配置时 `degraded` 且保留旧二进制；**仍不覆盖旧 cron 的 Xray/Nginx 自动更新语义** |
| F15 | `--stats` / `--json` / watch / reset | 部分实现（容器级） | **证据加强**：`idleleo stats` 真实调用 `xray api statsquery` 返回 inbound 计数；`--json` 原样输出；非 root exit 5、API down exit 8；**watch/reset 仍未实现** |
| F16 | GeoData 热更新/手动刷新/旧布局 | 部分实现（容器级） | 无新增；旧布局迁移仍未实现 |
| F17 | IPv4/IPv6、DNS、端口、防火墙 | 未实现 | 无变化 |
| F18 | 分享链接/二维码/Clash | 部分实现（容器级） | 无新增；二维码仍未实现 |
| F19 | 备份/恢复/重配置保留/模式切换 | 部分实现（容器级） | 无新增；`backup/restore` CLI 仍未实现 |
| F20 | Fail2ban | 未实现 | 无变化；D1 安全差异仍待实现 |
| F21 | 流量阻断与自定义路由 | 未实现 | 无变化 |
| F22 | Rill 观察/诊断/授权/卸载 | 部分实现（容器级） | **证据加强**：只读 `rill status` 在 absent / active / stale 三种真实状态下正确输出，且不写 Rill 状态；**安装/诊断/授权/两阶段卸载命令仍未迁移** |
| F23 | 六语言 | 部分实现（容器级） | 无新增；fr/fa/ru/ko 仍回退英文 |
| F24 | Docker 交付 | 未实现 | 无变化。本轮用 Docker 做测试环境，不等于产品 Docker 交付 |
| F25 | TCP 优化/测速 | 未实现 | 无变化；D3 安全差异仍待实现 |
| F26 | XTLS ONLY 旧模式 | 部分实现（容器级） | 无新增；按设计只读识别/阻断 |
| F27 | `--backup/--restore/--purge/--service-*` | 部分实现（容器级） | **证据加强**：`--service-*` 等价能力（status/start/stop/restart/reload/logs）已实现并实测；`backup/restore/purge` 仍未实现 |
| F28 | 运行态与分享信息展示 | 部分实现（容器级） | **证据加强**：`help`、`show`、`stats` 只读路径在真实安装上执行，且 `/etc/idleleo` 零写入；输出契约仍未与 Bash 逐字段差分 |

## 3. 为什么没有升级任何一项

发布授权要求的是：

1. `feature_contracts.json` 中该项为 `VERIFIED_GO_PARITY` 或 `APPROVED_SAFE_DIVERGENCE`；
2. `tests/go-parity/parity/features/Fxx_test.py` 真实存在并在受保护 CI 中执行；
3. 结果来自源码构建，而不是人工填写的 evidence。

本轮只新增了**容器级实现与运行证据**，上述 1–3 均未满足：

```text
RELEASE BLOCKED: pending 28; missing executable feature tests 28
```

因此 F01–F28 保持原状态；加强的只是备注中的证据描述。

## 4. 证据索引

| 证据 | 位置 |
|---|---|
| Phase 04 容器 E2E 脚本 | [`tests/go-parity/phase04/run_phase04.sh`](../../tests/go-parity/phase04/run_phase04.sh) |
| Phase 04 容器启动脚本 | [`tests/go-parity/phase04/run_phase04_container.sh`](../../tests/go-parity/phase04/run_phase04_container.sh) |
| Phase 04 固定镜像 | [`tests/go-parity/phase04/Dockerfile`](../../tests/go-parity/phase04/Dockerfile) |
| 本轮 E2E 原始日志 | `/tmp/phase04-c.log`（42/42）、`/tmp/phase04-b.log`（36/36，旧轮次） |
| Phase 03 迁移证据 | [PHASE_03_REPORT.md](../go/PHASE_03_REPORT.md) |
| 发布门禁红灯 | [GO_RELEASE_CANDIDATE.md](GO_RELEASE_CANDIDATE.md) 第 6 节 |

## 5. 2026-11-07 复核（v3.3.5 已发布后）

**结论：仍是 `0 / 28`，本轮不升格任何一项。** v3.3.5 已真实发布，但发布的是
Bash 侧修复，Go 二进制、bridge 清单和 `VERIFIED_GO_PARITY` 都没有发布；按硬约束
“现在是 Go 实验性、需显式选择”，矩阵必须保持红。

未实现项按解锁条件分三类，本轮都没有条件执行：

| 类别 | 代表项 | 现在缺什么才能判定 |
|---|---|---|
| 需要真实公网与 CA | F12（ACME 签发/续期/清理） | 真实域名 + 可访问 CA + DNS-01/HTTP-01 环境；容器内无法签发 |
| 需要真实多机/数据面 | F04（主备负载均衡）、F24/F25（多入口/多落地） | 至少两台真实 VPS、真实 DNS 与故障切换观测；容器只能证明单机路径 |
| 需要先发布 Go 通道 | F09/F10/F13/F17/F20/F21 等 Go 原生入口 | 发布 Go 二进制与 bridge 清单，并在发布后重跑同一可执行测试；不能用 Bash 夹具替代 |

`C12.1` / `C12.2` 本轮仍为 **FAIL**，但原因已经收敛为**一行有意的加固**：

- 3.3.5 的 `-u` 分支仍写着无人读取的 `bridge_manual_invocation="on"`。为避免未来
  合并时被重新接回自动 offer，`develop/go-native` 已删除该行；因此
  `install.sh` 与已发布 pin（v3.3.4，`0af8e8f2…`）不同。
- `C12.2` 的 `git diff $PIN..HEAD -- install.sh scripts config` 只差这一行（外加
  已发布的 3.3.5 版本号）。
- **转绿条件（不可放宽）**：把这条加固随下一次 Shell 发布（例如 3.3.6）发出去，
  然后同步更新 `tests/go-parity/phase01/run_phase01.sh` 的 `PIN` / `PIN_SHA` /
  `C12.4` 期望版本和 `parity/scripts/run_parity.py` 的 pin。在发布之前把 pin 指向
  未发布提交属于自证，不能算通过。

复跑记录（2026-11-07，固定 digest 容器 `idleleo-phase01-test:1.24`，未提供
Xray 二进制因此 `C06.real` 跳过）：**32 / 34 通过，失败项恰好只有
`C12.1` / `C12.2`**；`C01`–`C11`、`C12.3`、`C12.4` 全绿。历史证据
`phase01/evidence/c01_c12.tsv` 保留 2026-11-06 带真实 Xray 的 33/35 运行。
