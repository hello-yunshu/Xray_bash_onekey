# Phase 04 — 显式降级与已知限制

> 原则：做不到的写清楚“是什么、为什么、对产品意味着什么、解锁条件是什么”，
> 不把容器证据写成真实 VPS 证据。以下每一项都**没有**被本轮绕过或伪造。

## 1. 证据等级

| 项 | 事实 |
|---|---|
| 全部验收环境 | 固定 digest 容器（`CONTAINER_VERIFIED`） |
| 真实 VPS | **未使用、未修改** |
| 真实 ACME | **不纳入本轮**（容器内无公网域名/CA） |
| 结论措辞 | 任何文档不得写“真实 VPS 已验证” |

**用户影响**：容器级结果可以证明代码路径与 systemd/HTTP/文件系统行为，但**不能**
证明特定发行版内核、云厂商镜像、真实 DNS/防火墙、宿主重启后的行为。

**解锁条件**：在隔离测试 VPS 上按 `04_验收发布与回退.md` 第 2 节矩阵重跑同一 E2E，
并保存命令、时间戳、commit 与原始日志。

## 2. 自动更新通道

| 项 | 内容 |
|---|---|
| 是什么 | Go 自更新通道已实现，但**必须显式配置** manifest URL 才会运行 |
| 为什么 | 本轮没有发布 Go Release，也没有官方 manifest URL；不猜测来源是安全要求 |
| 产品影响 | 迁移到 Go 后，若用户没有执行 `idleleo update configure --manifest-url …`，定时任务每轮记录 `degraded`，**用户失去自动更新能力**（但不会静默失败，`schedule.log` 有明确原因） |
| 解锁条件 | 28 项门禁全绿 + 受保护 CI 出包 + 正式发布 manifest + 固定 URL/SHA 校验 |

已实现的安全边界（不是降级）：错误 SHA、截断下载、非 ELF、降级、磁盘满、健康检查失败
都保留旧二进制；恢复失败输出 `RECOVERY_REQUIRED`（exit 10）。

## 3. 证书：ACME / 外部续约契约

| 项 | 内容 |
|---|---|
| 是什么 | 只实现**外部续约后的状态契约**：记录证书 DER 指纹基线；指纹变化才 `restart xray` / `reload nginx`；未变化不重启；私钥 world-readable 拒绝 reload；到期或 <30 天未变化记录 `degraded` |
| 为什么 | 容器内无法完成真实 ACME 签发/续期；不伪造证书，也不调用外部 CA |
| 产品影响 | **ACME 签发、手动续期、证书清理均不可用**。用户必须继续用外部工具（如 certbot）续期；Go 只负责“续约后让服务用上新证书”。低于 30 天且未变化时，产品明确告警但**不会自动续期** |
| 解锁条件 | 真实域名 + 可达 CA 的隔离环境；实现签发/续期/清理并通过真实 ACME E2E |

## 4. Rill 管理命令

| 项 | 内容 |
|---|---|
| 是什么 | 只有只读 `idleleo rill status`（installed / status / enabled / mode / observationAge / warning） |
| 为什么 | Rill 安装、诊断、授权、两阶段卸载涉及外部组件与权限模型，本轮未迁移 |
| 产品影响 | 用户**不能通过 Go 管理器安装/授权/卸载 Rill**；只能查看状态。已迁移的机器上旧 Bash 不在正常控制路径，因此这些操作暂时只能人工执行或依赖既有 Rill 资产 |
| 解锁条件 | 完成 F22 的安装/诊断/授权/卸载命令，并在容器内验证幂等与回滚 |

只读状态复用 legacybridge 的审计投影，不复制 Rill 内容、不写 Rill 状态。

## 5. 服务类 CLI 的范围

| 项 | 内容 |
|---|---|
| 是什么 | `service status/start/stop/restart/reload/logs` 仅允许 `xray`、`nginx`、`idleleo-schedule.timer` |
| 为什么 | 防止 Go 管理器越界操作宿主任意 unit；真实 root 写入还要求 `--container` + 环境变量 + 容器标记 |
| 产品影响 | 不能管理第三方服务；在非容器真实 root 上默认拒绝写入（避免误操作宿主） |
| 解锁条件 | 明确的产品需求与权限模型；当前按最小权限原则保留 |

## 6. 仍未迁移的功能（用户会失去的旧能力）

| 功能 | 影响 | 解锁条件 |
|---|---|---|
| `backup` / `restore` / `purge` CLI（F19/F27） | 不能用 Go 做完整备份/恢复/彻底卸载；迁移路径自身的快照/回滚仍可用 | 实现路径白名单、恶意归档拒绝、模式恢复并做故障注入 |
| Xray/Nginx 更新（F13） | 不能通过 Go 更新 Xray/Nginx；Go 自更新只更新自身 | 实现下载事务、SHA、降级拒绝、失败注入 |
| Fail2ban（F20） | 无 Go 实现；D1 安全差异（不得删第三方 jail）待落地 | 实现自有边界 + 第三方 jail 保留 |
| 防火墙/流量阻断（F21） | 无 Go 实现 | 规则生成 + `xray -test` + 事务化 |
| 自定义 routing/DNS/outbounds 编辑 | 只在迁移审计中保护，未提供编辑命令 | 安全编辑或明确拒绝方案 |
| Docker 产品交付（F24） | 本轮 Docker 只是测试环境 | 真实镜像、entrypoint、volumes、fake-systemctl |
| 多发行版 / RPM / SELinux | 只跑 Ubuntu 24.04 容器 | Debian 12/13、CentOS Stream 10、Rocky/Alma、SELinux Enforcing |
| 真实 amd64 硬件 | 只有 amd64 容器执行 | 真实 amd64 主机/云实例 |
| `stats watch` / `stats reset`（F15） | 只有一次性查询与 `--json` | 实现 watch/reset 并与 Bash 契约差分 |
| 六语言完整文案（F23） | fr/fa/ru/ko 回退英文 | 逐条与 Bash 文案差分 |
| Reality primary/secondary（F04） | 未实现 | 双节点真实负载均衡验收 |

## 7. 发布门禁相关限制

| 项 | 内容 |
|---|---|
| 是什么 | `check_release_gate.py` 返回 exit 2：28 pending、28 个功能测试缺失 |
| 为什么 | 本轮只做实现与容器证据，未编写/伪造 28 个 L1–L3 执行器；改 JSON 状态被明确禁止 |
| 产品影响 | **不能发布、不能合并 `main`、不能打 tag**；Go 资产只是候选 |
| 解锁条件 | 28 个真实 feature test + 受保护 CI 绿色 + 独立 VM/systemd 等强制 job |

另：`go-release-qualification.yml` 的 `current/go` 路径与根模块布局不一致，当前即使
门禁项齐全也无法直接跑通；本轮未修改工作流，以免制造“绿灯假象”。

## 8. CI 状态

| 项 | 内容 |
|---|---|
| 旧红灯 run | `42048259341`，head `4752f77`，job `Stats Readout (ubuntu:24.04)` |
| 根因 | 旧 readiness 检查在慢 runner 上过早判定 API 就绪 |
| 现状 | 当前代码在 amd64 + tmux 容器真实复现：`Summary: PASS=47 FAIL=0`，`repro-exit=0` |
| 未完成 | 候选分支**没有**绿色 GitHub Actions run（未创建 PR；workflow 只对 main/PR/dispatch 触发） |
| 影响 | 不能以“CI 已绿”为依据发布 |

## 9. 安全与运维边界

- 不修改真实 VPS；真实 root 写入门禁默认拒绝。
- 不执行浮动远程脚本（D3）；不复刻 `rm -f jail.d/*.local`（D1）。
- 不默认禁用 SELinux / 改全局 limits（D2）。
- 旧 XTLS 只读识别并阻断（D4）。
- 不收集遥测；日志中不写入私钥。
- `.workbuddy/`、`docs/plans/` 保持未跟踪。
