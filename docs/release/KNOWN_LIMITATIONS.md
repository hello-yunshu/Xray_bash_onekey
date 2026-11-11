# Phase 04 — 显式降级与已知限制

> 原则：做不到的写清楚“是什么、为什么、对产品意味着什么、解锁条件是什么”，
> 不把容器证据写成真实 VPS 证据。以下每一项都**没有**被本轮绕过或伪造。

## 1. 证据等级

| 项 | 事实 |
|---|---|
| 全部验收环境 | 固定 digest 容器（`CONTAINER_VERIFIED`） |
| 真实 VPS | **未使用、未修改** |
| 真实 ACME（公网 CA） | **不纳入本轮**（无公网域名/CA）；本地 CA（Pebble）已验证，见第 3 节 |
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
| 产品影响 | 未配置时 Go 管理器自身不会自动升级（每轮记录 `degraded`）；但迁移**不会删除**旧的 `auto_update.sh` cron，Xray/Nginx 的自动更新仍由旧脚本继续执行，直到 Go 有等价执行器后再交接。证书同理，`ssl_update.sh` cron 保留 |
| 解锁条件 | 28 项门禁全绿 + 受保护 CI 出包 + 正式发布 manifest + 固定 URL/SHA 校验 |

已实现的安全边界（不是降级）：错误 SHA、截断下载、非 ELF、降级、磁盘满、健康检查失败
都保留旧二进制；恢复失败输出 `RECOVERY_REQUIRED`（exit 10）。

## 3. 证书：ACME / 外部续约契约

| 项 | 内容 |
|---|---|
| 是什么 | 已实现基于 **lego v5.6.0 库模式**（vendor，离线可构建）的 ACME v2 客户端，入口 `idleleo xray cert issue\|renew`；账户、订单、JWS/nonce、HTTP-01、CSR、finalize、证书下载由 lego 承担，证书对原子替换（temp+fsync+rename）、证书 0644 / 私钥 0600、webroot token 校验与 reload 回滚仍在本仓库；本轮在 **Pebble 本地 CA** 上真实验证签发、窗口内跳过、强制续期。`--reload-command` 失败恢复整对旧证书且旧对仍通过链/SAN/私钥匹配校验。负面覆盖 webroot 失效、reload 失败、只读目标、CA 拒绝域名。另保留“外部续约后状态契约”：DER 指纹变化才 `restart xray` / `reload nginx`，未变化不重启，私钥 world-readable 拒绝 reload，<30 天未变化记录 `degraded` |
| 为什么 | 本轮没有真实域名与可达的公网 CA；不伪造证书，也不调用公网 CA |
| 产品影响 | **本地 CA 已验证签发/续期事务与负面用例，公网 CA 未验证**。DNS-01、EAB、真实域名，以及 Bash 的 `idleleo-nginx` 组/重启语义未验收。S7-4 起 `install.sh` 与 `ssl_update.sh` 默认走 `idleleo xray cert issue\|renew`（native），不再下载 `get.acme.sh`；`IDLELEO_ACME_LEGACY=1` 可回退一版，`/root/.acme.sh` 保留不删。旧 cron 仍是触发点，但调用的是 native 续签；公网 CA 上的真实续签仍是未验收项 |
| 解锁条件 | 真实域名 + 可达公网 CA 的隔离环境；补 DNS-01/EAB；把 `cert-renew` 接入 scheduler 并重跑正面/负面 E2E |

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
| 为什么 | 防止 Go 管理器越界操作宿主任意 unit；容器内真实 root 写入要求 `--container` + 环境变量 + 容器标记，真机 root 放行但写入前必须记录审计日志 |
| 产品影响 | 不能管理第三方服务；真机 root 可用，但每次系统写入会在 `/var/log/idleleo/system-writes.log` 留痕（`mode=host`），审计不可写时命令拒绝执行 |
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
| Reality primary/secondary（F04） | 部分实现（容器级）：真实 Nginx + 双 Xray 后端 e2e 已过 | 双节点真实负载均衡与故障切换验收 |

## 7. 发布门禁相关限制

| 项 | 内容 |
|---|---|
| 是什么 | `check_release_gate.py` 返回 exit 2：28 pending、22 个功能缺少可执行测试 |
| 为什么 | 本轮只做实现与容器证据，未编写/伪造 28 个 L1–L3 执行器；改 JSON 状态被明确禁止。当前只有 F01/F05/F11/F26/F27/F28 有执行器 |
| 产品影响 | **不能发布、不能合并 `main`、不能打 tag**；Go 资产只是候选 |
| 解锁条件 | 28 个真实 feature test + 受保护 CI 绿色 + 独立 VM/systemd 等强制 job |

另：`go-release-qualification.yml` 已按真实布局修正（`--native-go-dir current`、
`--require-package github.com/hello-yunshu/Xray_bash_onekey/internal/service`）；
本地按同一参数实测门禁 `exit 2`（28 PENDING + 22 missing tests）。该工作流仍**零 run**：
`workflow_dispatch` 只对默认分支可见，它目前只存在于 `develop/go-native`。
`baseline_commit` 与 `PIN` 已随 2026-11-11 历史重写从 `0fa7052e…` 更新为 `3b2a5045…`
（v3.3.6 的 `install.sh` 字节未变），见 `docs/go/HISTORY_REWRITE_2026-11-11.md`。

phase01 C12 保持**已知 pin 不匹配**：pin 本身可解析，但当前 `install.sh` 因 S1 改动
与 v3.3.6 基线不同，C12.1 仍为 FAIL；这是预期状态，不要为了变绿去改基线。

## 8. CI 状态

| 项 | 内容 |
|---|---|
| 旧红灯 run | `42048259341`，head `4752f77`（重写后为 `945bc76`），job `Stats Readout (ubuntu:24.04)` |
| 根因 | 旧 readiness 检查在慢 runner 上过早判定 API 就绪 |
| 现状 | 当前代码在 amd64 + tmux 容器真实复现：`Summary: PASS=47 FAIL=0`，`repro-exit=0` |
| 候选分支 CI（head `79e8ec9`） | 四个开发 workflow 全部 success：`Go parity stage gate` `43032253403`、`Test Install` `43032253375`、`Go real-root change acceptance (container)` `43032253565`、`Go native artifacts (NOT FOR RELEASE)` `43032253332`；`Go preview qualification (NOT FOR RELEASE)` `43032253249` **success**（F01 21/0、F05 17/0、F11 21/0） |
| 曾红的原因 | 三次不同提交在 F01 报 `UNSUPPORTED_ENVIRONMENT: systemd is not usable after 30s`；同分钟另一 runner 的 run `43030084048` 成功且 `degraded 0.0s`，而修复后本 run 记录 `PASS systemd is usable: degraded after 51.2s`。判定为**真实时序问题**（等待预算不足），不是 runner 抖动；F11 的计数先 `1 -> 1` 后 `1 -> 3` 证明是 journald 滞后。修复：预算 30s → 120s，F11 改为轮询 journald。 |
| 拒绝测试在 CI 的实际执行 | `security-regression` job 中 `sudo -E bash .github/test/test_install_top_level_refusal.sh` 输出 `PASS: refused at the metadata gate (rc=1); no network, package, log or system write` |
| runner 侧网络故障（2026-11-11 13:52Z 起） | 之后的提交（`b84fc41` 文档、`891203c` 空提交重触发）上 `Test Install`、`preview`、`realroot` 变红，失败点统一是 apt：`Temporary failure resolving 'azure.archive.ubuntu.com'` / `E: Unable to fetch some archives` / `exit code 100`，与代码无关。全绿证据以 head `79e8ec9` 为准，不要引用这些红 run 判断代码质量 |
| 未完成 | 未创建 PR；`go-release-qualification.yml` 与 `publish-go-bridge.yml` 仍零 run（前者只在默认分支可 dispatch，后者还受 28 项 PENDING 门禁阻断） |
| `main` 与保护 | `main` 已于 2026-11-11 强推到重写后的 `6f291fa`（临时 `enforcement=disabled`，推完立即恢复 `active` 并回读确认）；ruleset `15353378` 的 `deletion` / `non_fast_forward` / `pull_request` / `required_status_checks` 四条规则保持不变 |
| 仍暴露的 pull ref | 普通 clone 三值 0 命中；`--mirror` clone（131 个 `refs/pull/*`）里 `4851375` 仍含一个旧用户名，仅由 `refs/pull/114..116` 可达，需 GitHub Support 清理 |
| 影响 | 不能以“CI 已绿”为依据发布 |

## 9. 安全与运维边界

- 不修改真实 VPS；容器内真实 root 写入仍要求双确认，真机 root 放行但强制写审计日志。
- 不执行浮动远程脚本（D3）；不复刻 `rm -f jail.d/*.local`（D1）。
- 不默认禁用 SELinux / 改全局 limits（D2）。
- 旧 XTLS 只读识别并阻断（D4）。
- 不收集遥测；日志中不写入私钥。
- `.workbuddy/`、`docs/plans/` 保持未跟踪。

## 10. S6/S7：信任根、helper 校验与入口退役（2026-11-12）

| 项 | 现状 | 仍未解决 |
|---|---|---|
| 版本元数据签名（S6-3） | `install.sh` 在 `load_versions` 前用 Ed25519 验 `metadata_signature`；切点为 `versions_signature_required_from="3.6.0"`：低于切点允许无签名但告警，≥ 3.6.0 缺签名即 `exit 1`；依赖 OpenSSL 3（无 `-rawin` 时 fail-closed）。`publish-shell-version.yml` 在写完 JSON、上传前 fail-closed 签名，并带 preflight 复核 | **仓库 Secret 必须配置 `IDLELEO_VERSIONS_ED25519_KEY`（与 `install.sh` 内置公钥配对的私钥）**；Secret 缺失时 workflow 直接红、拒绝无签名发布，因此若不配置，到 3.6.0 仍会断。生产版本 JSON 由独立的 API 仓库生成，该仓库尚未调用 `scripts/sign_json_ed25519.sh` |
| helper 校验（S6-2） | `release-manifest.json` 的 `helperScripts` 提供每个 helper 的 sha256，`download_script_file` 第 4 参数强制校验；切点由独立的 `helper_sha_required_from="3.4.0"` 控制（不随版本签名切点后移而放宽），≥ 3.4.0 未声明校验值的 helper 直接拒绝；已存在的 helper 也会重算 sha256，不一致则重下、失败返回非 0 | manifest 本身由发布流水线生成，人工改 manifest 不做兜底；manifest 的“生成→签名”链路见 S7-5 |
| TCP 入口（S6-1/S7-2） | `bbr_boost_sh` 默认调用 `idleleo tcp status`（失败回落 `tcp plan`），`--apply` 走 `tcp apply --profile bbr-fq --confirm`；不再下载 `Linux-NetSpeed/master/tcp.sh` | `--legacy` 只能使用本机已存在的 `tcp.sh`，不再提供下载；内核/发行版覆盖仍以容器为准 |
| speedtest（S7-1/S7-3） | 新增 `idleleo speedtest`（默认 Cloudflare 测速端点，`--json` 输出），菜单 33 改为调用它；不再下载 `superspeed.sh` | 只测下行吞吐；没有多节点/上行/延迟分解 |
| acme.sh 退役（S7-4） | 签发、续签、状态展示、卸载清理、备份全部改为 native `idleleo xray cert issue\|renew`；`ssl_update.sh` cron 保留但调用 native；卸载只删 `acme.sh --cron` 行与 `*_ecc` 目录，**保留 `/root/.acme.sh`**；`IDLELEO_ACME_LEGACY=1` 可回退一版 | 公网 CA 上的真实签发/续签仍未验收；下一版删除 `/root/.acme.sh` 前需要一次真实域名迁移演练 |
| manifest 验签（S7-5） | `internal/release` 对 Go 发布通道的 manifest 做 Ed25519 验签，canonical 形式与 `jq -cS 'del(.signature)'` 逐字节一致；缺签名、坏前缀、截断、篡改全部 fail-closed；调用方 `Apply`/`fetchManifest` 已由篡改集成测试覆盖（只测 `VerifyManifest` 的短路不再成立）。`publish-go-bridge.yml` 在发布前 fail-closed 签名 `manifest.json`，签名缺失或前缀不是 `ed25519:` 时发布 job 失败 | 候选项刷新（重建签名 manifest 并落盘）仍要等 release gate 变绿、28 项退出 PENDING 后才能由受保护流水线产出；`IDLELEO_RELEASE_PUBKEY_FILE` 仅用于测试/运维覆盖 |
| 插件化（S6-4） | 本轮明确不做 | 单独立项后再评估 |

补充：F12 仍为 `PENDING_GO_IMPLEMENTATION`。本环境没有真实公网域名、可达的公网 CA、DNS-01 与 EAB，无法签发可信证书；28 项账本一条未改，也没有为了“收尾”放宽 `check_release_gate.py` 的判据。
