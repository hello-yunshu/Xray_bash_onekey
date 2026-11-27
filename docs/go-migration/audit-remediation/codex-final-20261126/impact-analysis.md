# 当前候选补记（2026-11-28，更新至产品 SHA 85340b48）

当前正式账本绑定 `85340b4871fccfac703566a2ce00469e4a8a9371`，34 项为 29 DUAL、3 FAIL（OPS-14/16/27）、1 BASH_ONLY（OPS-30）、1 BLOCKED（OPS-18）、0 NOT_RUN；严格 rc=1。OPS-17a 与 OPS-25/26 现有当前候选真实双端通过证据，详见报告和证据索引。历史复用末段 `9e495b38 → 85340b48` 的 Git 文件列表及 binary diff SHA 在 `evidence/impact-reuse-9e-to-85340b48.json`。

OPS-14 另有当前候选真实负载 stats watch：35/35 Reality 请求 HTTP 200，20 个样本中 32 个正 inbound rate 点；Go 不记录对端地址，Bash iftop 有 per-peer 视图。仍保留 DIFF，等待契约所有者确认信息粒度与隐私取舍。OPS-16 机器可读状态/只读核验优势和 OPS-27 第三方文件保护安全优势保留未批准差异，未由执行者代批。OPS-30 Go `--lang` 逐命令语言选择 Docker 实测正常且不写偏好，但不替代 Bash 持久的完整语言偏好，仍为 BASH_ONLY。

OPS-18 使用一次性 Docker 对共享 OrbStack Linux 内核进行只读能力检查，available 只有 `reno cubic`、current `cubic`，没有 BBR。Go `tcp status` 返回 rc=0 并如实报告；在 `--network none --cap-drop=ALL` 的丢弃容器中实测 `tcp apply --confirm` rc=12，明确拒绝，`changed=false`，当前算法不变且没有创建受管 sysctl/状态文件。`evidence/ops18-kernel-probe-85340b48-20261128.log` 保留初次可选 qdisc 路径不存在导致的 rc=1 诊断和后续正确只读探测；`evidence/ops18-go-tcp-refusal-85340b48-20261128.log` 记录 Go 拒绝边界。此环境没有 BBR 模块，无法完成成功应用和回滚验证；不加载模块、不触碰宿主/生产 sysctl，OPS-18 继续 BLOCKED。

当前候选 7 项远程 CI 在产品提交 `85340b48` 上均通过；最终交付文档提交的 Privacy Guard 另行通过。最终报告、任务账本、证据索引优先于以下保留的历史快照。

---

# 最新候选更新（2026-11-28）

当前产品候选 `9e495b38a5574f53e37bd11e4b3c8f196f76e25b`。已将 OPS-14、OPS-16、OPS-20 的真实 Docker/Xray/Nginx/client 运行纳入严格 OPS-34；保留 OPS-14/16 的 FAIL，严格结果为 28 DUAL、3 FAIL（14/16/27）、1 BASH_ONLY（30）、2 BLOCKED（17a/18）、0 NOT_RUN，退出码 1。严格原始结果：`evidence/strict-ledger-final-9e495b38-20261128.log`。OPS-14 的 Go 30 样本 stats 与 Reality L4 成功；OPS-16 的只读证书状态 JSON、dry-run 预检与证书/私钥 SHA 不变均成功；OPS-20 当前候选双端 1 MiB HTTP/body SHA 与真实 inbound counter 增量通过。

历史复用链为 `7d3e19d9 → 8ff26917 → 9e495b38`，逐段通过验收器校验。末段仅 OPS-14/16 受影响，故当前候选对其补跑；OPS-03/17b 与四类冷恢复等原候选证据按链式映射保留原始 SHA，不改标为当前运行。

仍未闭环：OPS-14/16/27 需要在既有验收口径下取得可核验的正式差异裁决或达到契约一致；OPS-17a 需要 Bash 实际替换更新包的双端证据；OPS-18 需要真实宿主 BBR 验证；OPS-30 仍无 Go 等价实现/正式单侧裁决；当前 SHA 七项远程 CI 仍 CI_PENDING。Go 方案仅在有证据证明优于 Bash 时才能作为差异提案，不能由执行者自行批准。

# 最新候选更新（2026-11-28）

当前产品候选 SHA `85340b4871fccfac703566a2ce00469e4a8a9371`。严格 ledger 在增加 OPS-18 真实宿主/Docker证据后为 30 DUAL、3 FAIL（14/16/27）、1 BASH_ONLY（30）、0 BLOCKED、0 NOT_RUN，退出码 1。

OPS-18 的真实 run `ops18-host-bbr-9d32f5fd-20261128` 在一次性 Ubuntu 24.04 runner 的真实 OCI 容器中执行，容器以 host network 和 privileged 方式共享 runner 内核，核实 `bbr` 可用；OCI image ID、二进制、Bash 脚本、测试驱动与 manifest SHA 均可复核。Bash TCP wrapper 和原生 Go CLI 各自实际 apply/rollback，运行态、状态文件、事务 journal 与宿主原始 qdisc/congestion 均有前后核验。正式行升级为 DUAL。首轮 PATH 诊断失败被单独保留，未计为通过，第二次修复 harness 后的成功 run 是正式证据。

OPS-03 边界探针 `ops03-boundary-23fa585f-20261127` 验证共享 shortId、旧凭据撤销后新连接拒绝、重启后仍拒绝、存活基线用户可连接。其源码变更范围在三段 `impact-reuse` 映射中均不涉及 `internal/xraycfg`，正式 OPS-03 可复用原始证据并保留原 product SHA；不将其写作 85340 上重新执行。

审计/测试提交 `85340b48..9d32f5fd` 对产品候选不改变运行代码；差异是 OPS-18 专用 Docker 主机驱动/workflow。该提交上的 7 个既有 CI workflow 和 OPS-18 专用 workflow 均成功，产品候选仍绑定 `85340b48`。本轮更新后的报告与账本把受影响证据与复用证据分别标明，未把测试 harness SHA 当作产品代码 SHA。

仍未闭环：OPS-14/16/27 的正式行为差异裁决，以及 OPS-30 Bash 持久语言偏好差异；它们没有足够授权可自动更改严格分类。Go 方案可不同，但“更好”的证据不会自动变成契约批准。

---

# 历史证据影响分析（本轮候选 9e495b38；8ff26917 为上游候选）

## 当前候选与本轮代码差异

- 当前产品源码提交：`8ff26917e3e381d4023b7319d5405f7ba871f289`。
- 当前 Go CLI SHA-256：`c7fd0055b157fc8c7e848f1edb640161ba245a4373e3a5b0b57b36dbc18e237d`。
- `8ff26917` 相对 `7d3e19d9` 仅新增 `install.sh` 的 restore 修复：恢复真实 Xray 配置校验前，创建并按 systemd 单元用户/组收紧 `/var/log/xray`。该改动会影响 OPS-25/26，故二者在 `8ff26917` 上双端重跑；其余 OPS 通过机器可验证的祖先提交映射复用。映射记录确切改动文件、Git diff SHA、受影响与可复用 OPS ID，路径为 `evidence/impact-reuse-7d3-to-8ff26917.json`。验收器对每个复用行保留原 `productCodeSha` 并写明 `evidenceReuse`，不会改写旧 run 的候选身份，也不批准行为差异。
- 自先前冻结的产品提交 `f4deaf77` 后，产品代码变更集中在：`internal/cli/flags.go`、`internal/cli/xraylogs.go`、`internal/componentupdate/update.go`、`internal/deploy/guard.go`、`internal/deploy/logs.go`、`internal/i18n/i18n.go`（含相邻测试）。`internal/deploy/certclear.go`、`internal/xraycfg` 与 Bash 安装入口没有从该冻结点变化。
- 验收器、驱动与其独立工件有额外改动。每个矩阵 run 都保留自己真实的 `driverSha`、依赖摘要、镜像和二进制；未将不同 run 的驱动 SHA 合并或改写。

## 影响范围与本轮处理

| 证据族 / 旧路径 | 原候选与产物 | 影响分析 | 本轮处理与当前结果 |
|---|---|---|---|
| OPS-01…32 历史完整矩阵（round4 / round5 / f4deaf77） | 各自 run 的代码、二进制和 driver SHA | Guard、日志、更新器与验收器范围内的 OPS 不能因历史全绿继承当前通过；其他行也不能只靠旧 run 身份签收 | 当前候选分批执行真实双端 OPS，严格账本最新为 25 DUAL、5 FAIL、1 Bash-only、3 BLOCKED、0 NOT_RUN；结果路径和每行来源见 `ledger.json` 与本轮 `evidence-index.json` |
| OPS-03 shortId、撤销和重启边界 | `ops03-boundary-23fa585f-20261127`，产品 SHA 需按 `run.json` 解读 | `internal/xraycfg` 自 f4deaf77 起未变；共享凭据、撤销旧连接和重启属于用户生命周期行为，不能由一般 add/remove 流程推断 | 边界探针保留共享 shortId、移除后旧凭据拒绝、存活用户与重启后连接证据；当前 OPS-03 又在 `ops-core-7d3e19d9` 双端复跑。流程结果可复用，Go 显式 shortId 清理与 Bash 自动清理的命令语义仍单独披露 |
| OPS-04 分享 URI、OPS-17b Nginx 更新、OPS-25/26 备份恢复 | 早期 round5 / `obsfix-final-fb55` | 旧候选不能替代新账本；更新器改动直接影响 OPS-17b；restore 修复直接影响 OPS-25/26 | OPS-04 与 OPS-17b 的 7d3e19d9 证据按影响映射复用；OPS-25/26 在 8ff26917 双端重跑，真实备份、完整性校验、修改后恢复、权限、服务校验及 Reality L4 均通过。另以全新目标复现并修复 Bash cold restore：M4 TLS/WebSocket 归档恢复后配置、证书、二进制 SHA 和权限与源端一致，Xray/Nginx active 并通过实际客户端请求。首次冷恢复失败日志保留，证明问题不是单测推断 |
| Guard 旧 mtime / 未 reload / 异步 reload / rollback / Nginx master restart | `guard-ops08-23fa585f-20261127`，产品 SHA `23fa585f…`；更早红/绿记录在 `guard-ops08-async-*` | 该后续提交相对当前 `7d3e19d9` 的 Guard 产品文件无差异（由 Git diff 复核）；它晚于旧 f4deaf77，覆盖当前 Guard 实现。验收器和报告代码改动不改变被测进程行为 | 保留真实 `nginx -t`、磁盘编辑并保留旧 mtime、reload 前 runtime-unverified、reload 后 active、异步 reload 超时回滚、restart 后 runtime-unverified、未知 SNI 请求 rc。PID 数值被强制复用没有独立真机证据，未声称测试过 |
| 证书动态路径、所有权与事务回滚 | `cert-dynamic-https-bc409-20261127`；本轮 `certclear-fault-cli-7d3e19d9-20261127` | `certclear.go` 相对 f4deaf77 无变化；旧动态路径/所有权证据不受本轮 CLI/log/Guard 变更影响。故障注入在当前真实 CLI 重跑 | 动态 `${cert_name}` HTTPS 前后成功；项目未用证书可清理、第三方及嵌套用户数据保留；两个事务失败/中断场景回滚后摘要、权限、journal/staging 核对。OPS-27 Bash/Go 差异仍是 FAIL：Go 保留第三方文件、Bash 递归删除 |
| M1–M10 双端安装、双轮、每轮真实 L4 | 早期 P2 / M6-only evidence | `internal/xraycfg` 和 Bash install 未在旧冻结点后变化，但本轮候选要求覆盖重复 slash 修复和当前二进制身份 | 当前 ARM64 Docker 镜像上重跑 10 场景 × Bash/Go × 两轮；安装 rc=0，所有适用传输两轮真实 L4 `ok`，含真实 Pebble ACME 与 Relay，见 `matrix-current-7d3e19d9-20261127/p2/install-matrix.md` |
| 98 项配置/生成对照 | `matrix-20261120-final` 及其他历史摘要 | 旧结果含旧 Go 产物；`internal/xraycfg` 在冻结点后无差异，但当前候选需要锁定 Go binary、Bash 文件及实际输出 | 当前干净 clone（repo commit 7d3e19d9、repo_dirty=0）重跑：98 Bash/Go parity + 6 A1，54 MATCH、40 MATCH_CORE_FIELDS、4 REFUSED、6 A1_PASS、0 GAP。原 pinned Debian base 的 apt 索引下载被远端关闭；采用测试脚本文档允许的本地依赖镜像（Ubuntu e2e 工具层 + 本地 Go 1.27.4 工具链），离线矩阵实际运行成功。镜像 ID、工具版本、Dockerfile 均留档 |
| P3 hot-user：raw/ws/gRPC/xHTTP | 历史 P3 run，多为更早产品 SHA | Guard/log/update 改动不覆盖 P3 pilot，但用户管理端到端当前身份仍应补充 | 当前产品 SHA 的四个独立真实 Go Docker run 均安装 rc=0、driver 62 assertions / 0 failures；保留为 Go 单侧证据，不扩写成 Bash parity |
| Go 冷恢复 Reality/TLS/Relay/Multi 与 Bash 全新目标恢复 | `goevo-coldrestore-cold-fb55-*` 与本轮 `bashcold-restore-retry-current-7d3e19d9-20261127` | Go 冷恢复四类在 7d3e19d9 有当前候选实测；新 Bash restore 修复需要实际新目标回归 | Go 四类保留 7d3e19d9 原候选绑定；Bash M4 新目标测试在 8ff26917 用真实 CLI 完整备份/恢复，Xray/Nginx 配置及服务、权限/摘要和 TLS/WebSocket 客户端均通过。首次失败显示新系统缺 `/var/log/xray`，修复后真实回归通过；不把单场景 Bash 结果外推为 Reality/Relay/Multi 的 Bash 冷恢复覆盖 |
| OPS-17a 手动签名更新 | 历史“status”记录不证明更新行为 | 当前更新入口在本轮修改范围；旧 status 不能证明下载、验签、应用或不自动更新 | 当前二进制以一次性本地签名包真实执行 check/apply，验证 check 不改二进制、apply 后摘要匹配、Xray/Nginx 服务健康、Reality L4 成功。该 Go 单侧补证不满足 formal dual-side OPS-17a 行，保持 BLOCKED |
| R1/R2、v3.3.2/v3.3.3 迁移、Xray 三版本 | round3 / round5 各自旧 commit/产物 | update/CLI 有变更，不能不经影响分析把历史升级成功当本候选通过 | 当前 R1/R2 在 M1 Reality / M4 TLS 双轮及 install fault injection 共 106 assertions 全过；历史 Bash v3.3.2 与 v3.3.3 标签各自作为源再次执行相同 106 assertions，均 0 FAIL，历史安装器 commit/SHA 单独记录；Xray 26.11.9/26.10.31/26.10.21 三版均同配置部署和 L4 通过。Debian 12/amd64 仍需补测，不改写旧 run SHA |
| S4–S9 helper 脚本、M8 ACME wrapper | `FINAL-S6*`、早期 Go wrapper run | 普通安装入口不变，但 wrapper/调度/日志行为跨越当前 i18n/log 工具改动；不与完整 Bash 主程序等同 | 当前候选完整运行 `scripts-current-retry2-7d3e19d9-20261127/s`，64/64 断言通过，含 Pebble ACME renew/repeat/failure rollback。首轮63/1是过时“up to date”断言；新版本 26.11.9 高于元数据目标 26.10.31 时产品拒绝降级，更新断言后完整重跑通过。日志均保留 |
| Xray 三版本、Debian 12、amd64 | 历史 `versions-3`、`debian12-1`、旧 amd64 runs | 平台、daemon 与 Xray 兼容性都不能由当前 ARM64 单版本容器外推 | 当前候选已在 ARM64 Docker 上用 Xray 26.11.9/26.10.31/26.10.21 对同一生成配置做 `-test`、systemd 部署及真实客户端 L4，三者通过。Debian 12 M1/M4 两轮 Bash/Go L4 当前候选实测通过。linux/amd64 Docker image 运行 M1/M4 两轮 Bash/Go L4 通过，容器 uname=x86_64；宿主/server arch=arm64，因此是模拟执行，原生 AMD64 主机未验证 |
| 30 分钟 soak + 两个 schedule 周期 | `soak-30m-1` 历史候选 | 更新、Guard、runtime 状态变化不由短 OPS sweep 覆盖 | 当前候选 `soak-diag-current-7d3e19d9-20261127` 31/31 真实采样、1863 秒、schedule timer active / runs=2，PASS；首轮 current run iter 26 超时原 runner 未记录诊断，根因未知，失败证据保留 |

## 可复用与不可复用原则

- 没有把历史二进制、驱动、runId 或代码 SHA 改写成当前候选。复用只用于代码文件未变且测试输出仍对应同一契约的专项，并由上表标明原产物。
- 当前 M1–M10、98 项、P3、冷恢复及 OPS 主矩阵均有新候选运行。完整真实业务连接、配置/服务状态、退出码来自输出证据，不由单测或 run 摘要代替。
- OPS-14 与 OPS-16 的当前差异以及 OPS-27 第三方文件保护的差异保持正式 FAIL；OPS-30 保持 Bash-only；OPS-17a/18 保持 BLOCKED；OPS-23 已在 `8ff26917` 以当前候选双端真实通过。未取得绑定候选、scope、证据指纹和期限的独立批准记录，不自动将它们转成批准差异。
- 当前 ARM64 Docker 不证明 amd64、Debian 12、外部公共 CA/IPv6、宿主 BBR、生产服务器或真实掉电行为。
- 对 `7d3e19d9 → 8ff26917` 的机器可校验复用边界：受影响项仅 OPS-25/26，已有当前 SHA 真实双端证据；其余 32 项保留 `7d3e19d9` 的原始 provenance 并附 `evidenceReuse` 映射。严格结果为 26 DUAL、3 FAIL、1 BASH-only、4 BLOCKED、0 NOT_RUN，严格验收器 rc=1。
