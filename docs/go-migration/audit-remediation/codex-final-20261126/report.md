# Xray Go 重构定向收尾与最终验收报告

日期：2026-11-28（Asia/Shanghai）
工作分支：`work/go-hardening-parity-20261119`
当前产品候选：`8ff26917e3e381d4023b7319d5405f7ba871f289`
Go CLI SHA-256：`c7fd0055b157fc8c7e848f1edb640161ba245a4373e3a5b0b57b36dbc18e237d`
Docker 平台：`linux/arm64`

## 验收结论

**DOCKER_DEVELOPMENT_QUALIFICATION = NO_GO**  
**RELEASE_AUTHORIZED = NO**

当前候选已获得较广的真实 Bash/Go、Docker、Xray、Nginx、配置对照、热更新、冷恢复和客户端 L4 证据，但严格 OPS-34 验收器仍返回非零：28 DUAL、3 FAIL、1 BASH_ONLY、2 BLOCKED、0 NOT_RUN。候选尚不具备 Docker 开发候选签收资格。七项当前 SHA 远程 CI 未触发，状态为 `CI_PENDING`。本报告不把未运行、单侧证据或未经批准的产品差异转换成 PASS。

## 当前正式 OPS-34 分类

| 状态 | 数量 | OPS |
|---|---:|---|
| DUAL_SIDE_VERIFIED | 28 | 01、02、03、04、05、06、07、08、09、10、11、12、13、15、17b、17c、19、20、21、22、23、24、25、26、28、29、31、32 |
| FAIL | 3 | 14、16、27 |
| BASH_ONLY | 1 | 30 |
| BLOCKED | 2 | 17a、18 |
| GO_ONLY / NOT_RUN / APPROVED_DIFF / APPROVED_SINGLE_SIDE | 0 | — |

当前 OPS-34 摘要在 `tests/e2e-diff/ledger.json`、`tests/e2e-diff/matrix.json` 的 `acceptance` 节点和 `docs/go-evolution/hardening/acceptance.json` 的 `ops` 节点中绑定候选 SHA `8ff26917…`；`acceptance.json` 顶层的历史基线字段仍保留原 SHA，未将历史验收改写成当前候选。`8ff26917` 相对上一产品候选仅修改 Bash restore 初始化 Xray 日志目录，OPS-25/26 已在此 SHA 双端重跑；其余复用行逐项保留旧 provenance，并附经 Git commit/diff 摘要核验的影响映射，不把旧 run 改标成新 SHA。OPS-23 与 OPS-12/13 均在当前候选以真实 Docker 双端运行。OPS-12/13 旧失败、一次错误断言诊断和修正后的通过均有记录；最终通过 run 逐条列出两条 OPS-13 失败历史和 OPS-12 旧失败，验收器核验修复提交仅修改 runner、运行驱动摘要、产品候选和二进制/Bash 摘要一致且时间顺序成立。正式账本为 28 DUAL、3 FAIL、1 BASH_ONLY、2 BLOCKED、0 NOT_RUN。三份当前 OPS 分类与严格模式一致，含 BLOCKED ID 列表；严格模式本轮 rc=1，保留 OPS-14/16/27 FAIL。OPS-14/16 的历史差异批准未通过当前审批校验（缺少可核验授权来源/当前证据指纹），因此作为 FAIL；OPS-27 安全差异也尚无绑定当前证据的正式批准。最新本地门禁的 Bash/Tcl 驱动解析、diff 检查、40 个采集器契约测试及正式摘要隔离均通过；严格账本按真实未决项 rc=1。更新后的隐私扫描结果见 `privacy-scan-coldrestore-final-20261128.log`；报告和逐行证据以 ledger 原文为准，索引见本目录 `evidence-index.json`。

- **OPS-12/13 DUAL_SIDE_VERIFIED**：Bash 实时菜单与 Go 有界 snapshot/`--follow` 均在真实 Xray 日志中观测到追加标记；Go snapshot 还观测到预置标记。Bash 菜单/跟随与双方 follow 按预期由 20 秒观察超时结束（rc=124），Go snapshot rc=0。真实 Docker 证据：`ops-log-follow-final2-8ff26917-20261128/p2/OPS-12, OPS-13`；旧失败与修正历程均纳入账本和证据索引。
- **OPS-14 FAIL**：Bash 提供交互式实时 iftop 观察；Go 是有界统计查询。功能/操作模型不同，尚无经证明且符合既有契约的优越性结论。
- **OPS-16 FAIL**：Bash 证书状态/有效期交互菜单与 Go `cert renew --dry-run` 前置检查并非同一行为，不能由 dry-run 代替状态查看。
- **OPS-27 FAIL**：Go 只删除可证明属于项目且未使用的证书，保留第三方文件；Bash 在确认后递归删除整个目录。该 Go 安全边界更窄，但产品契约差异仍须明确记录；你在本轮明确了 Go 可有不同方案但须优于 Bash；现有 OPS-27 canary 真实对照证明 Go 避免删除第三方证书，安全性优于 Bash 的递归删除。正式 ledger 仍保留 FAIL，因为验收器未获当前证据绑定的外部批准记录；不伪造审批文件。
- **OPS-30 BASH_ONLY**：按账本保留，不扩张语言功能以追求分类全绿。
- **OPS-23 DUAL_SIDE_VERIFIED**：冻结候选 `8ff26917` 的 Bash 管理菜单经实际 `/usr/bin/idleleo` Go 入口调用 Cloudflare speedtest，Bash/Go 命令均 rc=0，各完成两次 10 MB 下载（各计 20,000,000 bytes）；Bash 首个样本 12.82 Mbps，Go 平均 14.22 Mbps（13.16、15.28）。Xray/Nginx 容器服务均 active。前两次诊断重跑暴露菜单驱动时序、迁移入口及外部下载超时问题，失败均保留且排除出汇总；第三次修正后通过。完整运行、构建清单及菜单 transcript：`ops23-dual-speedtest-retry3-8ff26917-20261127/p2/OPS-23/`。
- **OPS-17a/18 BLOCKED；OPS-24 已升级为双端通过**：OPS-17a 当前候选 Go 侧本地签名清单/资产检查成功且 `update check` 前后安装二进制 SHA 与版本相同；另将服务端资产故意损坏，`update apply` rc=1 并以 size mismatch 拒绝，原二进制/版本不变，Xray/Nginx 保持 active，`nginx -t` 与 `xray -test` 均 rc=0；无自动更新 timer/cron。成功 apply 后的真实 Reality L4 证据也已保留。Bash 侧新增一次真实 Docker/Expect PTY 菜单运行：脚本更新入口明确报告 `当前已经是最新版本`，安装脚本 SHA 前后相同，Xray/Nginx 均 active，更新后的真实 Reality 客户端 rc=0（`ops17a-pty-8ff-20261128-02`）。这修正了旧 stdin pipe 探针的 `rc=124`：它在 Bash 回到菜单后因 EOF 重复循环，是 harness 问题；首次 PTY 复跑又因新探针少传 L4 round 参数而中断，保留为诊断 run `ops17a-pty-8ff-20261128-01`。新 Bash 证据只覆盖“当前已最新”的无替换分支，没有实际 Bash 包替换；因此正式 OPS-17a 继续 BLOCKED，不能将无操作误记为更新成功。OPS-18 需真实宿主 BBR 环境，本轮禁止操作生产 VPS。

## 真实候选验证

### 当前候选运行

- **OPS-24 GeoData 刷新**：当前候选真实运行 Bash 菜单刷新与 Go `schedule install/run --job geodata-refresh`，两侧均使用固定 release `202611262204`；`geoip.dat` SHA-256 `9dc8e7de8db8300ce27b606f4a30632265713d2f33bcc568c0d2c44c825c8687`、`geosite.dat` SHA-256 `3f0a3587c23ad94855c839bf5429ffbd7aba752d14757f2ebc340cb262395624` 完全一致，Xray 均 active。旧交互序列曾停在子菜单且 Go JSON 初始解析器读错层级；原记录保留，独立 verifier 正反例通过。证据 `ops-observe-geodata-real3-8ff26917-20261127/p2/OPS-24/verification.json`。
- **OPS 矩阵**：当前严格账本候选为 8ff26917。OPS-20 中 Bash 与 Go Xray Reality 客户端分别经服务访问本地 Nginx origin 的 1 MiB 对象，HTTP 返回码、body 长度及 SHA-256 均核对；统计读取真实业务前后增量。OPS-25/26 在 8ff26917 上双端真实备份、校验、破坏后恢复，并核对数据/配置/canary 摘要、文件权限、服务和 Reality 客户端连接；证据 `ops-observe-restorefix-8ff26917-20261127`。
- **安装矩阵 M1–M10**：Bash/Go 各两轮，适用传输均有真实客户端 L4；安装 rc 均为 0，含 Pebble ACME 与 Relay。记录：`evidence/matrix-current-7d3e19d9.log`。
- **98 项配置对照**：干净 clone 的当前代码 SHA 和 `repo_dirty=0` 已核对；54 MATCH、40 MATCH_CORE_FIELDS、4 REFUSED、6 A1_PASS、0 GAP。固定 Debian apt 包索引下载发生真实网络 reset，随后按矩阵文档使用缓存依赖镜像成功完成；两次运行和环境诊断均保留。
- **P3 四传输**：raw、ws、gRPC、xHTTP 各自真实 Docker Go 运行；每个 driver 为 62 assertions / 0 failures。它们是 Go 单侧证据，不扩写成 Bash parity。
- **冷恢复对照**：Go Reality/TLS/Relay/Multi 在冻结候选 `8ff26917` 上均通过源端备份、全新目标恢复、服务/配置验证与真实客户端请求；新增第三方 canary 的内容、mode、owner 前后核对也在四场景通过。Bash Reality 全新目标冷恢复完整通过。Bash Relay/Multi 的归档内容恢复、服务验证和恢复后真实客户端均通过，但严格权限对照发现 Bash 将第三方证书/私钥从源端 `0644/0600 root:root` 改为目标 `0640 root:xray`；运行 `bashcoldrestore-bc12-8ff-1128` 与 `bc13` 逐项留下差异。Go 恢复不改变目标第三方 canary 内容或权限/属主，行为更保守。该差异不改写 OPS-25/26 原生账本 PASS_DUAL，也不掩盖 Bash 冷恢复权限差异。先前 M4 TLS/WebSocket 冷恢复仍有非致命 `harden_config_permissions` 警告，保留待诊断。
- **R1/R2 迁移**：当前候选在 M1 Reality 与 M4 TLS 场景中执行两轮 R1 和 R2 takeover/bridge，另执行 install fault injection；共 106 个断言通过。核对了恢复/迁移状态、证书、配置、权限、服务与迁移前后的真实客户端 L4。旧 Bash v3.3.2 与 v3.3.3 标签作为历史源的 M1/M4 R1/R2 与故障注入均各 106 PASS / 0 FAIL；确认容器运行历史安装器并绑定来源 commit/SHA。
- **平台覆盖**：Debian 12 的 M1/M4 两轮安装、Bash/Go 和每轮 Reality/TLS L4 均通过。另在当前 ARM 宿主上以 Docker `linux/amd64` 镜像实际启动容器，容器 `uname -m=x86_64`，AMD64 Xray ELF 与 Go 二进制运行，M1/M4 双端两轮 L4 通过；这是 Docker 架构模拟，不是原生 AMD64 硬件证据。首次尝试因 GitHub 最新 Release 资产下载中断失败，固定官方 v26.11.9 URL 下载并核对 ELF 后重跑通过，失败/成功均留档。
- **Xray 多版本**：当前生成的 Reality 配置在 ARM64 Docker 中由 Xray 26.11.9、26.10.31、26.10.21 三个真实发行版逐一校验；每个版本实际安装并经独立 Xray 客户端完成业务请求，均 PASS。ZIP SHA、镜像和驱动摘要在版本运行清单中。
- **S4–S9 脚本**：当前候选上真实执行 64 项断言全部通过，覆盖 Shell/Xray 更新检查、GeoData 更新和坏包/截断包拒绝、Pebble ACME 成功续期/重复续期/不可达 CA 回滚，以及 S7/S8/S9 legacy/download fail-closed 与替代 CLI。首次运行 63/1 的唯一失败是断言期望过时；修正为核对已安装 Xray 新于 pin 时拒绝降级后，完整重跑 64/0。原始两轮均留档。
- **OPS-17a 补证**：当前 Go 二进制在一次性容器对本地签名包执行 check/apply；检查不改变二进制，应用后摘要符合目标，Xray/Nginx 健康且 Reality L4 成功。另用签名资产损坏测试确认 `apply` 拒绝并保留现有版本/摘要。Bash 侧已通过 PTY 实际执行更新菜单并完成真实客户端复核；公开源显示当前已最新，所以没有包替换。旧 `rc=124` 被证实为 pipe/EOF 驱动问题，但真实 Bash 更新替换仍不可用作本地验证。两端证据都不改变 OPS-17a 正式 BLOCKED。
- **OPS-03 边界**：基础双端用户添加/删除在正式矩阵通过；独立探针另覆盖共享 shortId、旧凭据撤销及重启边界，但来自 `23fa585f` 运行，需按 `internal/xraycfg` 未变化的影响分析引用，不能篡改为 7d3 当前运行。Go 显式 shortId 清理与 Bash 自动清理的流程差异另行披露。
- **Guard**：当前候选完整 CLI + 真实 Nginx 已核验 reload 状态、异步 reload 超时/回滚、master 重启、SNI，以及同一数字 PID 配上不同 startTicks 时退回 `runtime-unverified`；把 PID 文件指向真实存活的非 Nginx 进程也被拒绝，恢复原始记录/PID 后重新报告 active。run `guard-pid-identity-8ff26917-20261127` 的 PID 复用边界通过受控身份不匹配模拟，未声称操作系统实际回收并复用了该 PID。此前真实 Nginx 的旧 mtime/SNI 异步场景仍依据 Guard 源码未变的影响分析复用。
- **证书清理**：真实 CLI 覆盖动态 `${cert_name}` HTTPS/ACME、项目所有权和第三方/嵌套用户数据保留，并对事务失败/中断进行回滚验证；摘要、mode、journal、staging 均核对。Go 更保守地保护第三方文件，但 OPS-27 仍按 FAIL。

### 稳定性 soak 状态

首轮 `soak-current-7d3e19d9-20261127` 在第 26 个一分钟样本真实失败：客户端 Reality curl 超时，rc=28、0 bytes。此前服务状态、Xray 配置校验、443 listener、进程重启数和真实 L4 样本均有记录。该失败未被隐藏。

为保留失败现场并采集 curl stderr、客户端 Xray 日志、服务端 journald/socket 诊断，已改进 `tests/e2e-diff/run_soak.sh` 并完成第二轮 `soak-diag-current-7d3e19d9-20261127`：31/31 次真实采样、1863 秒、31 个客户端成功且 0 失败，Xray 校验、监听、RSS 和零重启检查通过；真实 schedule timer active，state 记录 runs=2 且 GeoData 文件完整。结果 `PASS`，证据含逐样本表、schedule state/journal、容器构建清单和 run manifest。首轮失败发生在旧 runner 尚未保留诊断日志时，原因未能追溯；二轮通过不覆盖该失败，也不把猜测写成根因。

## 验收器、隐私与本地检查

- ledger、sanitizer 与 OPS-24 verifier 共 40 个契约测试通过；新测试确认 `matrix.json` 同时保留 BLOCKED 数量和 `blockedIds`；覆盖错误/缺失 provenance、路径穿越、非零实际 rc/冲突输出及失败替代等负例。验收器修复和新增测试在 `tests/e2e-diff/collect/`。该复验发现 matrix 汇总以前仅写 `blockedOps` 数量而遗漏 `blockedIds`；已修构建器、加入回归测试并重建正式三份 OPS 摘要。
- sanitizer 改为输出相对证据路径，并有回归测试；原始实测日志仍保留并通过脱敏映射追溯。
- 正式摘要重新绑定当前候选，并严格运行返回 rc=1，正确保留 FAIL/BLOCKED/BASH_ONLY。不能把严格失败解释成测试通过。
- 验收器新增机器校验的历史证据影响复用：Git 祖先关系、提交 diff 文件列表及 SHA-256、全部 34 OPS 的受影响/可复用分区；受影响的 OPS-25/26 必须具备当前 SHA 的真实通过证据。新增的 fixture 修复 supersession 仅允许提交祖先中只修改 `run_p2_matrix.sh` 的固定修复、明确列出每条替代 run，并校验候选 SHA、构建产物摘要和时间顺序。OPS-12/13 当前严格结果为 DUAL；strict run 为 28 DUAL、3 FAIL、1 BASH_ONLY、2 BLOCKED、0 NOT_RUN，rc=1。
- 当前候选的 Bash cold restore 首次真实失败：新目标缺 `/var/log/xray`，使 restore 内的 Xray 配置测试失败并触发回滚。`8ff26917` 在真实配置校验前调用既有 unit-aware 初始化；修复后重新创建全新目标，Bash restore rc=0，Xray/Nginx active 且 validator 通过，源/目标 Xray 配置、证书、私钥、Xray/Nginx 二进制 SHA 一致，权限一致；TLS/WebSocket 实际客户端取得 HTTP 200 对应的 577 字节响应。首次失败及成功证据分别留档。
- 七项远程 CI：`CI_PENDING`。当前开发分支未推送；本地检查不代替远程 CI。未进行 push、merge、tag、正式发布或生产 VPS 操作。
- 候选 Go 1.27.4 linux/arm64 容器已运行 `go test ./...`、`go test -race ./...`、`go vet ./...`、`go build -buildvcs=false -trimpath ./cmd/idleleo` 均通过；最终构建 SHA-256 `f0e96beaa71b3dae9e9a691b75abeb6dd09da0556e36eaa7f240040ecf424eac`。本轮最终本地门禁中 Bash `-n`、Expect/Tcl `info complete`、源代码/报告 scoped `git diff --check`、40 个采集器契约测试、正式工件隔离门禁均 rc=0；证据索引更新后本轮最终隐私扫描覆盖 75,366 个文件、0 finding，日志为 `privacy-scan-coldrestore-final-20261128.log`；初扫唯一候选值是证书文本序列号误报，已只遮蔽派生文本并保留原始 PEM，初扫和映射均留档。完整 staged `git diff --check` 因原始证据终端/快照/依赖文件的尾随空格曾返回 rc=2，原始日志未被改写；详见 `staged-evidence-whitespace-20261127.log`。严格账本 rc=1，保留当前 3 FAIL/2 BLOCKED/1 BASH_ONLY。首次本地复扫发现 6 项隐私问题，已逐值脱敏并记录 `privacy-redaction-map-20261127.json`；最终日志为 `final-local-gates-20261127.log`，首轮诊断日志保留为 `final-local-gates-diagnostic-first-20261127.log`。

## 未完成事项与最终阻断

1. **严格 OPS-34 仍 NO_GO**：OPS-14、OPS-16、OPS-27 为 FAIL；OPS-30 为 BASH_ONLY；OPS-17a、OPS-18 为 BLOCKED。Go 可以采用不同设计，但当前证据没有证明 OPS-14/16 的行为差异满足“优于 Bash”的条件。OPS-27 的第三方文件保护有明确安全优势和故障注入证据，仍需契约所有者确认如何将此差异纳入正式验收，执行者不自行改写验收口径。
2. **当前候选远程 CI 未完成**：七项 CI 状态仍为 `CI_PENDING`，触发需要将当前提交推送到远端；本轮没有推送。
3. **BLOCKED 行需要真实补证或保留阻断**：OPS-17a 现有 Go 侧通过真实签名包成功/失败边界和成功后的客户端 L4；Bash 侧 PTY 实测“已最新”无替换分支与更新后 L4 通过，旧 pipe `rc=124` 归因于 harness EOF 循环。真实 Bash 包替换尚未发生，正式行因此仍 BLOCKED。OPS-18 需真实宿主 BBR 环境。OPS-23 已双端真实通过。Guard 的 PID/startTicks 身份不匹配及假 PID现已用真实 CLI 和 Nginx 验证；该探针受控模拟 stale identity，没有声称内核实际复用 PID。
4. **冷恢复的 Bash 权限差异仍需正式处理**：Go Reality/TLS/Relay/Multi 四类都通过，且目标第三方 canary 保持原有字节、mode 与 owner。Bash Reality 冷恢复通过；Relay/Multi 的数据、服务和真实客户端通过，但 Bash 将归档中的第三方证书/私钥权限与属主调整为 `0640 root:xray`。这体现 Go 更窄的文件所有权边界，但没有据此改写正式 OPS 分类。先前 M4 restore 的 `harden_config_permissions` 警告也仍待进一步诊断。
5. **失败现场仍有未解释项**：soak 第二轮 31/31 次、1863 秒与两个调度周期通过；首轮第 26 样本超时未留足现场，根因无法确定。该历史失败保留，不能由第二轮结果覆盖。
6. **交付未闭环**：产品修复已提交 `8ff26917`；当前审计账本、报告和证据仍待提交本地开发分支。审计提交不改变产品候选 SHA；本轮未推送、未合并、未打 tag/正式发布、未操作生产 VPS。

平台证据已完成候选范围：Debian 12 M1/M4 双端真实 L4 两轮通过；amd64 M1/M4 在 linux/amd64 Docker 模拟环境通过，但 Docker 宿主为 ARM64，因此不声称原生 amd64 硬件验证。98 项配置对照、P3/版本迁移与 soak 的已完成范围见上文和证据索引，不再列作待跑事项。

## 最终判断

本候选在多项关键业务路径上有真实运行证据，但仍存在正式 FAIL、BLOCKED、BASH_ONLY 与 CI_PENDING。**当前结论为 NO_GO，而非“基本通过”或“仅剩文档”。**只有按既有契约解决或正式裁决差异、满足强制补证并对最终候选运行远程 CI 和严格验收后，才能重新评估 Docker 开发候选资格。发布授权始终为 **NO**。
