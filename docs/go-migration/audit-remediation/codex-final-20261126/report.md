# Xray Go 重构定向收尾与最终验收报告

日期：2026-11-27（Asia/Shanghai）
工作分支：`work/go-hardening-parity-20261119`
当前产品候选：`8ff26917e3e381d4023b7319d5405f7ba871f289`
Go CLI SHA-256：`c7fd0055b157fc8c7e848f1edb640161ba245a4373e3a5b0b57b36dbc18e237d`
Docker 平台：`linux/arm64`

## 验收结论

**DOCKER_DEVELOPMENT_QUALIFICATION = NO_GO**  
**RELEASE_AUTHORIZED = NO**

当前候选已获得较广的真实 Bash/Go、Docker、Xray、Nginx、配置对照、热更新、冷恢复和客户端 L4 证据，但严格 OPS-34 验收器仍返回非零：26 DUAL、3 FAIL、1 BASH_ONLY、4 BLOCKED、0 NOT_RUN。候选尚不具备 Docker 开发候选签收资格。七项当前 SHA 远程 CI 未触发，状态为 `CI_PENDING`。本报告不把未运行、单侧证据或未经批准的产品差异转换成 PASS。

## 当前正式 OPS-34 分类

| 状态 | 数量 | OPS |
|---|---:|---|
| DUAL_SIDE_VERIFIED | 26 | 01、02、03、04、05、06、07、08、09、10、11、12、13、15、17b、17c、19、20、21、22、25、26、28、29、31、32 |
| FAIL | 3 | 14、16、27 |
| BASH_ONLY | 1 | 30 |
| BLOCKED | 4 | 17a、18、23、24 |
| GO_ONLY / NOT_RUN / APPROVED_DIFF / APPROVED_SINGLE_SIDE | 0 | — |

当前 OPS-34 摘要在 `tests/e2e-diff/ledger.json`、`tests/e2e-diff/matrix.json` 的 `acceptance` 节点和 `docs/go-evolution/hardening/acceptance.json` 的 `ops` 节点中绑定候选 SHA `8ff26917…`；`acceptance.json` 顶层的历史基线字段仍保留原 SHA，未将历史验收改写成当前候选。`8ff26917` 相对上一产品候选仅修改 Bash restore 初始化 Xray 日志目录，OPS-25/26 已在此 SHA 双端重跑；其余复用行逐项保留旧 provenance，并附经 Git commit/diff 摘要核验的影响映射，不把旧 run 改标成新 SHA。三份当前 OPS 分类与严格模式一致，含 BLOCKED ID 列表；严格模式本轮 rc=1，准确保留 OPS-14/16/27 FAIL。详细失败原因及逐行证据以 ledger 原文为准；证据索引见本目录 `evidence-index.json`。

- **OPS-14 FAIL**：Bash 提供交互式实时 iftop 观察；Go 是有界统计查询。功能/操作模型不同，尚无经证明且符合既有契约的优越性结论。
- **OPS-16 FAIL**：Bash 证书状态/有效期交互菜单与 Go `cert renew --dry-run` 前置检查并非同一行为，不能由 dry-run 代替状态查看。
- **OPS-27 FAIL**：Go 只删除可证明属于项目且未使用的证书，保留第三方文件；Bash 在确认后递归删除整个目录。该 Go 安全边界更窄，但产品契约差异仍须明确记录；本报告不代替授权方批准既有行为差异。
- **OPS-30 BASH_ONLY**：按账本保留，不扩张语言功能以追求分类全绿。
- **OPS-17a/18/23/24 BLOCKED**：OPS-17a 虽已有 Go 手动签名更新和升级后真实 L4 补充证据，正式行仍没有满足双端契约；其余分别按正式账本中的环境/范围限制记载。

## 真实候选验证

### 当前候选运行

- **OPS 矩阵**：当前严格账本候选为 8ff26917。OPS-20 中 Bash 与 Go Xray Reality 客户端分别经服务访问本地 Nginx origin 的 1 MiB 对象，HTTP 返回码、body 长度及 SHA-256 均核对；统计读取真实业务前后增量。OPS-25/26 在 8ff26917 上双端真实备份、校验、破坏后恢复，并核对数据/配置/canary 摘要、文件权限、服务和 Reality 客户端连接；证据 `ops-observe-restorefix-8ff26917-20261127`。
- **安装矩阵 M1–M10**：Bash/Go 各两轮，适用传输均有真实客户端 L4；安装 rc 均为 0，含 Pebble ACME 与 Relay。记录：`evidence/matrix-current-7d3e19d9.log`。
- **98 项配置对照**：干净 clone 的当前代码 SHA 和 `repo_dirty=0` 已核对；54 MATCH、40 MATCH_CORE_FIELDS、4 REFUSED、6 A1_PASS、0 GAP。固定 Debian apt 包索引下载发生真实网络 reset，随后按矩阵文档使用缓存依赖镜像成功完成；两次运行和环境诊断均保留。
- **P3 四传输**：raw、ws、gRPC、xHTTP 各自真实 Docker Go 运行；每个 driver 为 62 assertions / 0 failures。它们是 Go 单侧证据，不扩写成 Bash parity。
- **四类 Go 冷恢复**：Reality、TLS、Relay、Multi 的源/目标 driver 均成功；验证归档 mode 0600、verify、状态字节、属主/权限、服务及恢复前后/重启后真实客户端。Bash 全新目标 M4 TLS/WebSocket 也已在 8ff26917 真实恢复并通过服务、配置、权限和客户端验证；restore 仍输出一条非致命 `harden_config_permissions` 未完全成功警告，具体子步骤未被旧日志捕获。逐项文件权限/SHA、Xray/Nginx validators、active 服务及真实 L4 均通过，但该警告保留为待诊断限制。Bash Reality、Relay、Multi 全新目标恢复仍未覆盖。
- **R1/R2 迁移**：当前候选在 M1 Reality 与 M4 TLS 场景中执行两轮 R1 和 R2 takeover/bridge，另执行 install fault injection；共 106 个断言通过。核对了恢复/迁移状态、证书、配置、权限、服务与迁移前后的真实客户端 L4。旧 Bash v3.3.2 与 v3.3.3 标签作为历史源的 M1/M4 R1/R2 与故障注入均各 106 PASS / 0 FAIL；确认容器运行历史安装器并绑定来源 commit/SHA。
- **平台覆盖**：Debian 12 的 M1/M4 两轮安装、Bash/Go 和每轮 Reality/TLS L4 均通过。另在当前 ARM 宿主上以 Docker `linux/amd64` 镜像实际启动容器，容器 `uname -m=x86_64`，AMD64 Xray ELF 与 Go 二进制运行，M1/M4 双端两轮 L4 通过；这是 Docker 架构模拟，不是原生 AMD64 硬件证据。首次尝试因 GitHub 最新 Release 资产下载中断失败，固定官方 v26.11.9 URL 下载并核对 ELF 后重跑通过，失败/成功均留档。
- **Xray 多版本**：当前生成的 Reality 配置在 ARM64 Docker 中由 Xray 26.11.9、26.10.31、26.10.21 三个真实发行版逐一校验；每个版本实际安装并经独立 Xray 客户端完成业务请求，均 PASS。ZIP SHA、镜像和驱动摘要在版本运行清单中。
- **S4–S9 脚本**：当前候选上真实执行 64 项断言全部通过，覆盖 Shell/Xray 更新检查、GeoData 更新和坏包/截断包拒绝、Pebble ACME 成功续期/重复续期/不可达 CA 回滚，以及 S7/S8/S9 legacy/download fail-closed 与替代 CLI。首次运行 63/1 的唯一失败是断言期望过时；修正为核对已安装 Xray 新于 pin 时拒绝降级后，完整重跑 64/0。原始两轮均留档。
- **OPS-17a 补证**：当前 Go 二进制在一次性容器对本地签名包执行 check/apply；检查不改变二进制，应用后摘要符合目标，Xray/Nginx 健康且 Reality L4 成功。该 Go 单侧补证不能解除正式 OPS-17a BLOCKED。
- **OPS-03 边界**：基础双端用户添加/删除在正式矩阵通过；独立探针另覆盖共享 shortId、旧凭据撤销及重启边界，但来自 `23fa585f` 运行，需按 `internal/xraycfg` 未变化的影响分析引用，不能篡改为 7d3 当前运行。Go 显式 shortId 清理与 Bash 自动清理的流程差异另行披露。
- **Guard**：真实 Nginx 下覆盖保留旧 mtime 的配置编辑、reload 前 `runtime-unverified`、成功 reload 后 active、异步 reload 超时和回滚、master 重启后重新验证及 SNI 行为。证据来自 `23fa585f` 后续 Guard 代码与当前 Guard 源码无差异的运行，按文件影响分析复用。没有实际强制数字 PID 复用的证据，不声称该边界已覆盖。
- **证书清理**：真实 CLI 覆盖动态 `${cert_name}` HTTPS/ACME、项目所有权和第三方/嵌套用户数据保留，并对事务失败/中断进行回滚验证；摘要、mode、journal、staging 均核对。Go 更保守地保护第三方文件，但 OPS-27 仍按 FAIL。

### 稳定性 soak 状态

首轮 `soak-current-7d3e19d9-20261127` 在第 26 个一分钟样本真实失败：客户端 Reality curl 超时，rc=28、0 bytes。此前服务状态、Xray 配置校验、443 listener、进程重启数和真实 L4 样本均有记录。该失败未被隐藏。

为保留失败现场并采集 curl stderr、客户端 Xray 日志、服务端 journald/socket 诊断，已改进 `tests/e2e-diff/run_soak.sh` 并完成第二轮 `soak-diag-current-7d3e19d9-20261127`：31/31 次真实采样、1863 秒、31 个客户端成功且 0 失败，Xray 校验、监听、RSS 和零重启检查通过；真实 schedule timer active，state 记录 runs=2 且 GeoData 文件完整。结果 `PASS`，证据含逐样本表、schedule state/journal、容器构建清单和 run manifest。首轮失败发生在旧 runner 尚未保留诊断日志时，原因未能追溯；二轮通过不覆盖该失败，也不把猜测写成根因。

## 验收器、隐私与本地检查

- ledger 构建器和 sanitizer 共 35 个契约测试通过；新测试确认 `matrix.json` 同时保留 BLOCKED 数量和 `blockedIds`；覆盖错误/缺失 provenance、路径穿越、非零实际 rc/冲突输出及失败替代等负例。验收器修复和新增测试在 `tests/e2e-diff/collect/`。该复验发现 matrix 汇总以前仅写 `blockedOps` 数量而遗漏 `blockedIds`；已修构建器、加入回归测试并重建正式三份 OPS 摘要。
- sanitizer 改为输出相对证据路径，并有回归测试；原始实测日志仍保留并通过脱敏映射追溯。
- 正式摘要重新绑定当前候选，并严格运行返回 rc=1，正确保留 FAIL/BLOCKED/BASH_ONLY。不能把严格失败解释成测试通过。
- 验收器新增机器校验的历史证据影响复用：Git 祖先关系、提交 diff 文件列表及 SHA-256、全部 34 OPS 的受影响/可复用分区；受影响的 OPS-25/26 必须具备当前 SHA 的真实通过证据。当前 strict run 为 26 DUAL、3 FAIL、1 BASH_ONLY、4 BLOCKED、0 NOT_RUN，rc=1。
- 当前候选的 Bash cold restore 首次真实失败：新目标缺 `/var/log/xray`，使 restore 内的 Xray 配置测试失败并触发回滚。`8ff26917` 在真实配置校验前调用既有 unit-aware 初始化；修复后重新创建全新目标，Bash restore rc=0，Xray/Nginx active 且 validator 通过，源/目标 Xray 配置、证书、私钥、Xray/Nginx 二进制 SHA 一致，权限一致；TLS/WebSocket 实际客户端取得 HTTP 200 对应的 577 字节响应。首次失败及成功证据分别留档。
- 七项远程 CI：`CI_PENDING`。当前开发分支未推送；本地检查不代替远程 CI。未进行 push、merge、tag、正式发布或生产 VPS 操作。
- 候选 Go 1.27.4 linux/arm64 容器已运行 `go test ./...`、`go test -race ./...`、`go vet ./...`、`go build -buildvcs=false -trimpath ./cmd/idleleo` 均通过；最终构建 SHA-256 `f0e96beaa71b3dae9e9a691b75abeb6dd09da0556e36eaa7f240040ecf424eac`。`bash -n`、`git diff --check`、36 个 ledger/sanitizer 测试与正式工件隔离门禁通过。最终 privacy/hygiene 扫描 72,768 个文本文件，0 finding。

## 未完成事项与最终阻断

1. **严格 OPS-34 仍 NO_GO**：OPS-14、OPS-16、OPS-27 为 FAIL；OPS-30 为 BASH_ONLY；OPS-17a、OPS-18、OPS-23、OPS-24 为 BLOCKED。Go 可以采用不同设计，但当前证据没有证明 OPS-14/16 的行为差异满足“优于 Bash”的条件。OPS-27 的第三方文件保护有明确安全优势和故障注入证据，仍需契约所有者确认如何将此差异纳入正式验收，执行者不自行改写验收口径。
2. **当前候选远程 CI 未完成**：七项 CI 状态仍为 `CI_PENDING`，触发需要将当前提交推送到远端；本轮没有推送。
3. **BLOCKED 行需要真实补证或保留阻断**：OPS-17a 已有 Go 侧签名更新、应用后健康与真实 L4 补证，但正式行仍缺双端契约证据；OPS-18/23/24 按正式账本中的范围/环境限制维持 BLOCKED。Guard 已覆盖异步 reload、失败回滚和 master 重启，但没有真实数值 PID 复用探针，因此不声称该边界通过。
4. **Bash 全新目标冷恢复范围仍窄于 Go**：Go Reality/TLS/Relay/Multi 四类通过；Bash 当前只完成 TLS/WebSocket M4。该 Bash 恢复的配置、证书、权限、服务与真实客户端 L4 已核验，但恢复输出仍有非致命 `harden_config_permissions` 警告，具体子步骤未捕获。
5. **失败现场仍有未解释项**：soak 第二轮 31/31 次、1863 秒与两个调度周期通过；首轮第 26 样本超时未留足现场，根因无法确定。该历史失败保留，不能由第二轮结果覆盖。
6. **交付未闭环**：产品修复已提交 `8ff26917`；当前审计账本、报告和证据仍待提交本地开发分支。审计提交不改变产品候选 SHA；本轮未推送、未合并、未打 tag/正式发布、未操作生产 VPS。

平台证据已完成候选范围：Debian 12 M1/M4 双端真实 L4 两轮通过；amd64 M1/M4 在 linux/amd64 Docker 模拟环境通过，但 Docker 宿主为 ARM64，因此不声称原生 amd64 硬件验证。98 项配置对照、P3/版本迁移与 soak 的已完成范围见上文和证据索引，不再列作待跑事项。

## 最终判断

本候选在多项关键业务路径上有真实运行证据，但仍存在正式 FAIL、BLOCKED、BASH_ONLY 与 CI_PENDING。**当前结论为 NO_GO，而非“基本通过”或“仅剩文档”。**只有按既有契约解决或正式裁决差异、满足强制补证并对最终候选运行远程 CI 和严格验收后，才能重新评估 Docker 开发候选资格。发布授权始终为 **NO**。
