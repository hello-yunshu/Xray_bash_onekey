# Goal：Xray Go 重构——独立双端验收与最终收敛

你是执行者。以独立审计报告 `Xray_独立审计报告_20261121.md` 为输入。目标是用真实 Bash/Go 两端运行证据关闭遗留问题，而不是增加功能或文档。分支 `work/go-hardening-parity-20261119`，当前审计 HEAD `c0f382f2bbc805556b0dd72b4a800af51de2312c`；固定 Bash v3.3.6 `0fa7052e`。保持 Go 唯一核心，受控独立 Shell 辅助；CLI 优先，轻量安全稳定，不恢复 XTLS ONLY，不做多软件平台。禁止合并、tag、release、操作生产 VPS；只用隔离容器/VM。

## S0 冻结与证据校准

1. git fetch；记录实际 HEAD、branch、dirty、Go 版本、Docker/架构/发行版/systemd、Xray 与 Nginx 版本/哈希、固定 Bash pin 全 SHA、镜像 digest、构建哈希。若继续有 push，冻结新版本并记录差异。源码树干净，构建 go.mod 要求工具链，用 vendored offline 构建；不降 Go 版本，不改依赖规避。
2. 复核上一轮任务书及当前审计报告全部项目；用实际 `tests/e2e-diff/matrix.json` 和 CLI/menu 清单派生账本。当前 `matrix.json` 仍 5/34，acceptance.json 11/34，统一由真实结果生成。历史文件保留，不修改过去日志的 SHA 或状态。所有结果含 commit、binary digest、命令、exit、预期、实际、证据链接、两端 rc、适用层、状态。
3. 每条命令真实运行、录退出码、留失败原始证据并脱敏；fixture、secret 不入库。禁止 mock 服务冒充真实 Xray/Nginx/systemd/Pebble。禁止 runner 用 Go 执行 Bash 对照却称独立两端。对未执行、环境阻断、Go-only、Bash-only、预期安全差异分别记 NOT_RUN/BLOCKED/GO_ONLY/BASH_ONLY/INTENTIONAL_SAFETY_DELTA。分母不缩水。

## S1 安全回归红绿（必须先做）

### A. P0 cert clear

- 独立报告仅证实行首正则漏扫和真实 Nginx 缺证书失败；现在构造真实 root 容器，在原 HEAD 执行完整 CLI dry-run/clear 验证，明确是否计划/实际误删，保留红测。仅用临时证书与第三方 canary，禁止生产操作。
- 覆盖一行多个指令、引号/空格、include 外部目录和非 .conf 后缀、真实 Nginx 相对路径前缀、symlink alias、未能读取的配置、变量证书路径、第三方 Nginx/证书、Xray 多配置、任务引用。无法证明引用/归属时拒绝清理或保留不确定对象；禁止仅因文件名或目录标记而删除第三方数据。检查归属、目录边界、锁、TOCTOU、journal、异常中断、幂等和回滚。
- 实现最简可靠的引用分析与 fail-closed；真实 root 模式用正确 Nginx binary/prefix、有效配置及 Xray 配置验证，提交删除事务之前检查；失败恢复原文件与服务可用性。无须引入大型解析/通用框架。若不能可靠验证，保守拒绝。dry-run 零写且明确未知原因。回归常规未使用证书可删、在用证书不可删、第三方不可删。
- 真 Nginx `-t`、reload、客户端握手、Xray -test、数据面前后通过；注入失败/kill后恢复。不得为模仿 Bash 而保留不安全删除。记录安全差异并明确用户可见行为。

### B. P1 Guard

- 复现 `InspectSNIGuard` 缺 isolate fragment 仍 active、主配置读不到仍 active；先检查合法 legacy 内联配置避免误判。测试缺少包含、错误配置、已配置但未 reload、监听/实际策略不符、metadata drift。
- 区分磁盘 configured、运行 active、unknown/inconsistent，未验证不得报告实际生效。保持 read-only show，真实三策略与失败 rollback。

### C. 回归及其他上轮问题

- OPS-04 public-port 修复：旧端口释放、真实客户经新公网端口访问、share 链接端口正确、loopback后端不变、重复/失败回滚；TLS 与 Reality+Nginx。
- OPS-10：真实 nginx -t/reload + 新旧客户端结果，并校验其他片段没有误改。
- XHTTP: 普通/前导斜杠/尾斜杠/空白/空字符串/重复斜杠，CLI 参数与真实数据面；不自动重写既有路径，无故不改默认。
- F28/F08/F18 和 A1/A3 在最后候选 SHA 重跑，不复用影响面绿色；Reality dial host 与 SNI 分离，多 root 不污染，旧新链接可用。Test Install 历史静默退出用 timeout/exit trap/日志最小定位；无法复现记 PARTIAL，不宣称修复。

## S2 真正全覆盖 Bash 与 Go 双端

使用现有 `tests/e2e-diff` 驱动，不另建第二套框架。比较的是操作后的实际功能与安全契约，不要求文件字节等同。每个适用 case 两端独立 clean root/container，真实 Bash 菜单/参数和 Go CLI 启动真实 Xray/Nginx/systemd；统一输入和本地 origin/客户端，按 L0退出码 L1文件 L2结构 L3运行态 L4真实业务 L5日志 L6重复运行比较，未适用层说明理由。对于风险操作，仅在一次性容器执行。

- M1–M10：安装、第二轮幂等、真实握手和业务请求、系统服务重启；Reality直连/前端/多传输、TLS WS/gRPC/XHTTP、None、relay；每种适用模式遍历端口、UUID、路径、listen、域名、IPv4/IPv6、用户选择与拒绝输入、重复、异常；避免无意义组合爆炸，用等价类加风险交叉。M8 单独用固定 Bash acme.sh 和 Go 独立连接本地 Pebble 真实签发/续期/失败回滚，不通过 Go 代替 Bash；若原 Bash 不支持本地 CA，透明记录测试注入边界及 BLOCKED，不能称纯 Bash。
- OPS 34 行全账本：先补 16证书状态/续期、17b Nginx更新、23测速、24 GeoData；再补 18 个仅 Go（01/02/03/08/11/12/13/14/15/17a/18/20/22/25/26/27/28/29），回归既有双端 04/05/06/07/09/10/17c/19/21/31/32；30语言是 Bash-only，说明是否为已批准的取消功能，未取得用户批准不得隐式删除/签收。更新账本逐 ID 明确真实 Bash 菜单入口、Go 命令、实际点检、变更/失败/重复。Go-only 功能保留可验证的强化能力，Bash 无等价时清楚登记，不造映射。OPS-27 优先安全差异。
- S1–S9 子脚本：引用证据的必须关联精确同一 run/case；S6 用固定真实 GeoData release asset 及校验和/本地缓存跑正常下载更新、断网/截断/坏哈希/更新失败保持旧资产、真实 Xray 热更新效果。禁止替换假资产，禁止只查看更新时间。S7 纯 Bash ACME/S8 BBR 单独标边界，S9 本地可控测速端点真实吞吐，外部性能不做承诺。
- E1–E8：所有适用 Bash 菜单操作单独执行（含 UUID/端口/target/SNI/用户/shortId/私钥变更），Go 独有路径只证明其正确性；新旧客户端、旧凭据失效、保留用户和路由，失败/回滚。历史 98 项：54 MATCH+40 CORE+4 REFUSED 为旧统计，不硬编码；按实际重新生成，6 A1另计，逐项预期拒绝也要检查原因。

## S3 迁移、冷恢复、稳定性

- R1/R2/INJ：至少旧版代表 Bash 两个版本（真实历史源码安装，不伪造快照）；旧节点配置/证书/用户/系统任务 → bridge/接管 → Go 真实客户端 → 重复 → 回滚/non-destructive，禁止双管理器同时生效。若历史版本无法部署，记录具体错误和未完成范围。
- 冷恢复独立源/目标容器，销毁源，只用备份恢复 Reality/TLS/relay/multi 代表配置，校验文件、所有权、任务、客户端，故障注入、并发、SIGKILL、ENOSPC/EROFS/EACCES、lock、证书缺失、部分恢复与重启。P3 hot-user raw/ws/grpc/xhttp 全跑，旧凭据失效、热更新不重启证据及持久化。
- 多版本 xray：当前/两个受支持版本至少代表数据面部署+客户端；不把只有 xray -test 的结果升级成实机部署。Debian 12 + Ubuntu 主环境代表关键 M/OPS/迁移，不把 smoke 当全矩阵。arm64/amd64 如可用分别构建和执行。VM 掉电/重启、真实内核 BBR、公网 ACME/DNS-01/EAB/IPv6/NAT 保留明确 VPS_DEFERRED 或 BLOCKED，禁止生产 VPS。
- 稳定性：实际经过 >=1800 秒（单调时钟），独立客户端定期握手与业务请求而非只查看 systemctl/监听。至少两个真实调度周期，隔离测试允许缩短周期而不改生产默认；记录实际触发与更新结果，而不只检查 cron/timer 是否安装。RSS/重启/错误率/服务状态及恢复日志。

## S4 最终候选与三轮闭环

第1轮原 HEAD 红测；第2轮修复定向实跑；第3轮冻结最终干净 SHA 全量验收（无中途功能改动；有改动就重新冻结相关矩阵，最终统一关键项目）。运行 gofmt/vet/build/test/race、Bash syntax、privacy、release 和 preview 门禁。现有驱动入口：

```bash
E2E_RUN_ID=FINAL-M bash tests/e2e-diff/run_p2_matrix.sh
E2E_RUN_ID=FINAL-OPS bash tests/e2e-diff/run_ops_sweep.sh
E2E_RUN_ID=FINAL-S bash tests/e2e-diff/run_s_scripts.sh
E2E_RUN_ID=FINAL-R bash tests/e2e-diff/run_r1_upgrade.sh
E2E_RUN_ID=FINAL-COLD bash tests/e2e-diff/run_coldrestore.sh
E2E_RUN_ID=FINAL-SOAK bash tests/e2e-diff/run_soak.sh
E2E_RUN_ID=FINAL-VERSIONS bash tests/e2e-diff/run_xray_versions.sh
```

以上命令为已有入口，先核实脚本选择范围、参数和默认模式再用；需要补齐的驱动先写红测/实现，不能假设运行一次已覆盖全部，也不能用 go sweep 代替 OPS 双端。运行 P3 每传输及正式 matrix container，按项目现有方式。真实 CI 在本分支 draft PR 上运行并记录 HEAD/run ID/job status；禁止触发 release/deploy。最终签收生成单一机器账本 + 简洁中文报告，包含：

1. 当前 SHA/基线/环境/构建与实际执行命令。
2. 34 OPS、10 M、8 E、9 S、R/INJ/冷恢复/P3/版本/发行版/调度/soak 完整逐行结果，按实际计数而不重复计数。
3. 红绿证据、日志、未适用原因、明确批准/未批准差异、失败及待执行项。
4. 独立结论 `GO_FOR_DOCKER_QUALIFIED_CANDIDATE` 仅当所有适用必需项通过、P0/P1无未闭合安全阻断、关键证据同 SHA、所有非等价功能获明确处置；否则 `NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`。正式发布默认 `NO_GO_NOT_AUTHORIZED`，在独立 VPS 及授权前不改变。
5. 将历史状态和当前状态分开，更新 machine-readable matrix/acceptance/FINAL_AUDIT/进度，不伪造历史；push 本工作分支，禁止合并与发布。

执行原则：不为追求全绿修改测试预期、跳过红测、吞退出码或模拟外部依赖冒充真实运行。不增加 Web/平台功能；先处理可证明风险，再用最小测试补齐。阻断时如实列出具体命令、退出码、环境原因，继续可执行部分，不无限重试。
