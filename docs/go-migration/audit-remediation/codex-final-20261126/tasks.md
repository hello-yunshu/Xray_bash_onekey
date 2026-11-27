# 历史候选快照（9e495b38；由下方“当前候选更新”取代）

本段保留 2026-11-28 较早候选的审计原文，不代表当前账本状态。当前状态见文末“当前候选更新”。

# 本轮任务账本（2026-11-28 更新）

唯一主任务书：`Codex_Xray_Goal_定向收尾与最终验收_20261126.md`。工作分支 `work/go-hardening-parity-20261119`。当前产品源码候选 `9e495b38a5574f53e37bd11e4b3c8f196f76e25b`；Go CLI 测试矩阵二进制 SHA-256 `c7fd0055b157fc8c7e848f1edb640161ba245a4373e3a5b0b57b36dbc18e237d`；最终 Go 全量测试构建 SHA-256 `f0e96beaa71b3dae9e9a691b75abeb6dd09da0556e36eaa7f240040ecf424eac`；Docker `linux/arm64`。所有旧 run SHA 均保留原值，不混写。

| ID | 状态 | 当前证据 | 阻断 / 后续 |
|---|---|---|---|
| S0 基线与环境 | DONE | 初始检查日志；产品候选 `8ff26917e3e381d4023b7319d5405f7ba871f289` 已在工作分支；未回退审计基线；Docker 29.8.2、Go 1.27.4、Xray、Nginx、Expect 可用 | 已 fetch 远端分支；origin HEAD `7d690f71` 是本地当前提交的祖先，产品候选及审计提交均为本地后续；当前 SHA 七项 CI 未触发，未推送 |
| A1 隐私与 CI | LOCAL_PASS / CI_PENDING | sanitizer 输出相对证据路径；证据索引更新后的最终扫描 `privacy-scan-coldrestore-final-20261128.log` 覆盖 75,366 个文件、0 finding。首次扫描发现的 6 项（被排除 b49 诊断 run 的公网地址，以及本轮摘要旁路中的宿主绝对路径）逐值替换为文档保留 IP/相对资产名，映射记录 `privacy-redaction-map-20261127.json`；此前历史泄露的修复来源仍在原记录中 | 当前 SHA 七项远程 CI 未触发；分支未推送。Docker Debian apt 包索引问题及其离线矩阵成功补救均留档 |
| A2 Guard 状态 | TARGETED_PASS_WITH_CONTROLLED_PID_REUSE_SIMULATION | 旧 mtime、未 reload、真实 Nginx/SNI、异步 reload/失败回滚及 master 重启场景按当前 Guard 源码影响分析复用；当前候选新增 `tests/e2e-diff/evidence/guard-pid-identity-8ff26917-20261127/p2/OPS-08/go/pid-identity-verification.json`，真实 CLI + Nginx 核对相同数字 PID 的 stale startTicks、存活假 PID、恢复后 active | stale startTicks 是受控 PID 复用身份模拟，未实际强制内核回收并重用相同 PID；最终报告明确边界，不声称实机回收测试 |
| A3 证书清理 | TARGETED_PASS / DIFF | 动态 `${cert_name}` HTTPS/ACME 真实 CLI 证据 `cert-dynamic-https-bc409-20261127`；当前 Go CLI 事务中断/恢复与回滚 `certclear-fault-cli-7d3e19d9-20261127/`，前后摘要、mode、journal、staging 已核对；OPS-27 双端 canary 在当前候选复跑 | Go 保留第三方文件、Bash 递归删除是安全优势；不擅自把差异改为批准状态，OPS-27 保持 FAIL，等待可核验契约决策 |
| B1-B3 验收器与正式账本 | STRICT_NO_GO | 最新 40 个采集器契约测试通过；包含 exact `blockedIds`、错误/缺失 provenance、路径穿越、非零实际 rc/输出标记、失败替代与证据影响复用。`--reuse-impact` 校验祖先提交、改动文件列表/diff SHA、OPS 互斥分区，并禁止受影响 OPS 借用旧 SHA PASS。当前 SHA 严格账本 28 DUAL / 3 FAIL / 1 Bash-only / 2 BLOCKED / 0 NOT_RUN，rc=1；失败差异未绑定可核验授权，严格保留 FAIL | 有效 FAIL / BLOCKED / Bash-only 保留；最新 artifact guard 确认正式摘要测试前后字节一致 |
| C1 OPS-20 真实统计 | PASS_DUAL | `ops-core-7d3e19d9-20261127/p2/OPS-20`：Bash/Go Reality 客户端各自访问 1 MiB 本地 origin、校验 HTTP body 与 SHA，读取真实 inbound stats 基线/增量 | 统计含协议/API 开销，按真实业务流量变化判定 |
| C2 当前 OPS 矩阵 | 28 DUAL / 3 FAIL / 1 BASH_ONLY / 2 BLOCKED | 之前列出的矩阵运行，加 `ops-log-follow-contract-8ff26917-20261127`（错误初始 tail 断言，OPS-13 FAIL）、`ops-log-follow-current-8ff26917-20261127`（第一次修正验证）、`ops-log-follow-final2-8ff26917-20261128`（明确逐条替代当前有效失败并正式纳入）；误筛选无 OPS 的 `ops-log-follow-final-...` 也保留并标为未执行。strict ledger `strict-ledger-current-8ff-opslog-final-20261128.log` rc=1 | FAIL：OPS-14、16、27；Bash-only：OPS-30；BLOCKED：OPS-17a、18。OPS-12/13 已由冻结候选 Bash/Go 实际 Xray 日志双端 follow 与 Go snapshot 验证，当前为 DUAL。OPS-23 在冻结候选 Bash 菜单→Go 入口与 Go CLI 各自真实完成 20 MB Cloudflare 下载；OPS-24 真实刷新 DUAL。OPS-17a Go 侧签名更新成功/失败边界及成功后真实 L4 见 `ops17a-update-failure-retry2-8ff26917-20261127`；Bash 侧新 PTY run `ops17a-pty-8ff-20261128-02` 实际执行菜单、确认当前已最新、脚本 SHA 不变、服务 active 与更新后 Reality L4 rc=0。旧 pipe rc=124 是 harness EOF 循环；首次 PTY 诊断的参数缺失也保留。由于 Bash 没有实际包替换且公开源已是最新，不能证明两种更新实现的成功替换路径等价，正式行继续 BLOCKED |
| C2 OPS-25/26 原生备份恢复 | PASS_DUAL | 当前 SHA `ops-observe-restorefix-8ff26917-20261127/p2/OPS-25, OPS-26`：Bash tar 与 Go backup/restore 分别真实校验、故意改坏后恢复数据/配置/canary，权限、服务与真实 Reality L4 成功；另有 Bash 新目标 M4 TLS/WebSocket 及 Reality/Relay/Multi 冷恢复对照，详见 `bashcoldrestore-bc12-8ff-1128`、`goevo-coldrestore-go12-8ff-1128` | 冷恢复对照发现 Bash Relay/Multi 会将第三方证书/私钥改为 `0640 root:xray`，源端为 `0644/0600 root:root`；Go 对目标第三方 canary 的内容、mode、owner 均保持不变。该安全差异单独记录，不改写 OPS-25/26 正式分类 |
| C2 M1-M10 安装与 L4 | PASS_TARGETED | `matrix-current-7d3e19d9-20261127/p2/install-matrix.md`：10 场景，Bash/Go 两轮，安装 rc=0、各自传输 L4 两轮均 ok，含 Pebble ACME 和 relay | 本轮只覆盖安装矩阵；ED-C01…ED-C15 仍按原登记呈现，不扩大差异批准范围 |
| C2 98 项配置对照 | PASS_TARGETED | `tests/go-parity/evidence/matrix-current-clean-7d3e19d9-20261127/summary.json`：54 MATCH、40 MATCH_CORE_FIELDS、4 REFUSED、6 A1_PASS、0 GAP；`repo_dirty=0`，product commit 为 7d3e19d9 | 该矩阵是 Bash install metadata / Go generate/relay 对照，不是完整服务部署；原固定 Debian 镜像 APT 索引故障有独立日志，成功 run 使用离线工具镜像 |
| C2 P3 四传输热更新 | PASS_TARGETED | 当前候选 Reality raw/ws/gRPC/xHTTP 四个独立 Go Docker 运行，4 个 `p3-current-*-7d3e19d9.log`；均 install rc=0、driver 62 assertions 通过 | 单侧 Go P3，不替代双端 OPS 或功能差异授权 |
| C2 Xray 多版本部署 | PASS_TARGETED | `evidence/xray-versions-current-7d3e19d9.log` + `tests/e2e-diff/evidence/versions-current-7d3e19d9-20261127/versions/`：26.11.9、26.10.31、26.10.21 共用当前真实生成配置，均 xray -test、systemd 部署、真实客户端 L4 通过 | ARM64 Docker；不替代 Debian 12/amd64 平台验证 |
| C2 冷恢复 | GO_PASS_4_SCENARIOS / BASH_REALITY_PASS / BASH_RELAY_MULTI_PERMISSION_DIFF | Go Reality/TLS/Relay/Multi 当前候选均通过源备份、目标恢复、Xray/Nginx 验证、服务、真实客户端及第三方 canary 内容/mode/owner 不变断言（`goevo-coldrestore-go12-8ff-1128`）。Bash Reality 完整冷恢复通过；Relay/Multi 的备份、字节恢复、验证器、服务和真实客户端通过，但严格 mode/owner 对照发现 thirdparty cert/key 被恢复流程归一为 `0640 root:xray`，而源端是 `0644/0600 root:root`（`bashcoldrestore-bc12-8ff-1128`、`bashcoldrestore-bc13-8ff-1128`）。先前 Bash M4 TLS/WebSocket 新目标恢复证据位于 `bashcold-restore-retry-current-7d3e19d9-20261127`；首次失败缺 `/var/log/xray` 的产品修复已提交 `8ff26917` | Bash 侧第三方权限变化与 Go 保留行为明确记录为安全差异；不修改 OPS-25/26 原生对照的正式 PASS_DUAL，不把 Bash Relay/Multi 严格权限检查误记成完全通过。旧 M4 restore 的 `harden_config_permissions` 非致命警告仍保留为待诊断限制 |
| C2 S4–S9 / Pebble ACME | PASS_TARGETED（修正旧断言后） | `evidence/s4-s9-current-retry2-7d3e19d9.log`：64 PASS / 0 FAIL，含 S5 Pebble 连续续期与 CA 不可达回滚 | 首轮 63/1 是“Xray is up to date”断言过时；产品检测到 26.11.9 高于 26.10.31 并拒绝降级，已改为验证该事实并重跑全部脚本；首轮日志保留 |
| C2 30 分钟稳定性 soak | PASS_TARGETED（另有首轮失败） | `evidence/soak-diag-current-7d3e19d9.log` + `tests/e2e-diff/evidence/soak-diag-current-7d3e19d9-20261127/soak/`：31/31、1863 秒、31 个真实 L4、0 fail、服务零重启、调度 timer active 且 runs=2 | 首轮 run 在 iter 26 出现真实 timeout；旧 runner 没保留失败现场，原因无法追溯。instrumented 二轮完整通过，保留首轮失败，不将原因写成已证实 |
| C2 迁移、版本与平台 | PASS_TARGETED / IMPACT NOTE | 当前 R1/R2、两历史源迁移、Xray 三版本已实测；Debian 12 M1/M4 两轮双端 L4 通过；amd64 M1/M4 在 linux/amd64 Docker 模拟环境通过 | amd64 镜像/ELF/container uname 均确认 x86_64，但 Docker 宿主为 arm64；只声明模拟环境证据，不声称原生 amd64 硬件结果 |
| D1 最终代码/测试 | PASS_LOCAL_WITH_STRICT_NO_GO | Go 1.27.4 linux/arm64 上 `go test ./...`、`go test -race ./...`、`go vet ./...`、`go build` 历史可靠记录均 rc=0；本轮 `bash -n`、Expect/Tcl `info complete`、40 个采集器 Python 契约测试、artifact guard 均 rc=0；证据索引更新后隐私扫描覆盖 75,366 个文件、0 finding，详见 `evidence/privacy-scan-coldrestore-final-20261128.log`；初扫的一条证书序列号/IPv6 误报及派生文本脱敏映射另存 `evidence/privacy-scan-coldrestore-initial-20261128.log`、`evidence/privacy-redaction-map-coldrestore-20261128.json`。完整 staged diff check 对历史原始证据文件的尾随空格曾 rc=2，没有改写日志；记录见 `evidence/staged-evidence-whitespace-20261127.log` | strict ledger rc=1 是真实未解决分类，不视为测试故障，也不降级验收口径；终端证据格式的 whitespace 结果透明保留 |
| D2 Docker 开发候选资格 | NO_GO | 当前严格分母 34：28 DUAL、3 FAIL、1 BASH_ONLY、2 BLOCKED、0 NOT_RUN；strict rc=1 | OPS-14/16/27 FAIL、OPS-17a/18 BLOCKED、OPS-30 Bash-only；当前 SHA 七项远程 CI 未完成 |
| D3 交付 | PRODUCT_COMMITTED / AUDIT_COMMITTED | 产品修复提交 `8ff26917`；此前审计提交为 `5aba12f9`；当前候选账本、OPS-14/16/20 新证据、报告与验收器更新已提交为 `c925b7fc`。未推送、未合并、未 tag/release/VPS | 七项远程 CI 仍为 CI_PENDING；按任务书无现成推送授权，保留本地分支提交 |


## 当前候选更新（2026-11-28；以下状态取代上方较早快照）

产品候选代码 SHA `2ccbeb3ca56bed006d85c7fa4f582f96a145ccfd`，工作分支 `work/go-hardening-parity-20261119`。严格 OPS-34 现为 **30 DUAL / 4 FAIL / 0 BASH_ONLY / 0 BLOCKED / 0 NOT_RUN**，严格退出码 `1`，资格 **NO_GO**。

| 项目 | 当前状态 | 证据与未决事项 |
|---|---|---|
| OPS-03 | DUAL，关闭 | 正式基础双端操作与独立短 ID/撤销/重启边界运行均有证据；独立 run `ops03-boundary-23fa585f-20261127` 验证共享 shortId 保留、删除后旧凭据连接拒绝、重启后旧凭据仍拒绝、基线用户持续可用。映射证明 `internal/xraycfg` 未变，不伪称在 2cc 上重跑。 |
| OPS-17a | DUAL，关闭 | `codex-ops17a-85340b48-20261128`；Bash/Go 签名更新替换、摘要、服务健康与更新后真实 Reality 客户端 L4。 |
| OPS-25/26 | DUAL，关闭 | `codex-ops-backup-85340b48-20261128`；Bash/Go 真实备份恢复、数据、权限、服务和真实连接对照。 |
| OPS-18 | DUAL，关闭 | 真实 BBR 宿主/Docker run `ops18-host-bbr-9d32f5fd-20261128`：Bash TCP 包装与原生 Go 分别 apply/rollback；核对 BBR/fq、生效状态、托管文件/journal 清除及宿主原值还原。OCI 镜像 ID、执行二进制、manifest、原始 artifact 和 workflow 日志均归档。一次 PATH harness 失败保留并明确被修复后的 run 取代。 |
| OPS-14 | FAIL / DIFF | 当前候选持续负载下 35/35 HTTP 200、20 个 watch 样本中 32 个正速率点；仍待契约所有者决定 aggregate rate 与 iftop per-peer 的粒度/隐私取舍。 |
| OPS-16 | FAIL | 只读 JSON 证书状态、scheduler 状态与 Bash 交互菜单存在行为差异；目前没有绑定当前证据的审批。 |
| OPS-27 | FAIL | Go 保留未管理的第三方证书，Bash 递归清理整个证书目录；安全优势和回滚边界有证据，但执行者不代替契约所有者审批。 |
| OPS-30 | FAIL / DIFF | Go `language set/show` 已读写 Bash 兼容的持久 `language.conf`，支持逐命令 `--lang` 覆盖；真实 Docker 对照验证两端 English locale 字节相同。Go 完整翻译仅 zh/en，TTY 菜单未本地化/自适应，未获契约裁定。F23 106 项探针见 `tests/go-parity/evidence/f23-persistent-language-20261128/`；P2 证据 `tests/e2e-diff/evidence/ops30-language-2ccbeb3c-20261128/p2/OPS-30/`。 |
| 远程 CI | PASS | 产品 SHA `2ccbeb3c` 的七项 PR workflow 均通过；审计交付 HEAD `f52dadba2c91636c2de53ac39133dafec80517f2` 上七项 PR workflow 与 push Privacy Guard 最终通过；Test Install 初次安全回归失败后，隔离 Docker 重现通过、同提交重跑通过，初次原因不明，见 `evidence/security-regression-rerun-f52dadba.log` 及 evidence-index.json `ci.auditHead` |（Test Install `46075930250`、real-root `46075930267`、Go parity stage `46075930310`、生产资格 `46075930317`、预览 `46075930397`、Rill `46075930329`、Privacy Guard `46075930255`）；push Privacy Guard `46075915776` 通过。 |
| Go 回归 | PASS | Docker Go 1.27.4 上 `go test ./...`、`go vet ./...` rc=0；F23 106/0。日志见 `tests/go-parity/evidence/f23-persistent-language-20261128/`。 |
| Docker 开发候选结论 | **NO_GO** | 正式分类仍有 OPS-14/16/27/30 四项 FAIL；CI 全绿不自动批准行为差异。 |

严格账本记录：`evidence/strict-ledger-ops30-language-2ccbeb3c.log`。当前未决项只剩 OPS-14/16/27/30；OPS-03、OPS-17a、OPS-18、OPS-25/26 均不再列为阻断项。未合并主线、未打 tag、未正式发布、未操作生产 VPS。
