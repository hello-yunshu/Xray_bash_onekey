# 历史证据影响分析

## 当前候选改动范围

本轮锚点为审计候选 `5041511998575851eb5cb16533e9fe999d29d5a8`，最终冻结代码为 `f4deaf77c08457bf2ed1a07e165b2ff5bf5b53f5`。本轮新增提交集中在：

| 文件 / 路径 | 变化面 | 必须重跑或新证据 |
|---|---|---|
| `internal/deploy/guard.go`、相关 Guard 测试 | active 证明、运行记录与策略内容绑定、旧 mtime 不再证明 worker 已加载 | OPS-08、旧 mtime / 未 reload / reload 后 SNI；本轮实际双端重跑 isolate |
| `internal/deploy/certclear.go`、相关证书测试 | 外部 ACME 树保守保留；项目文件仍要求路径、类型、摘要归属与未使用证明 | OPS-27 双端差异、Go 完整 CLI 动态 TLS、外部 ACME、项目闲置证书清理 |
| `tests/e2e-diff/collect/build_ledger.py`、`test_build_ledger.py`、验收汇总器 | provenance 校验、SNI 与业务事实、逐条 supersedes / 批准、严格分母 | 独立负例/契约测试、严格正式账本构建、三工件一致性 |
| `tests/e2e-diff/collect/l4.sh`、`client_config.py`、`run_p2_matrix.sh` | L4 客户端采集、统计 API 与证据清单 | OPS-20 双端真实客户端；OPS-08、OPS-27 受影响驱动也在最终 SHA 重跑 |
| `tests/e2e-diff/run_ops_sweep.sh` | 命令级实际 rc、期望 rc 与构建来源绑定 | 最终 SHA 全 sweep，57 PASS / 0 FAIL |
| `internal/xraycfg/edit.go`、`xraycfg.go`、相关测试 | XHTTP 安装/生成/编辑统一折叠重复 slash、保留 trailing slash，避免 Xray 路径与 Nginx URI 合并后的 location 不一致 | 旧候选 M6 容器旧 CLI 输入 `/ray//` 后真实客户端 curl rc=52；最终 SHA M6 双端默认/重复安装请求成功，Go 编辑输入 `//ray//custom//` 后真实 Xray 客户端成功请求，Xray `-test` 与 Nginx `-t` 通过 |
| 隐私 allowlist / evidence 归档 | 明确六项既有公共 IP 测试夹具；扫描器规则不降级 | 当前完整仓库扫描；远程 CI 仍须在最终 SHA 运行 |

## 历史专项复用决策

旧证据没有被改写或重新锚定到本轮 SHA。下表说明其作为“历史事实”可读，但是否纳入当前签收必须由影响范围和新 provenance 决定。

| 历史证据 / 套件 | 原候选 / 产品摘要 | 受本轮改动影响 | 本轮处理 / 结果 |
|---|---|---|---|
| `round4-final-50415119` OPS 全矩阵 | 旧候选 `50415119…`；无本轮完整 manifest provenance | 所有旧行均低于当前候选身份；OPS-08、OPS-20、OPS-27 直接受影响 | 仅保留为历史记录，不计本轮通过；当前只用最终 SHA 的 OPS-08/20/27 定向证据 |
| `round5-cand-ops03c-131954` OPS-03 | 旧候选，双端真实两步清理 | 本轮不改 shortId 管理逻辑，但验收摘要/provenance 改动影响其签收资格 | 旧证据不计入最终结论；最终 SHA 已实跑 Bash/Go 添加、真实连接、移除及 shortId 清理。Go 需显式执行第二条清理命令，结果由当前探针计为 DUAL；共享 shortId、撤销旧凭据和重启边界仍未跑 |
| `round5-cand-observe-130808` OPS-17b | 旧候选，Nginx 更新成功路径 | 本轮未改更新实现；候选不同且无本轮失败回滚/真实客户端数据 | 只作历史成功路径，当前 ledger 不采纳；失败回滚和升级后连接未跑 |
| `a4-xhttp-path.log` / 历史 XHTTP 交叉探针 | 旧候选；覆盖 `/xhttp` 与 `/xhttp/` 等 URI 语义 | 历史用例未覆盖重复斜杠经过托管 Nginx 的精确 location；本轮新修改 XHTTP 规范化 | 历史报告仍有效于原场景；针对新发现的重复斜杠故障，以最终候选 M6 双端客户端及 Go `//ray//custom//` 编辑后真实客户端重新运行 |
| `round4-full-50415119` / `round4-bizfacts*` 安装、配置、SNI 证据 | 产品候选 `50415119…` | Guard 运行状态代码及证据契约直接影响 SNI 结论；其他安装配置未改产品逻辑 | OPS-08 不复用，已用本轮双端实际重跑；其余配置安装只保留历史，不纳入本轮 PASS |
| M1–M10、两轮各传输 L4、98 项配置对照 | 早期产品/驱动 SHA | Guard、证书和 OPS 驱动变化局部影响；没有证据证明历史输出绑定本轮候选 | 未全量重跑；仅 M6 在最终 SHA 重新运行双端 XHTTP 默认及重复安装实际客户端连接；安装/编辑/传输其余行为仍未闭环签收 |
| R1/R2 与 v3.3.2 / v3.3.3 迁移 | 历史版本及其各自产物 | Go 管理核心/迁移路径本轮未修改；当前候选身份不同 | 未重跑；不能作当前候选验收证据 |
| S4–S9、P3 四传输热更新、冷恢复 Reality/TLS/Relay/Multi | 历史运行与各自构建 | Go 运行时统计设置和通用验收驱动变化；并非全路径静态无影响 | 未机械重跑；无最终 SHA 证据，保持未验证 |
| 故障注入（坏配置/证书、端口、只读、SIGKILL、ENOSPC、锁冲突） | 历史专项 | Guard 与 cert clear 事务边界直接相关 | 本轮 Go 包测试覆盖已有单测；本轮只实跑配置读取安全及证书保留/清理，未完整注入崩溃、ENOSPC、锁冲突及事务恢复 |
| Xray 三版本、Debian 12、amd64 部署 | 历史平台矩阵 | 本轮二进制目标和新 L4/Guard 驱动有影响 | 本地 Docker 为 linux/arm64；未运行 amd64 或第二发行版，保持未验证 |
| soak ≥1800 秒与两个调度周期 | 历史 soak | 本轮未改调度服务；当前 sweep 仅短时功能运行 | 未重跑，无当前候选稳定性结论 |
| OPS-17a / OPS-25 / OPS-26 | 旧 sweep/metadata/export 证据 | metadata 不等同更新或真实备份恢复，且不能替代 Bash 对照 | 前一候选 `5528ca7f` 的 Go CLI 用本地签名 release 实跑更新检查、应用、签名拒绝和健康失败回滚；真实备份校验与容器恢复后配置摘要一致。最终 XHTTP 候选改动未触及更新与备份实现文件，因此按路径影响分析复用，但不提升产品代码 SHA 的 provenance。未完成跨版本业务更新、Bash 对照及完整数据/权限/连接恢复，故 OPS-17a/25 仍 GO_ONLY，OPS-26 仍 BLOCKED |
| OPS-12/13、OPS-14/16/23/24、M8 | 历史产品契约 | 本轮未修改实时日志取舍、证书续期、速度测量、调度、Pebble 管理核心 | 本轮 sweep 重新确认 Go CLI 部分行为；保持 GO_ONLY。M8 继续标注 Bash wrapper 委托 Go，不宣称纯 Bash |

## CI 与批准边界

- 历史审计在旧 HEAD 曾有 5/7 CI 通过；Privacy Guard 与 Go parity stage gate 因 evidence hygiene 失败。本轮本地全仓扫描为 0 finding。
- 最终 SHA 在本轮没有 push，故不能触发或查询这 7 个工作流针对该 SHA 的结果；最终状态为 `CI_PENDING`。没有将本地扫描称为 CI 通过。
- 仓库里的 11/22、11/24 Trae 授权摘要无法独立核验原始会话。本轮没有读取到新的外部授权文本，也没有使用任何批准文件，不把 OPS-27 差异标为已批准。
