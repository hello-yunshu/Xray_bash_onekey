# 本轮任务账本（2026-11-26）

候选代码：`3577d48761135c9418e3b39f8a834210a6553a88`。依据本轮主任务书，不把审计锚点当作回退目标。

| ID | 状态 | 证据 | 阻断 / 后续 |
|---|---|---|---|
| S0 基线与环境 | DONE | `initial-findings.txt`；分支 `work/go-hardening-parity-20261119`，基线时干净且比 origin 超前 7 提交；无 AGENTS.md；Docker 29.8.2 linux/arm64、Go 1.27.4 容器、Xray、Nginx、Expect 可用 | 当前工作树改动已提交；未推送 |
| A1 隐私与 CI | LOCAL_PASS / CI_PENDING | `evidence/privacy-scan.log`：0 finding / 60,918 files；脱敏修复及历史 finding 见 `probe-development-log.md` | 当前候选未推送，无法在此 SHA 实跑七项 CI；不得以本地扫描代替 CI |
| A2 Guard 状态 | TARGETED_PASS | `tests/e2e-diff/evidence/codex-final-20261126-3577d487/p2/OPS-08`：双端保留旧 mtime、磁盘变更未 reload 时 `runtime-unverified`，Nginx `-t` 成功，旧 worker 拒绝未知 SNI；管理 reload 后 `active`；已知/未知 SNI 结果留档 | isolate 路径已验证；reject/decoy 的真实探查见证据日志。异步 reload、进程重启/PID 复用和 reload 故障回滚未在本轮完整运行 |
| A3 证书与 ACME 清理 | PARTIAL_PASS | Go CLI 动态 `${cert_name}` TLS 前后 HTTPS 成功；外部 ACME 树哈希前后一致；项目归属未用证书/私钥实际删除；未登记同内容副本及嵌套用户目录保留，见 `evidence/certclear-*` | 真实事务中断/回滚未测；Bash/Go OPS-27 对第三方 canary 的行为差异仍为 FAIL，不得批准 |
| B1 provenance 门禁 | PASS | `evidence/ledger-contract-tests.log` 32 tests；最终构建清单锁定候选 SHA、binary/script/driver/dependencies、镜像和平台；严格构建核验实际文件摘要 | 旧 run 保持其原候选身份；未把历史证据改绑为当前 SHA |
| B2 业务事实与返回码 | PARTIAL_PASS | OPS-08 真实 SNI 结果；OPS-20 双端真实业务与入站统计；Go sweep 57 PASS / 0 FAIL 并记录命令 actualRc/expectedRc | OPS-04 与 OPS-26 BLOCKED；其余 GO_ONLY 不能替代双端验证 |
| B3 替代/批准/失败保留 | PASS_GUARD | `test_build_ledger.py` 32 tests；严格正式账本保留 OPS-27 FAIL，无外部可核验授权，未生成批准 | 失败和未闭环项保留为未解决；审批仍需用户/可信授权来源 |
| C1 OPS-20 真实流量 | PASS_DUAL | Bash、Go 各自真实 Reality 客户端通过 Nginx origin 获取 1 MiB；HTTP rc=0、长度与 SHA-256 匹配；两端入站上/下行统计基线与增量留档 | 计数包含协议开销，按真实入站维度判断，不要求等于 payload 字节 |
| C2 其余能力影响分析 | PARTIAL | `impact-analysis.md` 对变更路径与历史专项逐类列出候选、受影响面、复用条件与未执行状态 | OPS-03/17a/17b/25/26、XHTTP 扩展入口及大范围历史矩阵未在本轮重跑或不具当前候选可信 provenance；不计 PASS |
| D1 构建与验证 | PASS | Go test/vet/build/race、Bash 语法、真实 Docker/Xray/Nginx/客户端回归、验收器负例与正式文件隔离日志 | 七项远程 CI 仍 pending |
| D2 Docker 开发候选资格 | NO_GO | `tests/e2e-diff/ledger.json` 当前 34 项：2 DUAL、17 GO_ONLY、1 FAIL、2 BLOCKED、12 NOT_RUN；严格 builder rc=1 | OPS-27 FAIL、OPS-04/26 BLOCKED、32 项未达到双端解决状态，且七项 CI 未在此 SHA 完成 |
| D3 交付 | LOCAL_COMMITTED | 当前分支提交见终报；报告、账本、影响分析、证据索引和脱敏真实日志齐备 | 无 push 授权，保留本地提交；未合并、tag、发布或接触生产 VPS |
