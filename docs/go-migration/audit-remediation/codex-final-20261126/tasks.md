# 本轮任务账本（2026-11-26）

候选代码：`f4deaf77c08457bf2ed1a07e165b2ff5bf5b53f5`。依据本轮主任务书，不把审计锚点当作回退目标。

2026-11-27 后续：在补跑未测 OPS 后发现并修复 Nginx 升级丢失托管主配置的问题，产品修复提交 `fb55adf78ee960eda695e6e5742f4c16ff328639`。另在产品源码未变化的后续审计提交上运行 Go Reality/TLS/Relay/Multi 四种冷恢复。下表中原正式 34 项摘要仍是 f4deaf77 的冻结快照；后续定向结果单独绑定其证据与产品二进制，未将其他历史项伪装成新 SHA 复测。最终当前分支仍为 NO_GO。

| ID | 状态 | 证据 | 阻断 / 后续 |
|---|---|---|---|
| S0 基线与环境 | DONE | `initial-findings.txt`；分支 `work/go-hardening-parity-20261119`，基线时干净且比 origin 超前 7 提交；无 AGENTS.md；Docker 29.8.2 linux/arm64、Go 1.27.4 容器、Xray、Nginx、Expect 可用 | 当前工作树改动已提交；未推送 |
| A1 隐私与 CI | LOCAL_PASS / CI_PENDING | 最终文档与证据更新后全仓扫描：`evidence/privacy-scan-final.log`；脱敏修复及历史 finding 见 `probe-development-log.md` | 当前候选未推送，无法在此 SHA 实跑七项 CI；不得以本地扫描代替 CI |
| A2 Guard 状态 | TARGETED_PASS | 最终 SHA `tests/e2e-diff/evidence/codex-final-20261126-f4deaf77/p2/OPS-08`：双端保留旧 mtime、磁盘变更未 reload 时 `runtime-unverified`，Nginx `-t` 成功，旧 worker 拒绝未知 SNI；管理 reload 后 `active`；已知/未知 SNI 结果留档 | isolate 路径已验证；reject/decoy 的真实探查见证据日志。异步 reload、进程重启/PID 复用和 reload 故障回滚未在本轮完整运行 |
| A3 证书与 ACME 清理 | PARTIAL_PASS | 当前候选 OPS-27 真双端 canary 差异；动态 `${cert_name}` HTTPS、外部 ACME 哈希与项目闲置 cert/key 清理在前一候选上实测，`certclear.go` 本轮未改，见 `evidence/certclear-*` | 真实事务中断/回滚未测；Bash/Go OPS-27 对第三方 canary 的行为差异仍为 FAIL，不得批准 |
| B1 provenance 门禁 | PASS | `evidence/ledger-contract-tests-final.log` 32 tests；最终构建清单锁定候选 SHA、binary/script/driver/dependencies、镜像和平台；严格构建核验实际文件摘要 | 旧 run 保持其原候选身份；未把历史证据改绑为当前 SHA |
| B2 业务事实与返回码 | PARTIAL_PASS | 最终 SHA OPS-01/02/03/08/20 双端真实结果；OPS-20 Reality 业务与入站统计；Go sweep 57 PASS / 0 FAIL 并记录命令 actualRc/expectedRc | OPS-04 与 OPS-26 BLOCKED；其余 GO_ONLY 不能替代双端验证 |
| B3 替代/批准/失败保留 | PASS_GUARD | `test_build_ledger.py` 32 tests 在最终提交 fb55adf7 重跑通过；`guard_acceptance_artifacts.sh` 确认三份正式摘要测试前后字节一致；严格正式账本仍保留 OPS-27 FAIL | 失败和未闭环项保留为未解决；审批仍需用户/可信授权来源 |
| C1 OPS-20 真实流量 | PASS_DUAL | Bash、Go 各自真实 Reality 客户端通过 Nginx origin 获取 1 MiB；HTTP rc=0、长度与 SHA-256 匹配；两端入站上/下行统计基线与增量留档 | 计数包含协议开销，按真实入站维度判断，不要求等于 payload 字节 |
| C2 其余能力影响分析 | PARTIAL | `impact-analysis.md` 对变更路径与历史专项逐类列出候选、受影响面、复用条件与未执行状态；补充提交 fb55adf7 上 OPS-17b 双端真实升级、升级后 L4、Go 更新失败回滚及回滚后 L4；Go 真实冷恢复 Reality/TLS/Relay/Multi 四类均通过，证据见 `tests/e2e-diff/evidence/goevo-coldrestore-cold-fb55-20261127*` | OPS-03 仍缺共享凭据与撤销/重启边界；OPS-17a 有签名更新成功、签名拒绝和健康回滚，但无跨版本业务连接；OPS-25/26 仍缺 Bash 与 Go 原生备份格式的对照。原 34 项机器账本仍明确绑定 f4deaf77；未把其余历史项冒充为 fb55adf7 证据 |
| D1 构建与验证 | PASS_TARGETED | Go update/CLI/deploy/Nginx 测试、componentupdate race、全仓 vet、真实 Bash/Go OPS-17b 更新/回滚/L4、验收器负例与正式文件隔离日志 | 新提交只按影响范围重跑，未将其他 f4deaf77 证据升级为 fb55adf7 全量通过；七项远程 CI 仍 pending |
| D2 Docker 开发候选资格 | NO_GO | 正式 34 项 f4deaf77 快照：5 DUAL、14 GO_ONLY、1 FAIL、2 BLOCKED、12 NOT_RUN；补充 fb55adf7 的 OPS-17b 通过不解除 OPS-27、OPS-04/26 及七项 CI 阻断 | fb55adf7 只完成定向更新路径验证；正式验收账本尚未在该提交全量重建，不能据此签收 |
| D3 交付 | LOCAL_COMMITTED | 产品修复提交 `fb55adf7`；补充审计与运行证据随本地提交 | 无 push 授权，保留本地提交；未合并、tag、发布或接触生产 VPS |
