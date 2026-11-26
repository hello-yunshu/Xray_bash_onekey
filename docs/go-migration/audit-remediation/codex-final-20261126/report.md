# Xray Go 重构定向收尾与最终验收报告

日期：2026-11-26（Asia/Shanghai）  
工作分支：`work/go-hardening-parity-20261119`  
最终代码：`3577d48761135c9418e3b39f8a834210a6553a88`

## 结论

**DOCKER_DEVELOPMENT_QUALIFICATION = NO_GO**  
**RELEASE_AUTHORIZED = NO**

Docker、Bash、Go、Xray、Nginx 和客户端均实际运行，OPS-08 与 OPS-20 的双端真实行为通过；这不足以形成开发候选签收。最终 34 项账本为 2 DUAL、17 GO_ONLY、1 FAIL、2 BLOCKED、12 NOT_RUN。OPS-27 仍有未批准行为差异，OPS-04/26 被阻断；严格验收器返回 rc=1 并保留失败。最终 SHA 的 7 项 CI 未运行：该分支未推送，不能用本地扫描代替远程工作流。

## 关键修复与真实业务结果

- **Guard（`internal/deploy/guard.go`）**：移除“进程启动时间早于文件 mtime 即 active”的推断。状态只有在 reload 记录绑定当前 Nginx PID、start ticks 和策略内容时才报告 active；磁盘策略变化但未 reload 时回落为 `runtime-unverified`。最终 SHA 双端 Docker/Nginx 实跑：保留旧 mtime 的磁盘编辑、`nginx -t` rc=0、reload 前 Guard 为 `runtime-unverified`，旧 worker 拒绝未知 SNI；管理 reload rc=0 后状态 `active`。已知 SNI、未知 SNI结果在 OPS-08 留档。另在 Go 容器运行 decoy/reject 策略：未知 SNI 经 decoy 返回诱饵页，reject 下 curl TLS 失败 rc=35。标准 curl 不能作为 Reality 已知 SNI 客户端；已知 Reality 业务由 OPS-20 的真实 Xray 客户端验证。
- **证书清理（`internal/deploy/certclear.go`）**：外部 `~/.acme.sh` 全目录始终保留，不因同域证书/密钥或类似 ownership marker 而移动。Go 完整 CLI 的动态 `${cert_name}` 配置在清理前后都完成 HTTPS 请求，证书、私钥和 ACME 树 SHA-256 前后相同。另验证项目 marker 精确登记的闲置证书与 key 被删，同内容但未登记副本、第三方 canary、嵌套 `.user-managed` 目录及数据保留。首次运行因一次性容器缺 `mime.types` 被安全逻辑拒绝；补齐容器测试夹具后相同 CLI 回归通过，两个结果均留档。
- **OPS-20 统计**：Bash 和 Go 各自启动真实 Xray Reality 客户端，经服务端访问本地 Nginx origin 的 1 MiB payload。两端 HTTP rc=0，body 长度均为 1,048,576，SHA-256 均为 `0be737c61b3af7e6f28386f2eea86dde147c084e05a635e5e133b7705481d41a`。Bash inbound uplink/downlink 合计增量 1,050,105 bytes；Go 为 1,049,892 bytes（另有 API 自身统计）。无 API 时 Bash rc=2、Go rc=3，符合各自入口；启用后两端统计查询 rc=0 且入站计数为正。开销不同，未要求计数等于 payload。
- **验收门禁**：真实摘要与镜像 manifest 校验、合法时间/runId/平台、SNI 实际 rc、命令 actualRc/expectedRc、严格分母和逐条失败替代得到加强。32 个门禁契约测试通过。最终严格账本拒绝未解决签收而仍写出真实三份正式摘要；没有使用 `--allow-incomplete` 生成最终验收结论或虚构批准。
- **证据卫生**：修复 round4 报告中会被误判为 IPv6 的地址写法，并对六个历史 GeoData 测试夹具地址作逐值说明；扫描器规则未放宽、历史失败记录未删除。全仓扫描结果 0 finding / 60,918 files。

## 最终 OPS-34 账本

| 状态 | 数量 | OPS ID |
|---|---:|---|
| DUAL_SIDE_VERIFIED | 2 | OPS-08、OPS-20 |
| GO_ONLY | 17 | OPS-01、02、03、11、12、13、14、15、16、17a、18、22、23、24、25、28、29 |
| FAIL | 1 | OPS-27 |
| BLOCKED | 2 | OPS-04、OPS-26 |
| NOT_RUN | 12 | OPS-05、06、07、09、10、17b、17c、19、21、30、31、32 |
| BASH_ONLY / APPROVED_DIFF / APPROVED_SINGLE_SIDE | 0 | — |

OPS-27 的差异是明确的真实差异：Bash 菜单清理会在一次确认后删除整个证书目录，包括第三方 canary；Go 仅删除可证明为项目所有且未使用的文件，保留 canary。没有独立可核验的授权原文，本轮不批准、不把失败改为等价。该项是安全边界差异，不意味着 Go 的保守实现应改成 Bash 的递归删除行为。

完整逐行历史和证据路径见 [ledger.json](../../../../tests/e2e-diff/ledger.json)、[matrix.json](../../../../tests/e2e-diff/matrix.json) 与 [acceptance.json](../../../go-evolution/hardening/acceptance.json)。

## 构建、测试与 CI

- Go 1.27.4 容器：`go test -count=1 ./...`、`go vet ./...`、`go build ./cmd/idleleo ./cmd/idleleo-recover`、`go build -race -o /tmp/idleleo-race ./cmd/idleleo`、`go test -race -count=1 ./...` 均 rc=0。
- Bash：对 `install.sh`、P2 matrix、OPS sweep、L4 collector 执行 `bash -n`，rc=0；完整 Bash 安装由真实双端 Docker 用例执行。
- Docker：最终候选二进制 SHA-256 `0c8d1e6eeea4060d36892604066430c6fbd775fa33dfc62404672c057ef056c3`，平台 linux/arm64。OPS-08/20、OPS-27、OPS sweep 各自有完整候选/run/镜像/构建清单 provenance；索引见 [evidence-index.json](evidence-index.json)。
- Go OPS sweep：57 PASS / 0 FAIL，包含用户、服务、统计、调度、证书 dry-run、元数据、卸载等 CLI 命令。`OPSS-01` 是非正式旁路项，运行通过但附加断言记录器打印 `unknown OPS id for command evidence`；未把它计入正式 34 项。
- 门禁：`test_build_ledger.py` 32 项通过，`guard_acceptance_artifacts.sh` 确认三份 tracked 正式摘要在测试前后字节一致。严格最终构建仍以 rc=1 失败，这是预期且诚实的签收结果。
- 远程 CI：旧审计报告记录旧 SHA 为 5/7，Privacy Guard 和 Go parity stage gate 曾因 hygiene 失败。本轮没有推送最终候选，因此七条工作流状态为 **CI_PENDING**，不是通过。

## 影响分析与未闭环

历史的 OPS-03 / OPS-17b、M1–M10、98 项配置对照、R1/R2/历史版本迁移、S4–S9、P3 热更新、冷恢复、广泛故障注入、Xray 多版本、Debian 12、amd64 和 ≥1800 秒 soak 均未被本轮安全性定向修复改动直接覆盖；但其 SHA 不是最终候选，且本轮门禁要求候选 provenance，因此只作为历史事实，不作当前 PASS。完整逐项影响表和复用理由见 [impact-analysis.md](impact-analysis.md)。

仍未完成的强制项：七项当前 SHA CI；OPS-27 差异的可核验产品契约/授权决策；OPS-04 分享链接端口事实、OPS-26 完整恢复；OPS-03 共享 shortId 与撤销凭据；OPS-17b 更新失败回滚/真实业务连接；OPS-17a 手动更新成功/失败；OPS-25/26 完整数据/权限/连接恢复；Guard 进程重启/PID 复用与完整失败回滚；证书 clear 的事务中断回滚、更多 ownership 负例；amd64/第二发行版和长时 soak。它们仍是 BLOCKED、NOT_RUN 或 GO_ONLY，不因摘要生成而改变。

## 交付状态

源码修复分成 7 个提交保留在当前开发分支；本轮最终报告、任务账本、影响分析、证据索引、实际日志及三份机器摘要一并提交。没有 merge、tag、release、VPS 操作或 push。待完成项不是继续改写通过条件的理由；下一步需要在最终 SHA 上完成 CI 和剩余强制真实场景，并由授权方明确 OPS-27 的比较契约后，重新运行严格账本。
