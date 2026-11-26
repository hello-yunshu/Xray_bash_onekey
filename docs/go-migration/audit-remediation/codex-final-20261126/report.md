# Xray Go 重构定向收尾与最终验收报告

日期：2026-11-26（Asia/Shanghai）  
工作分支：`work/go-hardening-parity-20261119`  
最终代码：`f4deaf77c08457bf2ed1a07e165b2ff5bf5b53f5`

## 结论

**DOCKER_DEVELOPMENT_QUALIFICATION = NO_GO**  
**RELEASE_AUTHORIZED = NO**

Docker、Bash、Go、Xray、Nginx 和客户端均实际运行，OPS-01/02/03/08/20 双端真实行为通过；这不足以形成开发候选签收。最终 34 项账本为 5 DUAL、14 GO_ONLY、1 FAIL、2 BLOCKED、12 NOT_RUN。OPS-27 仍有未批准行为差异，OPS-04/26 被阻断；严格验收器返回 rc=1 并保留失败。最终 SHA 的 7 项 CI 未运行：该分支未推送，不能用本地扫描代替远程工作流。

## 2026-11-27 后续复验：Nginx 更新丢配置

补跑 OPS-17b 后，在 f4deaf77 的真实 Docker Go 容器发现产品缺陷：Go 更新器备份并替换整个 `/usr/local/nginx`，没有保留已托管的 `conf/nginx.conf`；发行包默认文件通过 `nginx -t`，却不再 include `/etc/idleleo/conf/nginx/00-xray.conf`，导致 443 listener 消失、真实 Reality 客户端 curl exit 56。原始失败与 `nginx -T` 见 `tests/e2e-diff/evidence/obsfix-final-fb55/p2/OPS-17b/pre-fix-f4`。

最小修复提交为 `fb55adf78ee960eda695e6e5742f4c16ff328639`：升级前读取现有主配置及权限，安装新 Nginx 工件时写回暂存树并显式恢复权限；其他 Nginx 工件继续从已校验发行包安装。Go 回归测试验证主配置和 `0640` 权限保留。Go 1.27.4 容器内，受影响包测试、race 测试、`go vet ./...` 均通过，记录见 `evidence/nginx-update-preserve-config-go.log`。

精确提交 `fb55adf7` 的真实 OPS-OBSERVE 使用 ARM64 Docker 镜像 `sha256:c79dc885b786be832d0f050ee9cea9b4dfa3df4749f3e7cff9d27e16747a5c7b`；Go 二进制 SHA-256 为 `5cce2164229f1219f84fd2f089e0db404530f76dbb224b5a8ae53392e3fd38c6`，Nginx 1.27.5→1.30.6 两侧更新 rc=0。更新后双方服务 active、`nginx -t` 成功、托管 include 存在、443 listener 存在；双方真实 Reality 客户端均取得 577-byte HTTP 响应且 SHA-256 匹配。Go 侧用实际 Nginx 1.30.6 包声明错误目标版本，更新器 rc=6、`rolledBack=true`；配置 SHA 与真实版本恢复，Xray/Nginx 仍 active，443 仍监听，回滚后真实客户端再次成功。运行清单和日志见 `tests/e2e-diff/evidence/obsfix-final-fb55/p2/`。

后续卫生扫描均为 0 finding；最终扫描为 61,478 个文件，输出见 `evidence/nginx-update-privacy-final.log`。所有未计通过的诊断均保留：手动 L4 首次误挂空目录导致 Permission denied；一次候选 runner 因空 Xray 缓存记录空 SHA 后被停止；一次误用只读证据挂载作为 CLI 输出目录、尚未执行产品命令；以及容器写入保护在未设置授权变量时返回 rc=2、未改动状态。正确缓存、路径和容器变量下的正式验证见 `obsfix-final-fb55`，上述记录均不计入通过证据。

验收器本身未修改；在 fb55adf7 上重新运行 `python3 tests/e2e-diff/collect/test_build_ledger.py -q`（32 tests）和 `bash tests/e2e-diff/collect/guard_acceptance_artifacts.sh`，均通过且正式三份摘要字节未变，分别见 `evidence/ledger-contract-tests-followup.log` 与 `evidence/acceptance-artifact-isolation-followup.log`。全仓 hygiene 的最终复跑日志为 0 finding（61,478 个文件），见 `evidence/nginx-update-privacy-final.log`。

本次结果证明该 Nginx 更新缺陷已修复，也证明 Go 版本会在健康验证失败时恢复完整旧安装并维持可用 listener。它只覆盖 OPS-17b 的当前代码提交，不覆盖其他 33 项；此前正式 ledger/matrix/acceptance 仍是 f4deaf77 的冻结摘要，故本报告对 fb55adf7 不作全量签收，Docker 资格继续为 **NO_GO**。

## 关键修复与真实业务结果

- **Guard（`internal/deploy/guard.go`）**：移除“进程启动时间早于文件 mtime 即 active”的推断。状态只有在 reload 记录绑定当前 Nginx PID、start ticks 和策略内容时才报告 active；磁盘策略变化但未 reload 时回落为 `runtime-unverified`。最终 SHA 双端 Docker/Nginx 实跑：保留旧 mtime 的磁盘编辑、`nginx -t` rc=0、reload 前 Guard 为 `runtime-unverified`，旧 worker 拒绝未知 SNI；管理 reload rc=0 后状态 `active`。已知 SNI、未知 SNI结果在 OPS-08 留档。另在 Go 容器运行 decoy/reject 策略：未知 SNI 经 decoy 返回诱饵页，reject 下 curl TLS 失败 rc=35。标准 curl 不能作为 Reality 已知 SNI 客户端；已知 Reality 业务由 OPS-20 的真实 Xray 客户端验证。
- **证书清理（`internal/deploy/certclear.go`）**：外部 `~/.acme.sh` 全目录始终保留，不因同域证书/密钥或类似 ownership marker 而移动。Go 完整 CLI 的动态 `${cert_name}` 配置在清理前后都完成 HTTPS 请求，证书、私钥和 ACME 树 SHA-256 前后相同。另验证项目 marker 精确登记的闲置证书与 key 被删，同内容但未登记副本、第三方 canary、嵌套 `.user-managed` 目录及数据保留。首次运行因一次性容器缺 `mime.types` 被安全逻辑拒绝；补齐容器测试夹具后相同 CLI 回归通过，两个结果均留档。
- **OPS-20 统计**：Bash 和 Go 各自启动真实 Xray Reality 客户端，经服务端访问本地 Nginx origin 的 1 MiB payload。两端 HTTP rc=0，body 长度均为 1,048,576，SHA-256 均为 `0be737c61b3af7e6f28386f2eea86dde147c084e05a635e5e133b7705481d41a`。最终候选 Bash inbound uplink/downlink 合计增量 1,050,068 bytes；Go inbound 为 1,050,211 bytes（API 自身另增 584 bytes）。无 API 时 Bash rc=2、Go rc=3；启用后两端统计查询 rc=0 且入站计数为正。开销不同，未要求计数等于 payload。
- **OPS-03 用户与 shortId**：最终 SHA 的 Bash、Go 都真实添加两名客户端、连接成功并移除一名用户；Go 的移除步骤后仍有一个 inbound shortId，随后显式运行 `xray config edit --short-id-remove` 清理并 rc=0，Bash 则在用户移除时一并清理。探针按最终可观察状态将该项计为双端通过，但实现步骤不同，不能据此声称共享 shortId、撤销旧凭据或重启边界已覆盖。
- **XHTTP 路径**：最终 SHA 的 Bash 与 Go M6 各完成两轮 TLS/XHTTP 安装，真实 Xray 客户端均取得相同 577-byte 网页；手动输入 `//ray//custom//` 后 Go 分享 URI、Xray 路径和 Nginx location 均为 `/ray/custom/`，`nginx -t`、`xray -test` 与实际客户端请求通过。旧候选真实红测中 `/ray//` 生成精确 location，但请求 URI 被 Nginx 合并斜杠后未匹配、curl rc=52；当前修复在编辑和生成入口规范化重复斜杠，同时保留结尾 `/`。
- **备份、恢复与更新**：在前一候选 `5528ca7f` 容器中运行 Go CLI 创建并验证真实备份，改变有效配置后执行容器恢复；恢复后的配置摘要与原始摘要完全一致，Xray 配置校验成功，文件权限为 `640`、属主 `0:995`。同一候选的临时 Ed25519 签名更新 probe 验证检查、显式应用、损坏签名拒绝及健康失败后的真实二进制回滚。此次最终 XHTTP 改动只触及 `internal/xraycfg`，备份/更新实现文件与这些证据不受影响；E8 私钥轮换及健康失败回滚另在最终 SHA 真实客户端重跑，14/14 检查通过。上述 Go 实测仍不替代 OPS-25/26 的 Bash 对照和完整业务恢复场景。
- **验收门禁**：真实摘要与镜像 manifest 校验、合法时间/runId/平台、SNI 实际 rc、命令 actualRc/expectedRc、严格分母和逐条失败替代得到加强。32 个门禁契约测试通过。最终严格账本拒绝未解决签收而仍写出真实三份正式摘要；没有使用 `--allow-incomplete` 生成最终验收结论或虚构批准。
- **证据卫生**：修复 round4 报告中会被误判为 IPv6 的地址写法，并对六个历史 GeoData 测试夹具地址作逐值说明；扫描器规则未放宽、历史失败记录未删除。最终文档变更后的全仓扫描结果见 `evidence/privacy-scan-final.log`。

## 最终 OPS-34 账本

| 状态 | 数量 | OPS ID |
|---|---:|---|
| DUAL_SIDE_VERIFIED | 5 | OPS-01、02、03、08、20 |
| GO_ONLY | 14 | OPS-11、12、13、14、15、16、17a、18、22、23、24、25、28、29 |
| FAIL | 1 | OPS-27 |
| BLOCKED | 2 | OPS-04、OPS-26 |
| NOT_RUN | 12 | OPS-05、06、07、09、10、17b、17c、19、21、30、31、32 |
| BASH_ONLY / APPROVED_DIFF / APPROVED_SINGLE_SIDE | 0 | — |

OPS-27 的差异是明确的真实差异：Bash 菜单清理会在一次确认后删除整个证书目录，包括第三方 canary；Go 仅删除可证明为项目所有且未使用的文件，保留 canary。没有独立可核验的授权原文，本轮不批准、不把失败改为等价。该项是安全边界差异，不意味着 Go 的保守实现应改成 Bash 的递归删除行为。

完整逐行历史和证据路径见 [ledger.json](../../../../tests/e2e-diff/ledger.json)、[matrix.json](../../../../tests/e2e-diff/matrix.json) 与 [acceptance.json](../../../go-evolution/hardening/acceptance.json)。

## 构建、测试与 CI

- Go 1.27.4 容器：`go test -count=1 ./...`、`go vet ./...`、`go build ./cmd/idleleo ./cmd/idleleo-recover`、`go build -race -o /tmp/idleleo-race ./cmd/idleleo`、`go test -race -count=1 ./...` 均 rc=0。
- Bash：对 `install.sh`、P2 matrix、OPS sweep、L4 collector 执行 `bash -n`，rc=0；完整 Bash 安装由真实双端 Docker 用例执行。
- Docker：最终候选二进制 SHA-256 `160e248223fcf3988239defb4ea1b95ed85883d883b5a072838a8590dad75c1e`，平台 linux/arm64。最终 SHA 的 OPS-01/02/03/08/20、OPS-27、OPS sweep、E8 私钥轮换回滚和 M6 XHTTP 安装均有候选/run/镜像/构建清单 provenance；索引见 [evidence-index.json](evidence-index.json)。
- Go OPS sweep：57 PASS / 0 FAIL，包含用户、服务、统计、调度、证书 dry-run、元数据、卸载等 CLI 命令。`OPSS-01` 是非正式旁路项，运行通过但附加断言记录器打印 `unknown OPS id for command evidence`；未把它计入正式 34 项。
- 门禁：`test_build_ledger.py` 32 项通过，`guard_acceptance_artifacts.sh` 确认三份 tracked 正式摘要在测试前后字节一致。严格最终构建仍以 rc=1 失败，这是预期且诚实的签收结果。
- 远程 CI：旧审计报告记录旧 SHA 为 5/7，Privacy Guard 和 Go parity stage gate 曾因 hygiene 失败。本轮没有推送最终候选，因此七条工作流状态为 **CI_PENDING**，不是通过。

## 影响分析与未闭环

历史的 OPS-03 / OPS-17b、98 项配置对照、R1/R2/历史版本迁移、S4–S9、P3 热更新、冷恢复、广泛故障注入、Xray 多版本、Debian 12、amd64 和 ≥1800 秒 soak 未在本轮最终 SHA 全量复测。M6 是例外：因本轮发现并修复 XHTTP 重复斜杠缺陷，已在最终 SHA 定向重跑。其余旧 SHA 证据仅作历史事实，不作当前 PASS；完整逐项影响表和复用理由见 [impact-analysis.md](impact-analysis.md)。

仍未完成的强制项：七项当前 SHA CI；OPS-27 差异的可核验产品契约/授权决策；OPS-04 分享链接端口事实、OPS-26 完整 Bash/Go 恢复对照；OPS-03 共享 shortId 与撤销旧凭据边界；OPS-17b 跨版本更新后的真实业务连接；OPS-17a 的本地签名更新与失败回滚已在前一候选实跑且更新实现未受本轮 XHTTP 改动影响，完整跨版本业务升级仍未覆盖；OPS-25/26 完整 Bash/Go 数据、权限、连接恢复对照；Guard 进程重启/PID 复用与完整失败回滚；证书 clear 的事务中断回滚、更多 ownership 负例；amd64/第二发行版和长时 soak。它们仍是 BLOCKED、NOT_RUN 或 GO_ONLY，不因摘要生成而改变。

## 交付状态

XHTTP 路径修复已提交到当前开发分支；本轮最终报告、任务账本、影响分析、证据索引、实际日志及三份机器摘要随审计提交。没有 merge、tag、release、VPS 操作或 push。待完成项不是继续改写通过条件的理由；下一步需要在最终 SHA 上完成 CI 和剩余强制真实场景，并由授权方明确 OPS-27 的比较契约后，重新运行严格账本。
