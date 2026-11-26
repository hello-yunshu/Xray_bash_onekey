# 定向探针调试记录

以下失败均保留在此记录或 `evidence/` 下，不作为最终 PASS。已修正夹具/驱动后均用新的、同候选真实运行复测；没有删除最终账本中的产品差异。

| 运行 / 用例 | 实际失败 | 根因分类 | 修复与最终证据 |
|---|---|---|---|
| OPS-20 首轮 Bash L4（`codex-final-20261126-ops20-1`） | `curl exit 28, body bytes 0`（rc=28） | Docker 默认 RFC1918 源站地址被 Xray freedom 出站的私网保护拦截；不是服务端统计问题 | 改用相互隔离、非私网目的地址夹具与本地 Nginx origin；最终 Bash/Go 业务请求均 rc=0，证据 `tests/e2e-diff/evidence/codex-final-20261126-3577d487/p2/OPS-20` |
| OPS-20 Bash L4（`codex-final-20261126-ops20-2`） | `/opt/homebrew/bin/python3: Argument list too long` | 1 MiB 响应 body 被作为 Python argv 传入 | `collect/l4.sh` 改为文件输入；最终返回体长度与摘要通过 |
| OPS-20 数据统计初测 | 客户端传输成功，Go inbound counter 查询为空 | Go 只开 Stats API，未打开 Xray system policy 的 inbound uplink/downlink 计数 | `xray api enable` 同时启用 inbound policy；真实业务后 Bash 合计增量 1,050,105，Go 业务 inbound 增量 1,049,892 bytes |
| OPS-20 首轮失败后残留客户端容器 | 后续 Docker 网络出现重名/网段冲突 | 失败路径没有清理临时 L4 客户端 | 在 L4 collector 增加 EXIT 清理；最终容器清理后没有本轮测试容器残留 |
| OPS-08 首次 stale probe（`codex-final-20261126-ops08-1`） | `nginx -t` 失败 | 探针用了 `ssl_reject_handshake off` 但没有配置证书，测试配置本身不合法 | 改成仅编辑合法 `access_log` 指令并恢复旧 mtime；最终 `nginx -t` rc=0，运行时仍显示 `runtime-unverified`，reload 后 `active` |
| 早期 ledger strict build | 真正输出不完整/不可验证：文件清理在 manifest hash 后发生；matrix 根目录与 `build-manifest.json` 相对位置不一致 | 验收驱动构造问题，而非产品差异 | 清理放在 manifest 生成之前；matrix verifier 以真实 `p2/` 目录作为 manifest 根。最终 manifest 文件及 binary/script/dependency 摘要校验通过 |
| 项目闲置证书真实 Go CLI 首次运行 | CLI rc=0，但计划把项目归属证书留存；安全 warning 指向 `/usr/local/nginx/mime.types` 不可读；外层断言 rc=1 | 测试容器缺少镜像配置 include 文件，Go 按“无法证明无引用就保留”契约 fail-closed | 仅在一次性容器补齐 `mime.types` 并确认 `nginx -t`；重跑后 CLI rc=0 且明确删除 marker 登记的 cert/key。原始和重跑 JSON 分别在 `cert-owned-runtime.log`、`cert-owned-runtime-retry.json` |
| Guard reject 策略首次客户端探查 | `openssl s_client` 返回 rc=0，不能单独证明握手成功；随后的已知 Reality SNI 直接 curl 也 rc=35 | 探针客户端不符合 Reality 协议，且 `s_client` 退出码语义不足以证明握手 | 改用 curl 做未知 TLS 握手验证，reject 的未知 SNI curl rc=35；known Reality 正向行为由真实 Xray Reality 客户端 OPS-20 验证。记录 `guard-policy-runtime.log` 与 `guard-reject-client-check.log`，不把原 openssl rc 当业务结论 |
| 外部 ACME 动态路径初期探查 | 初版片段放入 Nginx stream include / 监听端口冲突 | 测试夹具放错 Nginx 上下文/端口，不是产品结果 | 移至真实 http include 的 `03-isolate.conf` 和可用 18443 端口，完整 Go CLI 与 HTTPS 前后请求通过 |

OPS sweep 还输出 `unknown OPS id for command evidence`，对应旁路 `OPSS-01` 的 `schedule status`；正式 OPS ID 没有因此被伪造。最终完整 sweep 仍为 57 PASS / 0 FAIL，`OPSS-01` 不纳入 OPS-34。

## 最终候选 SHA `5528ca7f` 的补充实测与失败记录

| 运行 / 用例 | 实际失败或差异 | 处理与最终证据 |
|---|---|---|
| OPS-03 最终双端矩阵 | Bash 用户移除时清除 shortId；Go 用户移除后保留一个 inbound shortId | Go 再执行 `xray config edit --short-id-remove`，rc=0 且清掉残留；最终业务态符合探针，但两端步骤差异明确记录在 `OPS-03/ops.json`，不推断共享 shortId / 撤销旧凭据 |
| Go 备份恢复初次外层断言 | 测试把原本已是 `warning` 的 loglevel 再设为 `warning`，没有造成可观察配置变化，断言失败 rc=1 | 修正夹具改为有效的 `debug` 配置变更后重跑。真实备份 create/verify/restore rc=0，恢复后配置 SHA 与原始值一致，Xray 配置校验成功，见 `backup-restore-runtime-retry.log`；首轮日志 `backup-restore-runtime.log` 保留 |
| 本地签名更新 probe 初次执行 | `update apply` 漏传容器模式参数，CLI 拒绝，rc=2；没有应用二进制 | 修正命令后重跑：签名版本检查通过、显式应用精确摘要成功、损坏 manifest 被拒绝且二进制不变，见 `update-local-release-runtime-retry.log`；初次失败保留于 `update-local-release-runtime.log` |
| 健康检查失败更新回滚 | 签名更新包内实际 CLI 版本低于 manifest 声明版本；安装后健康检查按真实版本事实失败 | 这次失败作为事务回滚场景使用：实际 updater 回滚成功，安装前后二进制 SHA 与 release state SHA 保持不变，见 `update-health-rollback-runtime.log` |
| 动态 TLS 配置后的静态证书清理夹具 | 动态 `${cert_name}` 配置使静态证书引用无法被安全证明，CLI 保守保留闲置静态证书并以 rc=1 告警 | 这是 fail-closed 的预期边界。另在没有动态变量的干净 Go 容器中独立运行静态清理：登记的闲置 cert/key 删除，同内容未登记副本及嵌套 `.user-managed` 均保留，rc=0，见 `cert-owned-static-runtime-5528.log`。变量配置下的原始结果保留于 `cert-owned-runtime-5528.log` |
| XHTTP 重复斜杠旧实现真实客户端红测 | 旧候选完整 Go CLI 接受并保存 `/ray//`，Nginx 生成 `location /ray//`；客户端 HTTP URI 合并斜杠后为 `/ray/<id>`，未命中该 location，真实请求 curl rc=52 | 当前候选将重复斜杠归一为 `/ray/` 且保留尾斜杠；使用相同隔离容器与真实 Xray 客户端，请求成功，完整红绿见 `xhttp-double-slash-red-retry.log`、`xhttp-double-slash-fixed-retry.log` 及对应 JSON 目录 |
| XHTTP 重复斜杠探针的无效尝试 | 第一次把 `--transport` 当作 transport 值；第二次挂载路径指向容器内文件，客户端二进制无执行权限；后续一次因测试容器保留两条 Docker 网络而拼接错误 IP | 这些运行均不用于产品结论。修正传输参数、从真实候选容器导出 Xray 二进制、断开旧网络后再做红测与绿测；命令结果和网络/IP 情况保留在相应 evidence 日志 |
| Go 工具链宿主调用 | 宿主无 `gofmt`，宿主 `bash -lc` 执行 Go 命令提示 `go: command not found` | 使用 `golang:1.27.4` 容器执行 gofmt、全量 go test、vet、build、race；最终结果见 `go-validation-xhttp-fix.log` |


最终候选补充：重复斜杠手工红绿探针中，首次新候选调用遗漏了必需的 `tls` 配置参数，导致参数错位和客户端配置生成失败；该尝试为无效探针，未计入结论。补齐参数后，`//ray//custom//` 编辑结果归一化为 `/ray/custom/`，实际 Xray 客户端连接成功（curl rc=0，577 字节）；详细调用与结果见 `xhttp-repeat-path-debug.log`、`xhttp-repeat-path-f4deaf77-retry2.log` 与 `xhttp-repeat-path-f4deaf77/`。
