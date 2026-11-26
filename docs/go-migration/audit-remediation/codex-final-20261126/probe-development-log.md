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
