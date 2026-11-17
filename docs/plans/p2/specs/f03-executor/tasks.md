# F03 执行器任务清单

对应规格：`docs/plans/p2/specs/f03-executor/spec.md`

- [x] T1 探查实测：容器内跑 `--mode none` 默认/守卫/四传输/`--public-port`/非法 listen，确认 tag、端口、payload、warning、无 Nginx 产物与端口冲突语义（含 none 多传输 `--ws-port` 被忽略）
- [x] T2 编写 `F03_test.py` 的 S1（默认 ws）与 S2（回环守卫、IPv6、非法格式缺口）
- [x] T3 补齐 S3（gRPC/xHTTP/multi/冲突）与 S4（公开端口）、S5（覆盖与边界），每个拒绝场景断言零写盘
- [x] T4 实现 S6 真实 Bash 执行（`config/vless_tls.json` 副本 + 提取函数 + `ws_backend_listen_addr=10.10.0.5`），产出 `bash-result.json` 与 14 条 `baseline-compare.json`
- [x] T5 修复 S3 暴露的监听传播缺陷：`extraListenFor` 对 `ModeNone` 返回 `spec.Listen`，picker 仍探测回环；新增 `TestGenerateNoneMultiTransportHonoursListen`；`go test ./internal/...` 全绿
- [x] T6 构建 `golang:1.27.4` 二进制，固定 digest 容器内连跑两次：159 passed / 0 failed（0.41s、0.43s）
- [x] T7 证据整理与 hygiene：`meta.txt`、`commands.log`、`observed.json`、`bash-result.json`、`baseline-compare.json`、`f03-work/`；`check_evidence_hygiene.py` 0 findings
- [x] T8 更新三处计数：`tasks.md` G-3（20/28，剩余 8）、features `README.md`、`FUNCTION_PARITY.md` F03 行
- [x] T9 单独提交 `test(parity): add F03 no-tls loopback executor`（d591b55b；只含本项文件；不 push/tag/merge）

## 执行顺序与边界

- T1 必须先于 T2：非法地址是否被接受等反例以实测定性，不按猜测断言。
- T3 的多传输非回环用例是 T5 的前置证据；未确认前不得先改生产代码。
- 任何一次容器运行都必须使用固定镜像 digest 与真实 `xray` 二进制；不得用 stub 替换 `-test`。
- 若某项断言与实测不符：先记录 `divergent-*`/`gap`，再决定是否修 Go；不允许删断言或放宽到恒真。
- 不修改 `install.sh`；不接触真实 VPS 与公网 CA。
