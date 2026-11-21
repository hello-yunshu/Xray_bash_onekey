# 第三轮整改缺陷记录（候选 `df3f3838`）

> 范围：A1–A5。只有“代码 + 真实执行 + 可复核证据”同时成立才标 PASS；
> 未执行的保持 NOT_RUN。A4 经负例探测确认**不是行为缺陷**，按语义差异记录。

## A1 证书清理可能删除非本项目/在用证书

- **复现（pre-fix，`45666732`）**：清理逻辑按文件通配删除，未证明证书归属与在用引用；
  第三方 ACME 域名与账户材料存在被一并删除的风险。红测日志
  `artifacts/go-docker-20261120/a1-red-baseline.log`。
- **根因**：删除对象来自路径约定而非运行时证据；没有 dry-run 计划、没有 staging/journal，
  部分失败会留下半删除状态。
- **修复（`df3f3838`）**：`internal/deploy/certclear.go` 重写为
  1) 只接受可证明属于本项目的证书（ACME 目录域名与配置/元数据归属）；
  2) 扫描 Nginx/Xray/计划任务的在用引用，在用证书拒绝删除；
  3) `--dry-run` 只输出计划，零写入；
  4) 删除先 staging 并写 journal，失败按 journal 恢复；
  5) 保留 ACME 账户与第三方域名目录。
- **绿测**：真实 root 容器（`a1-acme-realroot-final.log`）覆盖在用、第三方、本项目
  三类证书；`certclear_test.go` 先红后绿；部分失败恢复用例通过。
- **残余风险**：Bash 版仍保留旧的通配清理行为，登记为 `INTENTIONAL_SAFETY_DELTA`，
  本轮不强行复现危险行为。

## A2 分享链接的拨号地址/SNI 混用（复核）

- **状态**：上一轮已修复（`9f66b22a`、`1cd248e6`），本轮复核代码路径未被
  `df3f3838` 触及（该提交只改 `internal/xraycfg/edit.go` 的 XHTTP 路径）。
- **绿证**：F28 57/0、F08 129/0、F18 178/0（`c1b14832`/`ce746d8c`）；10 个
  share 元数据单测在仓库中持续运行。
- **限制**：**未在 `df3f3838` 重跑 F28**，按“影响面未触及 + 最近绿证”记为
  `PASS_IMPACT_SCOPED`，不是候选 SHA 的新执行证据。

## A3 Guard show 把缺失状态默认成 enabled/isolate

- **复现（pre-fix，`45666732`）**：构造 `metadata.json` 为 Reality、但根目录下没有
  任何 Nginx guard fragment，执行 `idleleo --root <root> xray guard show` 输出
  `sniGuard=true policy=isolate`。日志
  `a3-guard-redgreen.log` 的 `pre-fix` 段。
- **根因**：`xray guard show` 直接使用 `SNIGuardState{Enabled:true, Policy:isolate}`
  作为默认值，没有读取实际部署的 Nginx；`guard set` 先读后锁，且回滚错误只返回第一条。
- **修复（`df3f3838`）**：
  1) 新增 `deploy.InspectSNIGuard`，从实际 Nginx 主配置、include、decoy/isolate
     fragment 推导 `applicable/status/enabled/policy/denyPort`，并报告 drift/missing；
  2) `guard set` 先取更新锁再读状态，变更写 journal；
  3) 回滚失败聚合所有错误并返回 `RECOVERY_REQUIRED`，不再只报第一条；
  4) 元数据缺失时降级为“运行时证据 + warning”，不再假装已启用。
- **绿测**：同一根目录下 candidate 输出
  `applicable=false status=not-applicable enabled=false`（`a3-guard-redgreen.log`）；
  真实 `nginx:1.27-alpine` 的 isolate/reject/decoy 三策略切换、
  metadata drift/missing include 用例全部 PASS（`smoke-guard-cert-final.log`、
  `ops08-27-real-nginx.log`、`guard_test.go`）。
- **残余风险**：Bash 菜单的 guard 交互未与 Go 做双端对照，Bash 侧 `NOT_RUN`。

## A4 XHTTP 默认 `/xhttp` vs `/xhttp/`

- **调查结论：不是断连缺陷。** 用真实 Xray `26.10.31` 客户端验证
  server/client 路径的四种交叉（`/xhttp`、`/xhttp/` 互相组合）全部被接受，
  HTTP 观测为 200/301；尾斜杠由 Xray 归一化。
- **负例探测**：把候选新增的
  `TestEditXHTTPPathAlwaysHasLeadingSlash` 复制到父提交 `45666732` 运行，
  **测试通过**——父提交的 `Generate` 已在 `xraycfg.go` 补前导 `/`。因此不存在
  可复现的旧行为红测，`df3f3838` 的 `normalizeXHTTPPath` 只是把编辑路径的
  前导 `/` 统一到一处，属防御性整理。证据 `a4-prefix-probe.log`。
- **处置**：按任务书“若只是语义差异就记录，不做全量重写”执行；仅记录
  `Bash 默认 /xhttp`、`Go 编辑输入原样 + Generate 补 /` 的语义差异，不回写
  任何已部署配置。真实客户端证据 `artifacts/go-docker-20261120/a4-xhttp-path.log`。
- **残余风险**：未做“从 Bash 旧配置迁移后逐字段重写”的全量矩阵；本轮只验证路径语义。

## A5 已修复项、缓存、OPS-32 与 Test Install 静默退出

| 子项 | 结果 | 说明 |
| --- | --- | --- |
| 已修复项不回退 | PASS（影响面） | A2 路径未触及；全量单测与 98 项矩阵 0 GAP |
| 缓存不安全 / 断网假成功 | PASS | `--network none` 全量测试 rc=0；缓存 fail-closed 用例在 gate 中 |
| OPS-32 分析器不完整 | PASS | 候选 SHA 上 ws 与 reality 两种故障摘除均 PASS；判定为窗口尾部 `2*fail_timeout` 内 A 达标 |
| Test Install 静默退出 | CI_PENDING | 历史 flake 已记录，本轮未复现、未修复；推送后以 CI 结果为准 |

## 本轮新增的测试基础设施问题（不隐瞒）

1. **M8 Bash 侧不是纯 Bash ACME**：`bash_install.sh` 在 Pebble 模式实际调用
   `idleleo xray cert issue`（`BASH_DELEGATES_GO`）。因此 M8 只能证明
   Go ACME 与 Bash 安装流程协同，不能证明纯 `acme.sh` 路径。
2. **98 项矩阵 `summary.json` 的 `git_commit` 为 `86d810e5`**：矩阵脚本记录的
   是生成该证据时的元数据，实际在候选工作树重跑；报告按“工作树重跑”引用，
   不声称该字段等于 `df3f3838`。
