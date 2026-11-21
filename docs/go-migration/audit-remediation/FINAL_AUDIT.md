# 最终审计与整改结论（2026-11-19）

> 分支 `work/go-hardening-parity-20261119`，代码提交
> `4527b721fda1dee39545f63ae35f27f9f5078e4f`。未合并 `main`，未发布任何 Release，
> 未接触生产 VPS，未使用真实用户数据。未读取任务书中的外部 ChatGPT 链接。

## 1. 结论摘要

| 范围 | 结论 |
| --- | --- |
| P0-A 中转绑定/公网暴露 | `ALREADY_FIXED_VERIFIED`：真实 managed Nginx `nginx -t` 4/4，回环绑定跨容器拒绝、通配可达 |
| P0-B TLS 分享拓扑 | `FIXED_VERIFIED`（2026-11-20 复审加强）：元数据仅在路径+SHA 归属成立时消歧；Reality 强制显式 Host；10 个回归用例；F28 pre-fix 35/2 → 57/0 |
| P0-C 迁移/恢复资源安全 | `ALREADY_FIXED_VERIFIED`：6 个 Bash 样本扫描零写入，prepare/recover 不碰运行时 5 项，故障注入全绿 |
| P1-A 传输/元数据覆盖 | `FIXED_VERIFIED`：9 个矩阵场景 Go/Bash/L4 全 `MATCH`；历史 98 项矩阵复跑 `0 GAP`；OPS Go sweep 36 PASS；5 个 OPS 双端复跑 PASS |
| P1-B 事务性部署 | `ALREADY_FIXED_VERIFIED`：5 个回滚用例通过，失败不隐瞒 Nginx 残留 |
| P1-C DNS/网络可复现 | `ALREADY_FIXED_VERIFIED`：全量测试在 `--network none` 下通过 |
| P1-D 长期运行/所有权 | `ALREADY_FIXED_VERIFIED`：`-race` 与 fail2ban/日志/任务用例全绿 |

**发布判断：NO-GO。** 代码整改与容器级证据通过，但独立 VPS、公网 ACME（纯 Bash）、
多版本 Xray/Bash 矩阵与外部 IPv6 仍未验证；任务书也明确禁止本轮发布。
**合并判断：NO-GO。** 保持草稿 PR，等待上述实机门禁；不合并 `main` 或
`develop/go-native`。**PR 判断：可继续草稿评审**，本提交只包含一个 CLI 修复、
回归测试与可复核证据。

## 2. 逐条对照任务要求

| 要求 | 证据 | 结果 |
| --- | --- | --- |
| 读取审计整改任务并执行，不重写计划 | 规格与任务清单 `.trae/specs/go-audit-remediation-20261119/`；`AUDIT_ISSUES.md` 逐条映射原审计 | 满足 |
| 先 S0/阶段 A 基线核实 | HEAD、基线 `9b965843`、工具链/镜像 digest、测试入口均记录 | 满足 |
| P0 优先修复 | P0-B 修复；P0-A/P0-C 以真实执行复核 | 满足 |
| 实际修改代码 | `internal/cli/xray.go`、`internal/cli/share_metadata_test.go` | 满足 |
| 实际编译 | `go build ./...` 退出码 0 | 满足 |
| Docker 内 Bash/Go 对照 | 9 场景 × 双端 × 双轮 × L4（P2 SHA `4527b721`）；98 项矩阵在 `86d810e5`、5 个 OPS 双端在 `1cd8b98c` 重跑 | 满足 |
| 真实 `nginx -t` / 数据面 | P0-A managed Nginx；P2 L4 真实转发 | 满足 |
| 故障注入 | 31 PASS / 0 FAIL：无 root、只读、ENOSPC/EROFS/EACCES、断网、过期证书、损坏配置、端口占用、重复执行、并发、SIGKILL、陈旧锁、回滚失败、迁移接管/回滚 | 满足 |
| 不降低测试标准 | 网络瞬时失败保留为 `BLOCKER` 并单独重跑；`NOT_RUN` 未计 PASS；98 项矩阵只修正固化了旧缺陷的端口断言，未跳用例 | 满足 |
| 五份指定文档 | `AUDIT_ISSUES.md`、`REMEDIATION_PLAN.md`、`PARITY_MATRIX.csv`、`TEST_EVIDENCE.md`、`FINAL_AUDIT.md` | 满足 |
| `artifacts/audit-remediation/` | 两个证据脚本、P0-A/P0-C 原始产物、Go/Bash 日志、脱敏配置样本、`summary.json` | 满足 |
| 不合并 main / 不发布 / 不碰生产 | 仅本地分支提交；无 tag/release/merge | 满足 |
| 不声称读取外部链接 | 本文与追踪表均明确未读取 | 满足 |

## 3. 关键证据链

1. **P0-B 红测 → 修复 → 绿测**：注释回填调用后 TLS 用例输出
   `security=none`、`sni=127.0.0.1` 并 FAIL；恢复后 6/6 PASS。说明测试不是
   “跟着实现写”而是覆盖真实缺陷。
2. **P0-A 真实边界**：不是只看 JSON 里有 `listen`，而是启动 managed Nginx，
   在另一容器访问节点 IP；`127.0.0.1`/`::1` 被拒绝、`0.0.0.0` 可达。非法地址
   同时校验退出码与 fragment 哈希不变。
3. **P0-C 真实样本**：6 个 Bash fixture 覆盖 Reality、Reality+Nginx、TLS 多用户、
   自定义 DNS/routing、relay、XTLS 旧模式；扫描前后全树 SHA256 一致。
4. **矩阵可信度**：`install-matrix.md` 明确标注 27 条 L1 路径为注册差异（ED），
   不是静默忽略；L2/L3/L4 分别对照元数据、配置、分享与真实数据面。
5. **失败透明**：M7 首轮 GitHub 资产下载 `unexpected EOF` 被记录为 `BLOCKER`，
   重跑证据单独保存；M8 与外部实机项明确 `NOT_RUN`/`BLOCKED`。
6. **历史矩阵更新**：98 项矩阵原有 20 个 GAP 来自旧端口断言（把 Xray 回环后端
   端口当公网端口）。修正为校验 Nginx `listen <port>` 后复跑为 `54 MATCH /
   40 core / 0 GAP / 4 REFUSED`。这是测试意图修正，产品代码未改，P2 M2/M4 的
   L4 数据面独立证明端口拆分正确。
7. **运营路径**：OPS Go sweep 36 PASS / 0 FAIL；OPS-09/19/21/31/32 已用同一
   P2 驱动在 `1cd8b98c` 双端复跑并 PASS。其余 OPS 仍为单侧，报告不把单侧
   sweep 计为双端 MATCH。

## 4. 残余风险与未执行项

| 项 | 状态 | 影响 | 建议 |
| --- | --- | --- | --- |
| 独立 VPS 迁移与重启恢复 | `BLOCKED` | 无法证明真实 systemd/cron/SSH 断线场景 | 在一次性云主机执行 `04_验收发布与回退.md` 全流程 |
| 公网 CA / 纯 Bash ACME | `BLOCKED` | 证书签发/续期未在公网验证 | 用受控域名与 staging CA 执行 |
| 外部 IPv6 数据面 | `NOT_RUN` | 只验证监听与本地数据面 | 双栈宿主 + 外部客户端复测 |
| 多版本 Xray/Bash 配置矩阵 | `NOT_RUN` | fixture 之外的旧配置可能不同 | 固定历史 Release 建矩阵 |
| OPS 双端复跑 | `NOT_RUN` | 5 行已双端 PASS；其余 18 个 ID 仍只有 Go 单侧 sweep | 继续把剩余 OPS 接入双端驱动，或明确降级为非门禁 |
| OPS-08 / OPS-27 命令 | `FIXED_VERIFIED`（集成待跑） | `241cc99f` 已新增 `xray guard show/set` 与 `xray cert clear`；Go 单测、沙箱 CLI smoke 与真实 `nginx -t`（nginx:1.27-alpine，三种策略）通过；Bash 双端交互仍 `NOT_RUN` | 把两项接入 `run_p2_matrix.sh` 跑 Bash 交互侧 |
| OPS-30 语言切换 | `INTENTIONAL_DELTA_APPROVED` | `allowed-diff`，不要求逐字节一致 | 无 |
| OPS-05/06/07/10/17b/24 | 已有 Go 等价路径 | `xray edit`、`xray tls`、`update nginx`、`schedule run` 覆盖 | 无 |
| 旧 Stats Ubuntu CI 红灯根因 | 未在本轮重查 | 发布门禁仍可能被阻断 | 下载失败日志后单独修复 |

以上任何一项都不能被“容器内通过”替代；因此本轮不宣称可发布。

## 5. 交付物索引

- `docs/go-migration/audit-remediation/AUDIT_ISSUES.md`
- `docs/go-migration/audit-remediation/REMEDIATION_PLAN.md`
- `docs/go-migration/audit-remediation/PARITY_MATRIX.csv`
- `docs/go-migration/audit-remediation/TEST_EVIDENCE.md`
- `docs/go-migration/audit-remediation/FINAL_AUDIT.md`
- `artifacts/audit-remediation/summary.json`
- `artifacts/audit-remediation/p0a_relay_exposure.sh`、`p0c_migration_restore.sh`
- `tests/e2e-diff/evidence/audit-final-20261119/`、`audit-final-m7-20261119/`
- `tests/e2e-diff/evidence/audit-ops-20261120/`
- `tests/e2e-diff/evidence/audit-ops-dual-20261120/`
- `tests/go-parity/evidence/matrix-20261120-final/`
- `artifacts/audit-remediation/logs/ops08-27-smoke.log`（OPS-08/27 CLI smoke）
- `tests/go-parity/matrix/run_matrix.py`（前置端口断言修正）
- `artifacts/audit-remediation/fixtures/`（脱敏配置样本）

## 6. 2026-11-20 复审补充

- **复审起点**：`d13fca44`（任务书基线 `a1056a14` 之后含 OPS-08/27 与证据）。
  **修复提交**：`9f66b22a`、`f217a2fa`、`102f52e1`、`1cd248e6`。
- **新增 P0 修复**：
  1. `xray share` 只在 `--path` 与 `metadata.runtimeConfigPath` 规范化同路径且
     `runtimeSha256` 匹配时使用元数据；跨 root/跨配置不再污染；同路径哈希不符时
     跳过默认值并按运行时配置渲染，同时输出 `stale` 警告（loopback 歧义仍拒绝）。
  2. Reality 不再把 `Install.ServerNames[0]`/`realitySettings.serverNames` 当连接
     Host；缺少 `--host` 直接拒绝。
  3. `environment.txt` 只写 SHA256 值与仓库相对路径；历史 evidence 已脱敏。
  4. F28 不再打印临时 X25519 私钥；fixture root 移出 evidence。
- **测试**：`go test -count=1 ./...`、`go vet ./...`、`gofmt -l` 全绿；F28 57/0、
  F08 129/0、F18 178/0；98 项矩阵 54 MATCH + 40 MATCH_CORE_FIELDS + 4 REFUSED、
  0 GAP；P2 全量见 `tests/e2e-diff/evidence/fix-20261120-p2b/`。
- **最终 HEAD 复验**（`102f52e1`）：E7 13/13、E8 14/14、OPS-21 PASS（修复前
  `HARNESS-ERROR`）、OPS-19 109s PASS、OPS-31 PASS、OPS-32/ws PASS。
- **收尾修复**（`1cd248e6`）：
  1. `xray config edit` 新增 `--host`，`OldShareURI`/`NewShareURI`/`ShortIDLinks`
     统一用它作拨号地址；URL 形式拒绝；Reality 缺 `--host` 时输出降级警告。
     E7/E8 与驱动两侧改为显式 `--host 127.0.0.1`，13/13、14/14 通过。
  2. OPS-32 恢复判定改为窗口尾部 `2*fail_timeout` 内 A ≥ 3 且相邻间隔
     ≤ `fail_timeout`；重跑 ws/reality 均 PASS，p2d 旧数据重算同样 PASS。
- **最终复验**：`gofmt`/`vet`/`build`/`test ./...` 全绿；F28 57/0、F08 129/0、
  F18 178/0；98 项矩阵 `repo_dirty=0`、0 GAP；证据卫生 0/33667。
  详见 [REVIEW_20261120_FOLLOWUP.md](REVIEW_20261120_FOLLOWUP.md) §3。
- **结论不变：NO-GO / 不合并。** 独立 VPS、公网 ACME、多版本矩阵、外部 IPv6、
  剩余 OPS 双端仍未验证；本轮只允许整改分支提交与推送。

## 7. 第三轮 Docker 验收结论（2026-11-20，`df3f3838`）

完整报告：[DOCKER_ACCEPTANCE_20261120.md](DOCKER_ACCEPTANCE_20261120.md)。

### 7.1 已闭环

- **A1 证书清理**：所有权 + 在用引用 + 第三方/账户保留 + dry-run 零写 +
  staging/journal 恢复；真实 root 红绿。
- **A3 Guard**：pre-fix 在无 Nginx guard 时默认 `enabled/isolate`，候选从实际
  Nginx 推导 `not-applicable`；set 先锁后读、journal、聚合回滚错误。
- **A4 XHTTP**：父提交负例测试通过，判定非缺陷；真实 Xray 四交叉 200/301。
- **核心运行**：M1–M10 双端 fresh/幂等/L4/L6；E1–E8 67 项 Go 检查；
  OPS-09/19/21/31/32 双端；冷恢复 27/27；R1/R2/INJ 106/0；P3 62/62；
  98 项矩阵 0 GAP；8 包 race rc=0。

### 7.2 未闭环（阻断 Docker 候选）

1. 34 个 OPS 仅 5 个双端；17 个 Go sweep、2 个 Go 命令、10 个未执行。
2. 9 个 subscripts 未确认。
3. 多版本 Xray/Bash、第二发行版 smoke 未执行。
4. 30 分钟 + 两个调度周期 soak 未执行。
5. M8 Bash 侧为 `BASH_DELEGATES_GO`，纯 `acme.sh` `BLOCKED`。
6. A2/A3 的 Bash 交互与 F28 未在候选 SHA 重跑；Test Install 在 `aa4b9da9`
   通过，但历史静默退出的根因未定位。

### 7.3 双结论

| 范围 | 结论 |
| --- | --- |
| Docker 开发候选 | **NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE**：按 D4，容器必需项未全部完成 |
| 正式发布 | **NO_GO_NOT_AUTHORIZED**：任务书禁止；VPS/公网 CA/外部 IPv6/多版本/soak 未验证 |

不合并 `main` 或 `develop/go-native`，不打 tag，不发布，不操作生产 VPS。

## 8. 2026-11-21 独立双端验收（`96f77eae`）

审计包提出的 P0/P1/P2 缺陷已在真实 Docker 双端运行中复现并修复：

| ID | 缺陷 | 处理 | 证据 |
| --- | --- | --- | --- |
| P0 | cert clear 误删内联/包含/符号链接/变量路径证书 | 引用递归扫描、fail-closed、移动前后双重校验、失败回滚 | `artifacts/intake-20261121/s1/certclear-*.log`（7 红→10/10） |
| P1 | guard 缺 fragment/主配置时误报 active | inconsistent/configured 状态推导 + nginx 存活检查 | `artifacts/intake-20261121/s1/guard-*.log`（3 红→6/6） |
| P2 | XHTTP 空白输入静默接受 | 区分未提供与空白，空白拒绝 | `internal/xraycfg/edit_test.go` |
| P1 | 账本/矩阵/报告失配 | 34 行账本从证据生成，逐行记录 Bash 入口/Go 命令 | `tests/e2e-diff/ledger.json` |

Docker 可验证项：M1–M10 10/10 双端、E1–E8 100/100、OPS 34 行 0 FAIL/
0 BLOCKED/0 NOT_RUN、S4–S9、R1/R2/I/INJ 106/0、历史 3.3.2 13/0、冷恢复
27/27、P3 4×62、3 版本、Debian 12、31 样本 soak + 两周期调度、98 项矩阵
0 GAP、CI 7/7。详见 `DOCKER_ACCEPTANCE_20261121.md`。

**结论**：Docker 开发候选 `GO_FOR_DOCKER_QUALIFIED_CANDIDATE`；正式发布、
合并 `main`/`develop/go-native`、tag 仍为 `NO_GO_NOT_AUTHORIZED`（独立 VPS、
公网 ACME、外部 IPv6 未验证，且任务书禁止）。
