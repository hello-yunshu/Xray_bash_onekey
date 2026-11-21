# 最终审计 · 2026-11-19

> 2026-11-20 复审追加见 §8：在 `9f66b22a` / `f217a2fa` / `102f52e1` / `1cd248e6`
> 修复分享归属、Host/SNI 分离、证据卫生、F28 私钥泄漏、`config edit --host`
> 与 OPS-32 恢复判定；结论仍为发布/合并 **NO-GO**。

## 1. 结论

| 范围 | 结论 | 理由 |
| --- | --- | --- |
| 合并到 `main` | **NO-GO** | 独立 VM 未验收、OPS 29 行无双端证据、真实多版本 Xray 矩阵未跑 |
| 发布正式版本 / tag | **NO-GO** | 同上；且任务书禁止本轮发布 |
| 合并到 `develop/go-native` | **NO-GO（2026-11-20 复审后）** | 代码与容器级证据已全绿，但独立 VM/公网 ACME 等外部门禁仍未补齐；保持 draft PR |
| 生产 VPS 操作 | **禁止** | 任务书约束 |

本轮已把工作分支推送到 origin 并创建 draft PR #182（base `develop/go-native`），仅用于触发真实 CI；
未合并 `main`/`develop/go-native`、未创建 tag/release、未连接生产 VPS。

## 2. 交付物

| 交付物 | 状态 | 路径 |
| --- | --- | --- |
| S0 基线 | 完成 | `docs/go-evolution/hardening/00-baseline.md` |
| P1 安全/恢复报告 | 完成 | `docs/go-evolution/hardening/01-security-recovery.md` |
| P2 CI/双端报告 | 完成 | `docs/go-evolution/hardening/02-ci-and-bash-go-parity.md` |
| P3 原生体验报告 | 完成 | `docs/go-evolution/hardening/03-native-experience.md` |
| 验收矩阵 | 完成 | `docs/go-evolution/hardening/ACCEPTANCE_MATRIX.md` |
| 最终审计 | 完成 | `docs/go-evolution/hardening/FINAL_AUDIT.md` |
| 执行轨迹 | 完成 | `docs/go-evolution/hardening/TRAE_PROGRESS.md` |
| 机器可读验收看板 | 完成 | `docs/go-evolution/hardening/acceptance.json` |

代码提交：

| SHA | 内容 |
|---|---|
| `59adbce4` | S0 基线报告 |
| `8ac1385f` | P1：备份/恢复事务化、符号链接边界、repair 锁 |
| `4c986c26` | P2：CI 红灯修复、ANSI 历史分类、signed-stage 冒烟 |
| `04d06cf4` | P3：doctor 证据分级与真实客户端探针、preflight readiness、hot-user 探针断言 |
| `43ceb680` | P1 加固：六个持久点 SIGKILL、ENOSPC/EROFS/EACCES、并发锁/坏 journal/第三方文件/canary；P3 传输参数化 |
| `1b519028` | P2：M10 内联 relay doctor 探针；OPS-21 离线 geo 提示 |
| `911f91d2` | doctor：relay 以 nginx unit 判定健康；relay `--client-probe` |
| `de43a36b` | P3 runner：修复 `set -u` 下空数组展开（原始安装路径） |
| `4c9705a9` | P1：`backup create --include-geodata` 在可选 GeoData 树缺失时不再整体失败 |
| `4ab08050` | P1：双容器冷恢复用例（源机销毁、目标机恢复、权限/验证器/服务/真实客户端） |

## 3. P0/P1 缺陷闭环

| ID | 原缺陷 | 处理 | 复核 |
| --- | --- | --- | --- |
| B-01 | `Verify` 不拒绝额外条目、不校验 mode、无大小上限 | 重写为流式、精确集合、mode/size、压缩炸弹边界 | `internal/backup/hardening_test.go` |
| B-02 | `Create` 直接写最终路径、允许写入受管树 | 临时文件 + `os.Link` 不覆盖 + `Verify` 失败回滚 + 拒绝受管树内归档 | `TestCreate*` |
| B-03 | `Restore` 无锁、无 journal、无条件删除旧文件、SIGKILL 不收敛 | 共享 flock + 持久化 journal + 快照 + `recover` + 真实 SIGKILL 注入 | `TestRestoreHardKillAtEveryDurablePointConverges`（6 点）、`TestRestoreRollsBackOnFilesystemErrors`、`TestRestoreRefusesWhileAnotherProcessHoldsLock`、`TestRecoverRefusesCorruptJournalWithoutTouchingFiles` |
| B-04 | repair 跟随符号链接、正式运行无共享锁 | 逐级 `Lstat`、`O_NOFOLLOW`、正式运行持锁、dry-run 零写入 | `internal/repair/hardening_test.go` |
| B-05 | 恢复暂存 `filepath.Join` 可越界 | 组件级安全路径解析 + 受管根约束 | `TestRestoreRefusesSymlinkComponent`、`TestRestoreRejectsTraversalWithoutTouchingCanary` |

P1 定向测试共 41 个 `Test*` 函数（`internal/backup` 33、`internal/repair` 8），其中本轮新增 8 个测试与 9 个子测试点；
P3 新增客户端探针与 readiness 测试。当前 SHA 全量 `go test -count=1 ./...` 25 个包 `ok`、0 FAIL（见第 7 节）。

## 4. CI 红灯闭环

| 红灯 | 根因 | 修复 | 本轮证据 |
| --- | --- | --- | --- |
| `test_unverified_release_must_fail` | 测试把“账本全 PENDING”写死 | 在隔离副本上重写账本状态，分别验证 pending rc=2 与 signed rc=3 | `Ran 10 tests ... OK` |
| `check_preview_gate.py` 在签收后必红 | 强制账本 28 PENDING | 新增 signed 阶段检测；signed 时运行 `check_signed_stage.py`，无发布权限 | 同上；`actionlint` rc=0 |
| `Test Install` ANSI 扫描 | 历史日志与 fixture 混为一类 | 按 `production-output-risk/docs/test-fixture/canonical-payload/historical-evidence` 分类 | `73 passed, 0 failed`，`production-risk=0` |

真实 GitHub Actions：`CI_RUN` PASS。draft PR #182 在 SHA `4f12543e` 上六条工作流全部 success：
stage gate `44527239779`、preview `44527239752`、release qualification `44527239918`、
real-root `44527240183`、Test Install `44527240075`、Privacy Guard `44527239956`。
首轮 `4ab08050` 的 stage/Privacy 失败是文档写法被 IPv6 卫生规则命中，修正后复跑通过。

## 5. 仍未闭合的风险

| 风险 | 等级 | 现状 | 发布前要求 |
| --- | --- | --- | --- |
| 冷恢复（容器） | P1 | 已闭合 | `20261119-cold4`：源容器销毁后目标容器恢复，8/8 + 19/19，真实客户端通过 |
| 独立 VM 冷恢复/掉电恢复 | P1 | `BLOCKED` | 至少一次真实 VM 全流程（P3-04） |
| 真实 CI 复跑 | P1 | 已闭合 | PR #182 @ `4f12543e`：六条工作流 success，run id 见 §4 |
| OPS 29 行无双端证据 | P1 | `GO_ONLY_PASS` | 逐项补双端或正式批准安全差异 |
| 纯 Bash ACME（M8） | P1 | `BLOCKED` | 提供 `acme.sh` 与可达 ACME 端点后重跑 |
| 接管/迁移独立 VM | P1 | `PARTIAL` | 容器 R1/R2/INJ 已过（85+26 断言），仍需旧版真实安装 + 独立 VM |
| 真实多版本 Xray 候选矩阵 | P2 | `NOT_RUN` | 缓存至少 2 个真实历史版本并跑 preflight |
| relay 真实客户端探针 | P2 | 已闭合（转发层） | `20261119-m10relay2`：`REAL_CLIENT_PASS`；发布说明须写明这是 HTTP 经 Nginx Stream，不是 VLESS 会话 |
| 全量人工渗透审计 | P2 | `PARTIAL` | 发布前安全评审 |

## 6. 不得使用的表述

- 不得把 `go test` 通过写成“Bash/Go 双端通过”。
- 不得把 `exit 0`、JSON 匹配、Go 单边运行写成 `DUAL_SIDE_PASS`。
- 不得把 `20261119-r1` 中唯一的 INJ 外网失败写成产品回归；已用 `20261119-inj` 重跑并通过。
- 不得把 relay 的 `REAL_CLIENT_PASS` 写成 VLESS 用户会话；它证明的是 Nginx Stream 转发。
- 不得把容器内 systemd 结果写成真实 VM 或生产验证。
- 不得把 `compatible=true` 当作“配置已验证兼容”；必须同时看 `readiness=verified`。

## 7. 复现命令

```bash
# 全量 Go 门禁（当前 SHA 911f91d2）
docker run --rm -v "$PWD:/src:ro" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
  -e GOCACHE=/tmp/gocache golang:1.27.4 bash -c \
  'export PATH=$PATH:/usr/local/go/bin; gofmt -l cmd internal tests; go vet ./...; go build ./...; go test -count=1 ./...'

# CI fail-closed 负例
cd tests/go-parity/parity && python3 -m unittest discover -s tests -v

# ANSI 分类
python3 .github/test/test_color_output.py

# P2 全量矩阵（9 个安装 + 8 个编辑 + 5 个 OPS）
E2E_RUN_ID=<run-id> E2E_CONCURRENCY=4 bash tests/e2e-diff/run_p2_matrix.sh

# 接管/注入
E2E_RUN_ID=<run-id> E2E_PATHS=both bash tests/e2e-diff/run_r1_upgrade.sh
E2E_RUN_ID=<run-id> E2E_PATHS=inj E2E_ONLY=M4 bash tests/e2e-diff/run_r1_upgrade.sh

# P3 真实场景（raw / ws / grpc / xhttp）
E2E_RUN_ID=<run-id> bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=<run-id> E2E_TRANSPORT=ws bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=<run-id> E2E_TRANSPORT=grpc bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=<run-id> E2E_TRANSPORT=xhttp bash tests/e2e-diff/run_p3_hot.sh
```

## 8. 2026-11-20 复审

| 项 | 结论 | 证据 |
| --- | --- | --- |
| F28 Reality 分享失败（CI 35/2） | `FIXED_VERIFIED`：跨 root 元数据不再生效，F28 本地 57/0 | `artifacts/audit-remediation/followup-20261120/c3/f28/` |
| Reality Host/SNI 混用 | `FIXED_VERIFIED`：`serverNames` 只作 SNI，连接地址必须显式 `--host` | `internal/xraycfg/share.go`、`share_metadata_test.go` |
| `config edit` 链接 Host（FUP-08） | `FIXED_VERIFIED`：`--host` 成为唯一拨号地址，E7 13/13、E8 14/14 | `internal/xraycfg/reality_edit_test.go`、`tests/e2e-diff/evidence/fix-20261120-p2h/` |
| `environment.txt` 本机路径 | `FIXED_VERIFIED`：生成器与历史证据均脱敏，新增契约测试 | `tests/go-parity/matrix/test_environment_contract.py` |
| F28 临时私钥进入日志/证据 | `FIXED_VERIFIED`：`redact=True`，fixture root 移出 evidence | `tests/go-parity/parity/features/fixture_support.py` |
| Go 全量门禁 | PASS：gofmt/vet/build/test，`rc=0` | `artifacts/audit-remediation/followup-20261120/c3/gate.rc` |
| 98 项矩阵 | PASS：104 行，54 MATCH + 40 MATCH_CORE_FIELDS + 4 REFUSED + 6 A1，0 GAP，`repo_dirty=0` | `tests/go-parity/evidence/matrix-fix-20261120-clean2/` |
| P2 编辑与 OPS-32 | PASS：E7/E8 全绿；OPS-32 ws/reality 均 PASS | `tests/e2e-diff/evidence/fix-20261120-p2h/`、`.../fix-20261120-p2i/` |
| 真实 CI | 以推送后的 run id 为准；本地不得替代 | GitHub Actions |
| 发布/合并 | **NO-GO**：独立 VM、公网 ACME、多版本矩阵、外部 IPv6、剩余 OPS 双端仍未验证 | — |

**口径要求**：本文件与 `docs/go-migration/audit-remediation/FINAL_AUDIT.md` 必须
同时保持“NO-GO / 不合并”；不得引用旧 SHA 的绿灯替代当前 HEAD 的 CI。

## 9. 2026-11-20 第三轮 Docker 候选（`df3f3838`）

| 项 | 结论 | 证据 |
| --- | --- | --- |
| A1 证书清理 | `FIXED_VERIFIED`：所有权/引用/dry-run/staging+journal；真实 root | `artifacts/go-docker-20261120/a1-*.log`、`certclear_test.go` |
| A2 分享 Host/SNI | `PASS_IMPACT_SCOPED`：候选未触及 share；F28 57/0 为最近绿证 | `share_metadata_test.go` |
| A3 Guard | `FIXED_VERIFIED`：pre-fix `enabled/isolate` → candidate `not-applicable`；真实 nginx 三策略 | `.../a3-guard-redgreen.log`、`smoke-guard-cert-final.log` |
| A4 XHTTP | `NO_DEFECT_SEMANTIC_DIFF`：父提交负例测试通过；真实四交叉 200/301 | `.../a4-prefix-probe.log`、`a4-xhttp-path.log` |
| A5 缓存/OPS-32 | PASS；Test Install 在 `aa4b9da9` CI 通过，根因未定位 | `OPS-32`、`gate-final.log`、run 44725121834 |
| M1–M10 | `DUAL_SIDE_PASS`；M8 `DOCKER_EQUIVALENT_WITH_LIMITS` | `round3-final-20261120-1821-df3f3838/p2/` |
| 冷恢复/R1/P3 | cold 27/27、R1 106/0、P3 62/62 | 对应 evidence 目录 |
| 98 项矩阵 / race | 0 GAP；8 包 race rc=0 | `matrix-20261120-final/`、`race-final.log` |
| OPS 34 / subscripts | INCOMPLETE / NOT_RUN | `case-matrix.csv` |
| 多版本/第二发行版/soak | NOT_RUN | `DOCKER_ACCEPTANCE_20261120.md` |

**结论**：Docker 开发候选 `NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`；正式发布
`NO_GO_NOT_AUTHORIZED`。保持 draft PR；不合并、不打 tag、不发布。

## 10. 2026-11-21 独立双端验收与三轮闭环（产品代码 `96f77eae`）

| 项 | 结论 | 证据 |
| --- | --- | --- |
| P0 证书清理误删 | `FIXED_VERIFIED`：HEAD 7 项红 → 修复后 10/10，真实 root Nginx + Xray | `artifacts/intake-20261121/s1/certclear-*.log` |
| P1 Guard 状态误报 | `FIXED_VERIFIED`：HEAD 3 项红 → 修复后 6/6 | `artifacts/intake-20261121/s1/guard-*.log` |
| P2 XHTTP 空白输入 | `FIXED_VERIFIED`：空白/首尾空白拒绝，负例测试通过 | `internal/xraycfg/edit_test.go` |
| P1 四摘要不一致 | `FIXED_VERIFIED`：34 行账本自动生成，逐行含 Bash 入口/Go 命令/证据 | `tests/e2e-diff/ledger.json` |
| M1–M10 | 10/10 `DUAL_SIDE_PASS`；M8 为 `DOCKER_EQUIVALENT_WITH_LIMITS`（ED-C14） | `FINAL-M2-20261121/p2/install-matrix.md` |
| E1–E8 | 100/100 检查通过（Go-only，Bash 无非交互入口） | `FINAL-M2-20261121/p2/E*/go/edit/checks.json` |
| OPS 34 行 | 11 双端 + 22 Go-only + 1 Bash-only，0 FAIL / 0 BLOCKED / 0 NOT_RUN | `tests/e2e-diff/ledger.json` |
| OPS 真实 root | 26/26：OPS-08 六策略、OPS-27 十用例、OPS-17b 1.27.5→1.30.6 | `FINAL-RR-20261121/realroot/assertions.txt` |
| OPS-04/10 强度 | 双端真实新端口 L4、Go share 端口、幂等重放、越界拒绝且零写入；`nginx -t` 与片段字节比较 | `FINAL-M2-20261121/p2/OPS-04`、`OPS-10` |
| S4–S9 | S4 9/9、S5 12/12（Pebble 真签发）、S6 17/17（本地校验和 origin，含坏字节/截断）、S7 6/6 + 签发 BLOCKED、S8 13/13、S9 6/6 | `FINAL-S-20261121/s/`、`FINAL-S6D-20261121/s/assertions.txt` |
| R1/R2/I1/I4/INJ | 106/0；真实历史 Bash 3.3.2 13/0；3.3.3 52/0（`source=/seed/historical.sh`） | `FINAL-R2-20261121/`、`FINAL-HIST2-20261121/`、`FINAL-HIST3B-20261121/` |
| 冷恢复 / P3 | 27/27；raw/ws/grpc/xhttp 各 62/62 | `goevo-coldrestore-FINAL-COLD-20261121/`、`goevo-p3-*` |
| 多版本 / Debian 12 | 3 版本配置+部署+客户端 PASS；M1/M4/OPS-09 双端 PASS | `FINAL-VERSIONS2-20261121/`、`FINAL-DEBIAN12-20261121/` |
| 31 样本 soak + 调度 | 1849s、31/31 客户端 ok、timer 两周期、GeoData 校验和匹配 | `FINAL-SOAK-20261121/soak/soak.json` |
| 98 项矩阵 | 104 行 0 GAP，`repo_dirty=0` | `tests/go-parity/evidence/matrix-20261121/` |
| F28/F08/F18 最终 SHA | 57/0、129/0、178/0（干净 worktree + 真实 xray） | `artifacts/intake-20261121/s1/features-final/run.log` |
| amd64 | `linux/amd64` 构建 + `internal/xraycfg`/`internal/deploy` 测试通过 | `artifacts/intake-20261121/s0/amd64-gate.log` |
| 环境证据 | OS/systemd/bash/nginx/xray 版本与 sha256；Bash pin 短 SHA 无法本地解析 | `artifacts/intake-20261121/s0/environment-final.json` |
| 真实 CI | 7/7 success @ `96f77eae`；证据/文档 head `c3d4f904` 7/7（stage/preview/release/real-root/Test Install/Privacy/Rill） | PR #182 |

**未闭合（不得视为通过）**：

- 冷恢复只覆盖 Reality；TLS/relay/multi 代表配置与 SIGKILL/ENOSPC/EROFS/lock/
  证书缺失/部分恢复的端到端故障注入未做（`NOT_DONE`）。
- E1–E8 为 Go-only；Bash 用户增删、shortId/私钥菜单未逐一驱动（`NOT_DONE`）。
- XHTTP 空白输入已修；尾斜杠/重复斜杠的真实数据面未在最终 SHA 重跑（`NOT_DONE`）。
- Test Install 历史静默退出仍为 `PARTIAL`，本轮未复现，不以本地结果替代 CI。

**本轮结论**：Docker 可验证的适用项（矩阵、OPS、S、R、冷恢复、P3、版本、
发行版、soak、最终 SHA 特性、amd64）已在本机容器真实双端跑绿；但上述三个
`NOT_DONE` 类别仍未完成，因此 Docker 开发候选保持
`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`。正式发布、合并 `main`/`develop/go-native`、
tag 为 `NO_GO_NOT_AUTHORIZED`（独立 VPS、公网 ACME、外部 IPv6 未验证，且任务书
禁止）。详见 `docs/go-migration/audit-remediation/DOCKER_ACCEPTANCE_20261121.md`。
