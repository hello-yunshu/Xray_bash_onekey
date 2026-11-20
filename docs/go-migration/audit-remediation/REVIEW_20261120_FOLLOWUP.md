# 2026-11-20 审计整改复审报告

本报告回答一个问题：`2026-11-20` 目标书列出的整改项是否已在整改分支真实完成，
证据是否可复现，以及当前是否具备合入条件。

## 1. 固定版本与边界

| 项 | 值 |
| --- | --- |
| 分支 | `work/go-hardening-parity-20261119` |
| 目标书基线 | `a1056a14` |
| 复审起点 | `d13fca44`（含 OPS-08/27 与证据） |
| 修复提交 | `9f66b22a`（分享归属、Reality Host、隐私、F28）、`f217a2fa`（E2E 显式 Host）、`b212f1cf`（矩阵快照顺序）、`c65dbd04`（矩阵证据）、`102f52e1`（陈旧元数据降级）、`1cd248e6`（`config edit --host`、OPS-32 恢复判定）。 |
| 证据提交 | `d56e1dac`（门禁/Fixture/E7-E8）、`afe677a3`（矩阵 clean2）、紧随其后的 OPS-32 与文档提交，见 `git log`。 |
| 二进制 | `idleleo 0.2.0-phase04`，`-buildvcs=false -trimpath`，`sha256 42f2de09…`；Xray `26.10.31`，`sha256 59396499…`（`artifacts/audit-remediation/followup-20261120/c3/binaries.sha256`）。 |
| 允许范围 | 仅整改分支提交/推送；**未**合并 `main`/`develop/go-native`，**未**打 tag 发版，**未**操作生产 VPS，**未**强推共享历史。 |

## 2. 修复结果

| ID | 级别 | 问题 | 修复 | 状态 |
| --- | --- | --- | --- | --- |
| FUP-01 | P0 | `xray share` 把默认 `/etc/idleleo` 元数据套到另一个 `--root` 的配置（F28 CI 红：35/2） | 元数据仅在所选 `--path` 与 `runtimeConfigPath` 规范化同路径、且 `runtimeSha256` 匹配时生效；跨 root/跨配置忽略 | FIXED_VERIFIED |
| FUP-02 | P0 | Reality 分享把 `serverNames`（SNI）当拨号地址 | 删除 SNI→Host 回填；Reality 缺 `--host` 直接拒绝；TLS 仍可用运行时 `tlsServerName` | FIXED_VERIFIED |
| FUP-03 | P0 | `environment.txt` 写入 macOS 宿主绝对路径 | 只写 SHA256 值 + 仓库相对路径；历史 evidence 同步脱敏；新增契约测试防复发 | FIXED_VERIFIED |
| FUP-04 | P1 | F28 日志/argv 泄漏临时 X25519 私钥 | `f.run(..., redact=True)`；删除 `x25519 -i` 调用；fixture root 移出 evidence | FIXED_VERIFIED |
| FUP-05 | P1 | F28 `share` 未带 `--root`；Reality 探针无 Host | 补 `--root`；各探针显式 `--host` | FIXED_VERIFIED |
| FUP-06 | P1 | 98 项矩阵首次 `repo_dirty=1` 由输出目录自污染 | 先快照再 `mkdir`；复跑 `repo_dirty=0` | FIXED_VERIFIED |
| FUP-07 | P1 | 直接编辑 `config.json` 后 `xray share` 因哈希不符完全不可用 | 陈旧哈希降级：跳过元数据默认值、按运行时配置渲染并输出 `stale` 警告；loopback 歧义仍返回可操作错误 | FIXED_VERIFIED |
| FUP-08 | P1 | `config edit` 的 `OldShareURI`/`NewShareURI`/`ShortIDLinks` 以 Reality SNI 作拨号地址，报告与备份可能给出不可连接链接 | `EditRequest.Host` 成为唯一拨号地址来源；URL 形式拒绝；Reality 缺 `--host` 时输出降级警告；E7/E8 与驱动两侧显式 `--host 127.0.0.1` | FIXED_VERIFIED |
| FUP-09 | P1 | OPS-32 要求 A 链延伸到恢复窗口末尾，nginx 衰减权重导致的稀疏命中被误判为未恢复 | 判定改为窗口尾部 `2*fail_timeout` 内 A ≥ `stable_min` 且相邻间隔 ≤ `fail_timeout`，规则文案同步 | FIXED_VERIFIED |

## 3. 测试结果

### 3.1 最终复验（代码 `1cd248e6`）

| 套件 | 结果 | 证据 |
| --- | --- | --- |
| `gofmt` / `go vet` / `go build` / `go test ./...` | 全绿（`rc=0`，0 FAIL） | `artifacts/audit-remediation/followup-20261120/c3/{gate.rc,go-test.log}` |
| F28（share/show/status 只读契约） | **57 / 0** | `.../followup-20261120/c3/f28/` |
| F08（Reality / Nginx 生成） | **129 / 0** | `.../c3/f08/` |
| F18（QR / 分享输出） | **178 / 0** | `.../c3/f18/` |
| 98 项 Bash/Go 矩阵 | 104 行 = 54 `MATCH` + 40 `MATCH_CORE_FIELDS` + 4 `REFUSED` + 6 `A1_PASS`，**0 GAP**，`repo_dirty=0` | `tests/go-parity/evidence/matrix-fix-20261120-clean2/` |
| P2 E1-E6 | 全部 `allPassed`（E1 6/6、E2 4/4、E3 4/4、E4 5/5、E5 11/11、E6 10/10 checks） | `tests/e2e-diff/evidence/fix-20261120-p2j/p2/` |
| P2 E7 / E8 | **13/13**、**14/14** `allPassed`（两侧 `--host 127.0.0.1`） | `tests/e2e-diff/evidence/fix-20261120-p2h/p2/` |
| P2 OPS-32（ws / reality） | **PASS / PASS** | `tests/e2e-diff/evidence/fix-20261120-p2i/p2/OPS-32/` |
| 证据卫生 | `0 finding(s) in 33993 file(s)` | 本轮全仓扫描 |
| `environment.txt` 契约 | 2 tests OK | `tests/go-parity/matrix/test_environment_contract.py` |

### 3.2 前序轮次（保留，用于对照）

| 套件 | 结果 | 证据 |
| --- | --- | --- |
| F28 pre-fix 红测对照 | 35 passed / 2 failed → 57 / 0 | `.../followup-20261120/f28-prefix-excerpt.txt`、`.../f28/` |
| P2 M1-M10 | 全部 `allPassed` | `tests/e2e-diff/evidence/fix-20261120-p2b/p2/`（`f217a2fa`） |
| P2 E1-E7（`f217a2fa`） | 全部 `allPassed`（E1-E6 已在 `1cd248e6` 重跑，见 §3.1） | `tests/e2e-diff/evidence/fix-20261120-p2b/p2/` |
| P2 E8（`102f52e1`） | 14/14（`oldLinkCaptured`、`backupHasOldShareUri` 转绿） | `.../fix-20261120-p2c/p2/E8/` |
| P2 OPS-21 | **PASS**（修复前 `HARNESS-ERROR`，`shareUri=false`） | `.../fix-20261120-p2c/p2/OPS-21/` |
| P2 OPS-09 | PASS | `.../fix-20261120-p2b/p2/OPS-09/` |
| P2 OPS-19 | **PASS**（109s；p2b 曾因 GitHub 下载超时 `BLOCKER`） | `.../fix-20261120-p2d/p2/OPS-19/` |
| P2 OPS-31 | **PASS**（reality-balance 增删） | `.../fix-20261120-p2d/p2/OPS-31/` |
| P2 OPS-32（旧判定） | ws PASS；reality `BLOCKER`（判定口径，非行为差异；新分析器重算 PASS） | `.../fix-20261120-p2d/p2/OPS-32/`、`artifacts/audit-remediation/followup-20261120/ops32-reanalysis/` |

## 4. 同 HEAD CI（文档提交 `5f382902`，草稿 PR #182）

> 推送后在 `5f382902` 上触发；代码内容与 `1cd248e6` 相同，后续如需再改代码必须重跑。

| Workflow | Run | 结论 |
| --- | --- | --- |
| Go parity stage gate | [44671935449](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44671935449) | success |
| Privacy Guard | [44671935247](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44671935247) | success |
| Go production parity release qualification | [44671935222](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44671935222) | success |
| Go preview qualification (not for release) | [44671935256](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44671935256) | success |
| Go real-root change acceptance (container) | [44671935218](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44671935218) | success |
| Test Install | [44671935238](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44671935238) | success |

PR #182 保持 **draft**，未合并 `develop/go-native`，未打 tag，未触碰生产 VPS。

## 5. 剩余问题

### P0

无已知未决 P0。

### P1

1. **独立实机场景未覆盖。** 真实 root 由 CI 的
   `Go real-root change acceptance (container)` 覆盖，但独立测试 VPS 上的公网
   ACME、外部 IPv6、多版本 Xray/Bash 矩阵仍为 `BLOCKED`/`NOT_RUN`。目标书禁止
   操作生产 VPS，本轮未提供独立测试环境，因此记为**外部受限、未验证**，不能
   当作通过。

### P2

1. **P2 依赖外网下载。** `OPS-19`（GitHub Nginx 包）、`OPS-31`/`OPS-32` 的 Bash
   侧（apt/nginx 下载）在 `p2b`、`p2e` 出现 `curl: (18) Transferred a partial
   file` / `rc=124`，与代码无关；`p2d`（OPS-19/31）、`p2i`（OPS-32）同机复跑即
   通过。建议 CI 预置包缓存或离线镜像，并把下载失败与行为差异分开记 verdict。
2. **证据体积。** `tests/go-parity/evidence/matrix-fix-20261120-clean2/` 约
   15 MB，已入库；后续可考虑压缩或只保留 summary 与失败样本。
3. **同 HEAD CI 回填。** 代码不变时无需重跑；后续代码变化必须重跑并替换 run id
   （见 §4）。

## 6. 结论

**NO-GO（不合并主线、不发版）。**

整改分支上的代码问题已全部真实修复并复验：P0 分享元数据污染、Reality
Host/SNI 混用、证据隐私、矩阵自污染，以及本轮新增的
`config edit --host`（FUP-08）与 OPS-32 恢复判定（FUP-09）。最终代码
`1cd248e6` 上：本地全量门禁、F28 57/0、F08 129/0、F18 178/0、98 项矩阵 0 GAP
（`repo_dirty=0`）、E1-E6 全绿、E7 13/13、E8 14/14、OPS-32 ws/reality 均 PASS、
证据卫生 0 findings。

仍判 NO-GO 的唯一原因是外部环境项：独立 VPS 的公网 ACME、IPv6 与多版本
Xray/Bash 矩阵没有证据，而目标书禁止操作生产 VPS。按目标书“NOT_RUN/BLOCKED
不算通过”，在这些项目补齐前不具备合入主线或发布的条件。除此之外没有已知的
P0/P1 代码缺陷。

## 7. 下一步最小动作

1. 提供一个独立测试 VPS（非生产），跑公网 ACME、IPv6 与多版本矩阵，回填
   `ACCEPTANCE_MATRIX.md` 的 M8 与 OPS-SWEEP 行。
2. 为 OPS-19/31/32 增加离线包缓存，消除网络抖动对 verdict 的影响（P2）。
3. 外部项补齐后重新评审 GO/NO-GO；在此之前 PR #182 保持 draft。
