# 2026-11-20 审计整改复审报告

本报告回答一个问题：`2026-11-20` 目标书列出的整改项是否已在整改分支真实完成，
证据是否可复现，以及当前是否具备合入条件。

## 1. 固定版本与边界

| 项 | 值 |
| --- | --- |
| 分支 | `work/go-hardening-parity-20261119` |
| 目标书基线 | `a1056a14` |
| 复审起点 | `d13fca44`（含 OPS-08/27 与证据） |
| 修复提交 | `9f66b22a`（分享归属、Reality Host、隐私、F28）、`f217a2fa`（E2E 显式 Host）、`b212f1cf`（矩阵快照顺序）、`c65dbd04`（矩阵证据）、`102f52e1`（陈旧元数据降级）。 |
| 证据提交 | 紧随其后的 evidence/docs 提交，见 `git log`。 |
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

## 3. 测试结果（均在最终 HEAD 重跑）

| 套件 | 结果 | 证据 |
| --- | --- | --- |
| `gofmt` / `go vet` / `go build` / `go test -count=1 ./...` | 全绿 | `artifacts/audit-remediation/followup-20261120/c2/go.log` |
| F28（share/show/status 只读契约） | **57 passed / 0 failed** | `.../followup-20261120/f28-final/` |
| F08（Reality / Nginx 生成） | **129 / 0** | `.../f08-final/` |
| F18（QR / 分享输出） | **178 / 0** | `.../f18-final/` |
| F28 pre-fix 红测对照 | 35 passed / 2 failed → 57 / 0 | `.../f28-prefix-excerpt.txt`、`.../f28/`（修复提交时） |
| 98 项 Bash/Go 矩阵 | 104 行 = 54 `MATCH` + 40 `MATCH_CORE_FIELDS` + 4 `REFUSED` + 6 `A1_PASS`，**0 GAP**，`repo_dirty=0` | `tests/go-parity/evidence/matrix-fix-20261120-clean/` |
| P2 M1-M10 | 全部 `allPassed` | `tests/e2e-diff/evidence/fix-20261120-p2b/p2/` |
| P2 E1-E7 | 全部 `allPassed` | 同上 |
| P2 E8 | **14/14 `allPassed`**（修复后 `oldLinkCaptured`、`backupHasOldShareUri` 转绿） | `.../fix-20261120-p2c/p2/E8/go/edit/checks.json` |
| P2 OPS-21 | **PASS**（修复前 `HARNESS-ERROR`，`shareUri=false`） | `.../fix-20261120-p2c/p2/OPS-21/` |
| P2 OPS-09 | PASS | `.../fix-20261120-p2b/p2/OPS-09/` |
| P2 OPS-19 | **PASS**（109s；p2b 同项曾因 GitHub 下载超时 `BLOCKER`） | `.../fix-20261120-p2d/p2/OPS-19/` |
| P2 OPS-31 | **PASS**（reality-balance 增删） | `.../fix-20261120-p2d/p2/OPS-31/` |
| P2 OPS-32 | **ws PASS，reality `BLOCKER`（判定器抖动）** | `.../fix-20261120-p2d/p2/OPS-32/` |
| 证据卫生 | `hygiene: 0 finding(s) in 3560 file(s)` | 本轮扫描 |
| `environment.txt` 契约 | 2 tests OK | `tests/go-parity/matrix/test_environment_contract.py` |

## 4. 剩余问题

### P0

无已知未决 P0。

### P1

1. **`config edit` 的分享链接仍以 SNI 作 Host。** `internal/xraycfg/edit.go` 的
   `shareHostFor` 在 Reality 下返回 `spec.Domain`，而 `OldShareURI`/`ShortIDLinks`
   用它拼客户端链接；当前元数据不保存公网地址，`config edit` 也没有 `--host`。
   E2E 探针固定拨 `127.0.0.1`，所以测试绿，但报告/备份里的链接可能不可直接拨号。
   建议：为 `config edit` 增加 `--host`（或持久化公网地址）后再全部改用显式 Host。
2. **OPS-32/reality 判定器不稳定。** 最终 HEAD 的 `p2d`：ws 通过；reality 的
   bash/go 配置行、warmup、dead-attempt、error log 完全一致，但 go 的恢复窗口里
   backend-a 只零星命中（11/120，最后一次在后段，尾部连续 B 达 10s），判定器要求
   “窗口末尾连续命中 A ≥3 次”因此判 `BLOCKER`（bash 仅以 59.1s 命中险过）。
   Go 与 ws 无关代码未改动，这属于加权 + 多 worker 各自衰减导致的采样抖动。
   建议：判定改为聚合命中率/窗口后段 A 比例，或固定单 worker/共享 zone。
3. **P2 依赖外网下载。** `OPS-19`（GitHub Nginx 包）、`OPS-31`/`OPS-32` 的 Bash 侧
   （apt/nginx 下载）在 `p2b`、`p2e` 出现 `curl: (18) Transferred a partial file` /
   `rc=124`，导致 `BLOCKER`/`HARNESS-ERROR`，与代码无关；`p2d` 同机重试即通过。
   建议 CI 预置包缓存或离线镜像，并把下载失败与行为差异分开记 verdict。
4. **真实 root 场景未覆盖。** F01 需要真实 systemd/root 环境，本轮 `NOT_RUN`；
   独立 VPS、公网 ACME、外部 IPv6、多版本矩阵仍为 `BLOCKED`/`NOT_RUN`。

### P2

1. GitHub Actions 同 HEAD 的 run id 需在推送后回填（Stage Gate、Privacy Guard、
   Release Qualification、Preview/Real-root/Test Install）。
2. `tests/go-parity/evidence/matrix-fix-20261120-clean/` 约 15 MB，已入库；
   后续可考虑压缩或只保留 summary 与失败样本。

## 5. 结论

**NO-GO（不合并、不发版）。**

本轮整改范围内的问题（P0 分享元数据污染、Reality Host/SNI 混用、证据隐私、
矩阵自污染）已真实修复并在最终 HEAD 复验通过；但独立 VPS/真实 ACME/IPv6/
多版本仍无证据，P1-1（`config edit` 链接 Host）尚未收敛，OPS-19/31/32 本轮只拿到
“历史 PASS + 网络 BLOCKED”的组合结论。按目标书“NOT_RUN/BLOCKED 不算通过”，
不具备合入主线或发布的条件。

## 6. 下一步最小动作

1. 推送整改分支，跑同 HEAD 的 GitHub Actions 并回填 run id（不合并）。
2. 修 P1-1：为 `config edit` 引入显式 `--host`（或持久化公网地址），统一
   `oldShareUri`/`ShortIDLinks` 的拨号地址语义。
3. 为 OPS-19/31/32 增加离线包缓存，消除网络抖动对 verdict 的影响。
4. 在独立测试 VPS 上补 F01、真实 ACME、IPv6 与多版本矩阵后，重新评审 GO/NO-GO。
