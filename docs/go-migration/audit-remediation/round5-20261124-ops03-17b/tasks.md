# Tasks：OPS-03 / OPS-17b 修复

对应 spec：`./spec.md`
默认方案：OPS-03 = Plan A（驱动两步走，产品零改动）；OPS-17b = 真实版本切换。

## 前置

- [x] 批准 spec §9 的三项（Plan A、真实版本切换 + stub 退化、允许新 run id 重跑与 push）。
- [x] 确认仍在 `work/go-hardening-parity-20261119`，候选仍为 `50415119`（HEAD 为 docs-only 的 `d756dfff`）。
- [x] 选一个未使用的 `E2E_RUN_ID`（`round5-ops03c-082104`、`round5-obsc4-085130`）。

## T1 — OPS-03 驱动改造

- [x] `tests/e2e-diff/run_p2_matrix.sh::ops_users_job()`：
  - Bash 在 `removed` 之后补 `ops_snapshot cleaned` + `ops_health cleaned`。
  - Go 在 `removed` 之后执行 `12-short-id-clean --root / xray config edit --short-id-remove "$OPS_USER_SHORT_ID" --yes ...`，再拍 `cleaned` 并做健康检查。
  - 保留 `removed` 快照，作为「Go 残留」的现场证据。
- [x] 判定器：
  - `obs` 增加 `cleanedSids`、`cleanupRc`。
  - `shortid_clean` 改为比较 `cleanedSids == beforeSids` 且 `cleanupRc == 0`。
  - `details` 增加 `shortIdResidueAfterRemove`、`cleanupCommand`、`cleanedShortIds`。
  - `shortid-difference.json` 增加 `remediation` 字段。
- 验证：`bash -n tests/e2e-diff/run_p2_matrix.sh`。

## T2 — OPS-17b 夹具与调用

- [x] 新增 `seed_old_nginx_binary()`（优先 `nginx:1.27` 真二进制，失败退化 stub 并写 `previous-binary.txt`）。
- [x] Bash：把 `/etc/idleleo/conf/install_config.json` 的 `nginx_build_version` 改为 `1.27.0`。
- [x] 生成 Go 格式 manifest `$WORK/seed/nginx/go-nginx-manifest.json`（component/version/url/sha256/size，取自 `seed_nginx_cache` 产物）。
- [x] 替换调用：Bash `run 180 '5\n3\n\n\n0\n'`（多出空行应答 IP 提示）；Go `update nginx --manifest /seed/nginx/go-nginx-manifest.json --container --json`（去掉 `--no-restart`）。
- [x] 采集更新前后 `nginx -v`、备份目录、`updated` 健康检查、`previous-binary.txt`。

## T3 — OPS-17b 判定器

- [x] 删除 OPS-17b 的硬编码 BLOCKED。
- [x] 按 spec §5.2-D 计算 PASS/FAIL；只有前置包/`expected-version.txt` 缺失才 BLOCKED。
- [x] PASS 需要 `details`，含两侧 before/after、backup、health、`goReport`、`previousBinary`。
- [x] Bash 更新成功后会删除备份目录，判定器以 `run.out` 的 `备份旧版` 作为等价证据；`ls` 的报错文本不再被误判为备份。
- [x] OPS-17a 保持原样。

## T4 — 定向实跑 OPS-03

- [x] 新 run id，只跑 users job（`round5-ops03c-082104`）。
- [x] 断言：两侧 `cleaned.short-ids.txt == before.short-ids.txt`；Go `12-short-id-clean.rc=0`；`cleaned` 健康通过。
- [x] `config edit` 需要把 `--root /` 放在 `xray` 之前（子命令不认 `--sandbox/--root`）。

## T5 — 定向实跑 OPS-17b

- [x] 同一或另一新 run id，跑 observe job（`round5-obsc4-085130`）。
- [x] 断言：Bash `run.rc=0` 且输出含 `Nginx 更新: v1.27.0 → v2026.10.15.7679`；两侧 `nginx-after=1.30.6`；Bash 日志 `备份旧版` + Go 备份目录存在；`updated` 健康 rc=0；Go JSON `previousVersion=1.27.5`、`newVersion=1.30.6`。
- [x] 两侧旧二进制均为真实 `nginx:1.27`（`previousBinary=real`），未退化 stub。
- [x] 失败不得手改结果；保留 `run.out/run.err` 现场。

## T6 — 账本与报告

- [x] 用既有账本生成器重建 `tests/e2e-diff/ledger.json`（`--allow-repo-write`），核对 OPS-03/OPS-17b 与总计数。
  - 两行均在 `50415119` 上重放：OPS-03 `round5-cand-ops03c-131954`、OPS-17b `round5-cand-observe-130808`。
  - OPS-03 通过 `E2E_SUPERSEDES=round4-full-50415119` + `E2E_FIXED_BY=51db24e6…` 走设计内的 supersede 机制替换旧 FAIL。
  - 重建结果：DUAL 21、FAIL 12、GO_ONLY 1、BLOCKED 0（共 34 行）；OPS-01/02 未受影响。
- [x] 更新报告与证据索引：写明 OPS-03 的两步差异、OPS-17b 的 before/after/backup/health。
- [x] 确认没有把任何 DIFF 自行改成 PASS（仅提交两侧真实 PASS 的两行）。

## T7 — 提交与推送

- [x] 提交驱动改动 + 新证据（证据单独提交，避免漏 stage）。
- [x] push 到 `work/go-hardening-parity-20261119`。
- [x] 回报：目标行最终状态、证据路径、剩余未闭合项。

## 完成定义

- OPS-03 与 OPS-17b 在账本中的状态由真实证据决定（PASS 或带原因的 FAIL/BLOCKED）。
- 报告中的每条结论都能指向具体证据文件。
- 产品代码在 Plan A 下未改动，候选哈希不变。
