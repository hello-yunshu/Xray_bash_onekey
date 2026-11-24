# Round5 修复报告：OPS-03 shortId 残留与 OPS-17b Nginx 更新超时

## 结论

| 行 | 本轮结果 | 证据 |
| --- | --- | --- |
| OPS-03 | PASS（两侧均回到 baseline shortId） | `tests/e2e-diff/evidence/round5-ops03c-082104/p2/OPS-03/ops.json` |
| OPS-17b | PASS（两侧 1.27.5 → 1.30.6，rc=0、健康、有备份） | `tests/e2e-diff/evidence/round5-obsc4-085130/p2/OPS-17b/ops.json` |

两行均由真实运行产生，未手改结果，未把任何 DIFF 自行改成 PASS。

## OPS-03：Bash 一步、Go 两步

产品语义保持不变（Plan A，产品代码零改动）：

- Bash `user remove` 直接清掉 inbound 级 shortId：`removedShortIds=1`、`shortIdResidueAfterRemove=0`、`cleanedShortIds=1`。
- Go `user remove` 按文档保留 inbound 级 shortId，需要显式第二步：`removedShortIds=2`、`shortIdResidueAfterRemove=1`，随后
  `xray config edit --short-id-remove <sid>`（`cleanupRc=0`）把 `cleanedShortIds` 拉回 1。

驱动在 `ops_users_job()` 中按此两步执行，并将“Go 需要额外一步”写入 `details`：

- `go.shortIdResidueAfterRemove=1`
- `go.cleanupCommand="xray config edit --short-id-remove"`
- `go.cleanupRc=0`
- `go.cleanedShortIds=1`（与 baseline 的 `beforeShortIds=1` 相等）

## OPS-17b：真实 Nginx 版本切换

两侧都从真实 `nginx:1.27` 二进制开始（`previousBinary=real`），并各自完成一次真实更新：

| 侧 | before | after | 备份证据 | 健康 |
| --- | --- | --- | --- | --- |
| Bash | 1.27.5 | 1.30.6 | 更新前 `备份旧版` 日志（成功后按产品逻辑删除备份目录） | rc=0 |
| Go | 1.27.5 | 1.30.6 | `/etc/idleleo/backup/nginx-1.27.5-1795481706750492059` | rc=0 |

Go JSON 同时给出 `verified=true`、`restarted=true`、`health=true`。Bash `install_config.json` 的 `nginx_build_version` 更新为 `2026.10.15.7679`。

驱动改动：

- `seed_old_nginx_binary()`：从 `nginx:1.27` 提取真实二进制；不可用时退化为 stub 并写 `previous-binary.txt`。
- `seed_nginx_cache()` 产出的离线包同时生成 Go 侧 manifest（`/seed/nginx/go-nginx-manifest.json`）。
- 菜单输入序列为 `5 → 3 → 空（IP 提示默认）→ 空（保留原配置）→ 0（退出重启后的菜单）`，超时 180s。
- 判定器按 rc / 前后 `nginx -v` / 备份 / 健康 / Go JSON 实算 PASS；只有 `expected-version.txt` 或离线包缺失才 BLOCKED。
- Bash 成功后备份目录会被删除，`ls` 的报错文本不再被当作备份证据；改用 `run.out` 的 `备份旧版` 日志行。

## 账本状态

两行都已在冻结候选 `5041511998575851eb5cb16533e9fe999d29d5a8` 上重放，证据 `productCodeSha` 与候选一致：

- OPS-03：`round5-cand-ops03c-131954` → `DUAL_SIDE_VERIFIED / PASS`，并显式声明
  `supersedes=round4-full-50415119`、`fixedBy=51db24e6bacbbac2b0bf9d52de2c702423040456`，
  旧 FAIL 被设计内的 supersede 机制替换。
- OPS-17b：`round5-cand-observe-130808` → `DUAL_SIDE_VERIFIED / PASS`。

重建后的总计数：`DUAL_SIDE_VERIFIED=21`、`FAIL=12`、`GO_ONLY=1`、`BLOCKED=0`（共 34 行）。OPS-01/02 未受影响。

## 实现要点

- 驱动新增 `E2E_SUPERSEDES` / `E2E_FIXED_BY`，把 supersede 声明写入证据的 `run` 块；不设置时两字段为 `null`。
- 本轮一次 OPS-03 重放遇到真实 Reality 握手 EOF（`shortIdClean=False`），未写 PASS，直接重跑；最终 PASS 来自真实成功运行。
- 候选重放在临时 worktree 中完成，产品代码零改动，跑完已移除 worktree。
