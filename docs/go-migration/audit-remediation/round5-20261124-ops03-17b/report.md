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

## 账本状态与未闭合项

本轮证据的 `productCodeSha` 为 `d756dfff6b5091b2d2a9fea8188297fc50aa23a8`。冻结候选为 `50415119`；两者之间只有 `docs/` 与 `tests/` 提交，产品目录零差异，`idleleo` 二进制 SHA 均为 `9147144e…`。

账本生成器要求证据的 `productCodeSha` 必须等于 `--code-sha`，因此本轮证据不能直接并入锚定 `50415119` 的账本。为遵守“候选不变、不改验收口径”的约束，**本轮没有重建账本**，`tests/e2e-diff/ledger.json` 保持原样，OPS-03 仍显示 FAIL、OPS-17b 仍显示 BLOCKED。

要闭合账本，需要把这两行在 `50415119` 上重放一次（临时 worktree/checkout），生成绑定候选的证据后再重建账本。该操作涉及 git 工作树，需显式批准后执行。
