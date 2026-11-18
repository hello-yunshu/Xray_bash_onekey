# 收口规范：推送、提交归并、深度清理与最终证据

状态：待批准（Spec 模式，未执行任何进一步改动）

## 1. 目标

把 `develop/go-native` 的收尾工作一次做完并留下可复核的证据：

1. 该推送的推送（分支 + 最终矩阵证据）；
2. 合并/整理提交历史，保证重写后代码树与重写前完全一致；
3. 深度清理垃圾（过期证据目录、`/tmp` 工作目录、遗留容器、临时脚本）。

硬约束（继承前序会话）：不伪造证据、不空 `exit 0`、不为换绿改测试、不把 ledger 改成 VERIFIED、不碰真实 VPS/公网 ACME CA、不改 `install.sh`。

## 2. 已完成（无需再次执行）

| 项 | 结果 | 证据 |
| --- | --- | --- |
| 提交归并 | 16 → 13 个提交；`dea46bb9` fixup 进 `21750b7d`，`c26b3cd6` fixup 进 `044c774b`，`e32c95a5` fixup 进 `21750b7d` | `git log --oneline main..HEAD` |
| 树一致性 | `git diff --quiet dea46bb9 HEAD` 通过（TREE_IDENTICAL） | 命令输出 |
| 推送 | `dea46bb9...b99b1864`（forced update） | `git push --force-with-lease=refs/heads/develop/go-native:dea46bb9` |
| 备份分支 | `backup/pre-squash-20261118` → `dea46bb9` | `git branch` |
| `/tmp` 清理 | 删除旧 `e2e-*` 工作目录约 3.2G、旧日志、`ops21-diag`、`idleleo-f*-build` | 剩余仅 `e2e-<当前 run>` |
| 中间证据清理 | 删除 7 个中间 run：`20261117-2145-47a370e5`、`20261118-0320/0445-47a370e5`、`0520/0535/0600-ops21`、`0542-full` | `git status` |
| 遗留容器清理 | 删除本项目 10 个容器：6×`idleleo-preview`、`idleleo-b3`、`p2-help`、`tls-probe`、`c6-e2e-probe` | `docker ps -a` |

## 3. 当前阻塞：Docker 容器无出网（实测）

环境：OrbStack 29.8.2，macOS。

实测结论：

- 容器内 `curl https://1.1.1.1`、真实 GitHub IP（`185.199.111.133` / `140.82.113.3`）、Clash 伪 IP（`198.18.0.30`）全部 `Failed to connect ... after 0 ms`；
- 容器内 `getent hosts raw.githubusercontent.com` 直接失败（Docker 内置 DNS 无上游）；
- 宿主机对 `1.1.1.1` 同样失败，但对 `raw.githubusercontent.com` 返回 200，解析结果为 `198.18.0.30`（Clash TUN 伪 IP 拦截）。

影响（实测，非推断）：以 `E2E_RUN_ID=20261118-final-b99b1864` 在 `b99b1864` 上重跑全量时：

- `M4/bash/install.rc=124`（超时）；
- `M4/go/install.rc=1`、`M5/go/install.rc=1`，日志为
  `Nginx build version unavailable: Get "https://raw.githubusercontent.com/...": dial tcp 198.18.0.30:443: connect: network is unreachable`。

该 run 已中止、容器已删除，证据目录 `tests/e2e-diff/evidence/20261118-final-b99b1864/` 记为无效（不可入库）。

这不是代码缺陷，`run_p2_matrix.sh` 的 `pin_host` 逻辑在出网正常时工作（`20261118-0605-full` 全量通过）。需要在环境侧恢复 Docker 出网后重跑，或改用既有证据。

## 4. 待决策项（批准时请逐项选择）

**D1 最终证据策略**

- A. 参考方案：以 `tests/e2e-diff/evidence/20261118-0605-full`（8.1M，M1–M10/E1–E8/OPS 全 PASS，含 ED-C14/C15）作为最终证据入库，并在提交说明与 `docs/plans/p2/closeout-report.md` 中写明：该 run 的 `run.json.commit` 是重写前的 `47a370e5`，重写后树逐字节一致（`git diff --quiet` 可复现）。
- B. 推荐：恢复容器出网后，用 `E2E_RUN_ID=20261118-postfix-b99b1864` 在 `b99b1864` 上重跑全量，`run.json.commit` 直接等于推送后的 HEAD，再入库。
- C. 两者都做：先按 B 重跑；若环境无法恢复，则退回 A。

**D2 证据提交形态**

- A. 推荐：新增 1 个提交 `test(e2e): archive the final matrix evidence`，父提交为 `b99b1864`（`run.json.commit` 与父提交一致，可核对）。
- B. amend 进 `21750b7d`：会使证据记录的 commit 指向不存在的历史，不推荐。

**D3 备份分支**

- 保留 `backup/pre-squash-20261118`（唯一能回到 `dea46bb9` 的入口）；
- 删除更早的 `backup/pre-squash-20261117`。

**D4 git gc**

- 执行 `git gc --prune=now` 仅在 D3 保留备份分支的前提下进行（备份分支使旧对象仍可达，`--prune=now` 不会删除 `dea46bb9`）。

## 5. 批准后执行清单

1. 环境恢复（D1=B 时，由用户操作，本 agent 不重启 OrbStack、不改 Clash）：
   - 让 OrbStack 容器具备出网（重启 OrbStack 或调整 Clash TUN/DNS），验收命令：
     `docker run --rm idleleo-e2e:24.04 curl -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1` 应为 `200/301/302`。
2. 重跑：`E2E_RUN_ID=20261118-postfix-b99b1864 E2E_CONCURRENCY=5 bash tests/e2e-diff/run_p2_matrix.sh`（约 30 分钟，后台）。
3. 判定校验：`tests/e2e-diff/evidence/<run>/p2/install-matrix.md` 无 `BLOCKER`/`HARNESS-ERROR`，OPS 四项 PASS，`ops.json` 双侧 `status=pass`。
4. 证据入库（D1=A 时用 `20261118-0605-full`）：只 `git add tests/e2e-diff/evidence/<run>`；提交信息注明 run id、commit、结论。
5. 删除剩余过期证据：`20261118-0605-full`（D1=B 时）、`20261118-0640-e5`、`20261118-final-b99b1864`。
6. 清理 `/tmp/reorder_todo.py`、`/tmp/e2e-final-b99b1864.out`。
7. 分支：删除 `backup/pre-squash-20261117`（D3），保留 `backup/pre-squash-20261118`。
8. 推送：`git push origin develop/go-native`；`git gc --prune=now`（D4）。

## 6. 验收标准

- `git status --short` 为空；
- `git diff --quiet origin/develop/go-native HEAD` 通过；
- `report.py` 汇总无 `BLOCKER`、无 `HARNESS-ERROR`，未登记差异为 0；
- `run.json.commit` 等于入库时 HEAD；
- `/tmp` 无本项目 `e2e-*` 残留；`docker ps -a` 无本项目遗留容器；
- `install.sh`、`tests/go-parity/evidence/**/ledger*` 未被改动（`git diff` 为空）。

## 7. 明确不做

- 不修改 `run_p2_matrix.sh` 判定口径或 `expected_diffs.json` 来换绿；
- 不删除其他项目的容器/卷/镜像（`pm-*`、`upnp-*`、`cfi-*`、`docker-classroom-*`、`yingshu-*`、`owrt-*`、`miwifi-*`）；
- 不改 `install.sh`、不改 G-6 账本状态、不触碰真实 VPS/公网 ACME CA；
- 不自动重启 OrbStack 或修改 Clash 配置（会中断用户其他容器）。
