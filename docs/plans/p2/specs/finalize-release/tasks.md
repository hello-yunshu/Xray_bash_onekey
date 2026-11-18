# 收口任务：推送、提交归并、深度清理

前置：批准 `docs/plans/p2/specs/finalize-release/spec.md` 中 D1–D4 决策。

## 已完成

- [x] T1 提交归并 16 → 13，树与 `dea46bb9` 逐字节一致（`git diff --quiet`）
- [x] T2 `--force-with-lease` 推送 `dea46bb9...b99b1864`
- [x] T3 备份分支 `backup/pre-squash-20261118` → `dea46bb9`
- [x] T4 删除 7 个中间 evidence run
- [x] T5 删除 `/tmp/e2e-*`（约 3.2G）、旧日志、`ops21-diag`、`idleleo-f*-build`
- [x] T6 删除本项目 10 个遗留容器
- [x] T7 在 `b99b1864` 上重跑全量并实测阻塞（容器无出网），中止并删除该 run 容器

## 待批准后执行

### 环境（D1=B 必须，用户操作）

- [ ] T8 恢复 OrbStack 容器出网；验收：
      `docker run --rm idleleo-e2e:24.04 curl -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1` 返回 2xx/3xx

### 证据（D1 / D2）

- [ ] T9 `E2E_RUN_ID=20261118-postfix-b99b1864 E2E_CONCURRENCY=5 bash tests/e2e-diff/run_p2_matrix.sh`（后台，约 30 分钟）
- [ ] T10 核对 `install-matrix.md`：无 BLOCKER / HARNESS-ERROR，OPS-19/21/09/31/32 PASS，`ops.json` 双侧 `status=pass`
- [ ] T11 核对 `run.json.commit == git rev-parse HEAD`
- [ ] T12 选定证据（D1=A 用 `20261118-0605-full`；D1=B 用新 run），`git add` 仅该目录
- [ ] T13 提交（D2=A）：`test(e2e): archive the final matrix evidence`，提交说明含 run id / commit / 结论
- [ ] T14 删除剩余过期证据：`20261118-0605-full`（B 时）、`20261118-0640-e5`、`20261118-final-b99b1864`

### 清理与推送（D3 / D4）

- [ ] T15 删除 `/tmp/reorder_todo.py`、`/tmp/e2e-final-b99b1864.out`
- [ ] T16 删除 `backup/pre-squash-20261117`，保留 `backup/pre-squash-20261118`
- [ ] T17 `git push origin develop/go-native`
- [ ] T18 `git gc --prune=now`
- [ ] T19 终检：`git status` 空、`git diff origin/develop/go-native HEAD` 空、`docker ps -a` 无本项目遗留、`/tmp` 无本项目 `e2e-*`

## 验收

- [ ] 判定汇总无 BLOCKER / HARNESS-ERROR，未登记差异 0
- [ ] 证据 commit 与 HEAD 一致（D1=B）且可复现（D1=A 需在提交说明与 closeout 中写明差异）
- [ ] `install.sh`、G-6 账本未改
