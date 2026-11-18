# 收口任务：推送、提交归并、深度清理

前置：批准 `docs/plans/p2/specs/finalize-release/spec.md` 中 D1–D4 决策。
本轮实际采用 D1=A（环境无法恢复，按 spec 第 4 节 C 的退路执行）、D2=A、D3、D4。

## 提交归并

- [x] T1 提交归并 16 → 13，树与 `dea46bb9` 逐字节一致（`git diff --quiet`）
- [x] T2 `--force-with-lease` 推送 `dea46bb9...b99b1864`
- [x] T3 备份分支 `backup/pre-squash-20261118` → `dea46bb9`

## 清理

- [x] T4 删除 7 个中间 evidence run
- [x] T5 删除 `/tmp/e2e-*`（约 3.2G）、旧日志、`ops21-diag`、`idleleo-f*-build`
- [x] T6 删除本项目 10 个遗留容器
- [x] T7 在 `b99b1864` 上重跑全量并实测阻塞（容器无出网），中止并删除该 run 容器与网络

## 环境（D1=B 的前置，本轮未满足）

- [ ] T8 恢复 OrbStack 容器出网；验收：
      `docker run --rm idleleo-e2e:24.04 curl -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1` 返回 2xx/3xx
      —— 实测 `000`，`getent hosts` 失败；D1 因此退回 A

## 证据（D1=A）

- [x] T9 T（重跑）不适用：容器无出网，`M4/bash/install.rc=124`、`M4|M5/go/install.rc=1`
- [x] T10 核对 `20261118-0605-full/p2/install-matrix.md`：本轮列无 BLOCKER / HARNESS-ERROR，
      OPS-19/21/09/31/32 PASS，`OPS-21/ops.json` 双侧 `status=pass`、`failed=[]`
- [x] T11 记录取证口径：`run.json.commit=47a370e5`，修复内容在 `21750b7d`，
      树与 `dea46bb9`/`b99b1864` 一致；写入 `docs/plans/p2/closeout-report.md`
- [x] T12 选定证据 `20261118-0605-full`，只 `git add` 该目录
- [x] T13 提交 `944ebeb1 test(e2e): archive the final full-matrix evidence`
- [x] T14 删除剩余过期证据：`20261118-0640-e5`、`20261118-final-b99b1864`

## 推送与 gc

- [x] T15 删除 `/tmp/reorder_todo.py`、`/tmp/e2e-final-b99b1864.out`、`/tmp/e2e-20261118-final-b99b1864`
- [x] T16 删除 `backup/pre-squash-20261117`，保留 `backup/pre-squash-20261118`
- [x] T17 `git push origin develop/go-native`（`b99b1864..944ebeb1`）
- [x] T18 `git gc --prune=now`
- [x] T19 终检：`git status` 空、`git diff origin/develop/go-native HEAD` 空、
      `docker ps -a` 无本项目遗留、无 `e2e-*` 网络、`/tmp` 无本项目 `e2e-*`

## 验收

- [x] 判定汇总无 BLOCKER / HARNESS-ERROR，未登记差异 0
- [x] 证据 commit 与 HEAD 的差异已在提交说明与 closeout 写明（D1=A 允许的差异）
- [x] `install.sh`、G-6 账本未改

## 遗留

- [ ] E5 驱动的 30s 结算预算与 `nginx-reload-diag.txt` 尚未在任何归档运行中执行；
      需容器出网后单跑 `E2E_ONLY=E5` 补证
