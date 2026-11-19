# P1 安全与恢复（2026-11-19）

代码提交：`8ac1385f`（`fix(go): make backup restore transactional and refuse symlink escapes`）
基线：`59adbce4`（S0 报告）

## 1. 修复范围

| 问题 | 位置 | 处理 |
|---|---|---|
| 归档验证接受未声明的额外条目 | `internal/backup/backup.go::Verify` | manifest 与 tar 条目集合必须完全一致；重复路径、缺失、mode/size 漂移均拒绝 |
| manifest 无上限、单文件 `io.ReadAll` 可被压缩炸弹打爆 | 同上 | manifest ≤16 MiB，单条目 ≤1 GiB，解压总量 ≤4 GiB，逐文件流式哈希 |
| gzip 多成员/尾随数据 | 同上 | `Multistream(false)` + 缓冲区与底层文件双重检查 |
| 非规范路径（`a//b`、`..`、反斜杠、绝对路径） | `safeEntryName` / `cleanRel` | 统一拒绝 |
| Create 崩溃留下半成品归档 | `internal/backup/backup.go::Create` | 同目录临时文件 → fsync → `link(2)` 原子占名；失败清理临时文件 |
| 归档可以写进受管树（备份自己） | 同上 | `archiveInsideManaged` 预检拒绝 |
| 受管目录祖先为符号链接时越界读取 | 同上 + `securePath` | 逐级 `Lstat`，任一符号链接即拒绝 |
| Restore 无锁、无 journal、SIGKILL 后不可收敛 | `internal/backup/transaction.go` | 共享更新锁 + `PREPARED/APPLYING/COMMITTED/ROLLED_BACK/RECOVERY_NEEDED` 持久 journal |
| `_ = os.Remove(dst+".restore-old")` 无条件删除既有文件 | 旧 Restore | 删除该逻辑；快照写入独立目录并记录 SHA256/mode/uid/gid |
| 恢复失败无回滚 | `restoreApply` / `restoreFailed` | 逆序回滚并校验快照摘要；回滚失败进入 `RECOVERY_NEEDED`，提示 `backup recover` |
| 服务未重建 | `internal/cli/backup.go::restoreServiceApply` | 真实根上在事务内执行 `nginx -t`、`systemctl restart xray`、`is-active`；失败回滚文件 |
| 跨机冷恢复盲用源 UID/GID | `transaction.go` | 不使用归档中的数字 UID/GID；以目标机 `xray` 组解析，仅 root 执行 chown |
| repair 跟随符号链接 | `internal/repair/repair.go` | 所有路径逐级 `Lstat`；符号链接只报告不改写；`checkTemp` 不删除符号链接 |
| 正式 repair 无共享锁 | 同上 | 非 dry-run 获取 `host.AcquireUpdate`；dry-run 不创建锁文件 |
| change plan 泄露私钥/明文 | `internal/change/plan.go`（既有） | 审阅确认仅输出路径与摘要；`plan_test` 已覆盖，无代码改动 |

## 2. 新增测试（真实执行）

文件：`internal/backup/hardening_test.go`、`internal/repair/hardening_test.go`

| 测试 | 断言 |
|---|---|
| `TestVerifyRejectsUndeclaredEntry` | tar 多出文件 → Verify 失败 |
| `TestVerifyRejectsModeMismatch` | manifest 0644 vs tar 0600 → 失败 |
| `TestVerifyRejectsDuplicateManifest` | 双 manifest → 失败 |
| `TestVerifyRejectsConcatenatedGzipMember` | 两个合法归档拼接 → 失败 |
| `TestVerifyRejectsOversizedManifest` | 声明 16 MiB+1 → 不分配即失败 |
| `TestVerifyRejectsNonCanonicalPath` | `conf//xray` → 失败 |
| `TestCreateRefusesArchiveInsideManagedTree` | 归档写入 conf 树 → 失败且不落盘 |
| `TestCreateLeavesNoPartialArchiveWhenCancelled` | ctx 取消 → 无最终文件、无临时文件 |
| `TestCreateRefusesSymlinkedManagedDir` | conf 为符号链接 → 失败 |
| `TestRestoreRefusesSymlinkComponent` | 恢复不得穿过 symlink 改写外部文件 |
| `TestRestoreRollsBackWhenServiceApplyFails` | 服务激活失败 → 文件回到旧内容、journal `ROLLED_BACK`、快照清理 |
| `TestRestoreRefusesWhileJournalIsInterrupted` | journal `APPLYING` → 拒绝第二次恢复并提示 `backup recover` |
| `TestRecoverPreparedDoesNotTouchFiles` | `PREPARED` 收敛为 `ROLLED_BACK`，文件不变 |
| `TestRestoreHardKillConvergesWithExplicitRecover` | 子进程在 `after-half` 被 **真实 SIGKILL**；journal 为 `APPLYING`；`Recover` 回滚；再恢复成功 |
| `TestRestoreHardKillAtEveryDurablePointConverges` | 六个持久点（`after-prepare`/`after-first-file`/`after-half`/`before-commit`/`before-service`/`after-service`）逐一真实 SIGKILL；每个点 journal 非终端、`Recover` 收敛为 `ROLLED_BACK`、内容回到旧值、再次 Restore 成功 |
| `TestRestoreRollsBackOnFilesystemErrors` | ENOSPC（rename 注入）、EROFS（rename 注入）、EACCES（chmod 注入）均回滚旧内容并留下 `ROLLED_BACK` |
| `TestRestoreLeavesThirdPartyFilesAlone` | 失败回滚只覆盖清单内文件，第三方 `custom.conf` 保持原样 |
| `TestRestoreRefusesWhileAnotherProcessHoldsLock` | 另一进程持有共享更新锁时 Restore 报 “another update”，不进入 APPLYING |
| `TestRecoverRefusesCorruptJournalWithoutTouchingFiles` | journal 非法 JSON 时拒绝收敛，不删除 journal、不改动文件 |
| `TestRestoreRejectsTraversalWithoutTouchingCanary` | 归档含 `../canary` 时 Verify/Restore 拒绝，根外 canary 内容保持 `untouched` |
| `TestRepairRefusesSymlinkedPaths` | cert 目录 symlink → 只报告，外部 key 模式/内容不变 |
| `TestRepairRefusesSymlinkedStagingEntry` | `var/tmp/restore-*` symlink 不被删除 |
| `TestRepairDryRunTakesNoLockAndWritesNothing` | dry-run 不建锁、不改 mode |
| `TestRepairRefusesWhileAnotherUpdateHoldsTheLock` | 锁被占用 → repair 拒绝 |

执行命令与结果（2026-11-19 二次强化后复跑，代码 `911f91d2` 的 `internal/backup` 与 `internal/repair` 内容与 `43ceb680` 相同）：

```bash
docker run --rm -v "$PWD:/src:ro" -w /src -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor \
  -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache golang:1.27.4 \
  bash -c 'export PATH=$PATH:/usr/local/go/bin; go test -count=1 -v ./internal/backup ./internal/repair'
# ok github.com/hello-yunshu/Xray_bash_onekey/internal/backup 0.660s
# ok github.com/hello-yunshu/Xray_bash_onekey/internal/repair 0.002s
# PASS，0 FAIL，退出码 0
```

子测试实测：`TestRestoreHardKillAtEveryDurablePointConverges` 的
`prepared/first-file/half/before-commit/before-service/after-service` 六项全部 `PASS`；
`TestRestoreRollsBackOnFilesystemErrors` 的 `enospc/read-only/permission` 三项全部 `PASS`。

SIGKILL 证据不依赖模拟：子进程通过 `IDLELEO_RESTORE_FAULT=after-half` 调用
`syscall.Kill(os.Getpid(), SIGKILL)`，父测试用 `WaitStatus.Signaled()` 校验信号为 `SIGKILL`。

## 3. 验收边界

| 项 | 等级 | 说明 |
|---|---|---|
| Go 单元/进程级恢复事务 | `LOCAL_RUN` | Docker `golang:1.27.4` 内真实执行，含 SIGKILL |
| 真实 systemd 重启与 `xray -test` | `NOT_RUN` | 本轮未操作生产 VPS；`restoreServiceApply` 只在 `root=="/"` 触发 |
| 跨机冷恢复 | `NOT_RUN` | 需要第二台主机；权限模板已实现，未做双机实测 |
| Bash/Go 双端备份一致性 | `NOT_RUN` | Bash 安装器没有等价 backup 子命令，不构成双端可比 |

## 4. 已知限制

- `Verify` 的硬链接/稀疏文件不保留；归档只恢复普通文件内容与 mode，这是既有契约。
- 快照目录与目标同根时依赖同一文件系统；跨挂载点恢复会退化为“先复制快照再 rename”，不会丢数据。
- `Recover` 只能在目标文件仍可写时回滚；磁盘只读等场景保持 `RECOVERY_NEEDED` 并明确报错。
