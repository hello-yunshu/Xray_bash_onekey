# P1 安全与恢复（2026-11-19）

代码提交：`8ac1385f`（恢复事务化）、`43ceb680`（六个持久点与文件系统故障注入）、
`4c9705a9`（可选 GeoData 缺失修复）、`4ab08050`（双容器冷恢复用例）
基线：`59adbce4`（S0 报告）

## 1. 修复范围

| 问题 | 位置 | 处理 |
|---|---|---|
| 归档验证接受未声明的额外条目 | `internal/backup/backup.go · Verify` | manifest 与 tar 条目集合必须完全一致；重复路径、缺失、mode/size 漂移均拒绝 |
| manifest 无上限、单文件 `io.ReadAll` 可被压缩炸弹打爆 | 同上 | manifest ≤16 MiB，单条目 ≤1 GiB，解压总量 ≤4 GiB，逐文件流式哈希 |
| gzip 多成员/尾随数据 | 同上 | `Multistream(false)` + 缓冲区与底层文件双重检查 |
| 非规范路径（`a//b`、`..`、反斜杠、绝对路径） | `safeEntryName` / `cleanRel` | 统一拒绝 |
| Create 崩溃留下半成品归档 | `internal/backup/backup.go · Create` | 同目录临时文件 → fsync → `link(2)` 原子占名；失败清理临时文件 |
| 归档可以写进受管树（备份自己） | 同上 | `archiveInsideManaged` 预检拒绝 |
| 受管目录祖先为符号链接时越界读取 | 同上 + `securePath` | 逐级 `Lstat`，任一符号链接即拒绝 |
| `--include-geodata` 在未下载 GeoData 的安装上整体失败 | `Create` | 缺失的可选树记录为 `absent` 并跳过；符号链接父级仍然拒绝 |
| Restore 无锁、无 journal、SIGKILL 后不可收敛 | `internal/backup/transaction.go` | 共享更新锁 + `PREPARED/APPLYING/COMMITTED/ROLLED_BACK/RECOVERY_NEEDED` 持久 journal |
| `_ = os.Remove(dst+".restore-old")` 无条件删除既有文件 | 旧 Restore | 删除该逻辑；快照写入独立目录并记录 SHA256/mode/uid/gid |
| 恢复失败无回滚 | `restoreApply` / `restoreFailed` | 逆序回滚并校验快照摘要；回滚失败进入 `RECOVERY_NEEDED`，提示 `backup recover` |
| 服务未重建 | `internal/cli/backup.go · restoreServiceApply` | 真实根上在事务内执行 `nginx -t`、`systemctl restart xray`、`is-active`；失败回滚文件 |
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
| `TestCreateSkipsAbsentGeodataTree` | 未下载 GeoData 时 `--include-geodata` 成功，不创建可选树，manifest 仍记录请求 |
| `TestCreateStillRefusesSymlinkedGeodataParent` | `etc/idleleo/share` 为符号链接 → 仍拒绝 |
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
| 真实 systemd 重启与 `xray -test` | `LOCAL_RUN` | 冷恢复用例中真实 `systemctl restart xray`、`xray run -test -config`、`is-active` |
| 跨机冷恢复 | `LOCAL_RUN` | 两个独立 systemd 容器：源机销毁后目标机恢复；独立 VM 仍未做（见 P3-04） |
| Bash/Go 双端备份一致性 | `NOT_RUN` | Bash 安装器没有等价 backup 子命令，不构成双端可比 |

## 4. 双容器冷恢复实测（T04）

用例：`tests/e2e-diff/run_coldrestore.sh` + `drivers/go_coldrestore.sh`。
源容器 A 安装 Go 管理器并写入真实用户/密钥；`backup create --include-geodata` 把归档写入
宿主临时目录（不进入仓库）；真实客户端走 A 的 Reality 入站取得 origin 正文；随后**销毁 A**。
目标容器 B 从同一镜像全新启动，重新安装（生成不同的 UUID/私钥/服务账户），再恢复 A 的归档。

执行（2026-11-19，代码 `4ab08050`）：

```bash
E2E_RUN_ID=20261119-cold4 bash tests/e2e-diff/run_coldrestore.sh
# source_driver_rc=0  target_driver_rc=0  RESULT: PASS
```

| 侧 | 断言 | 结果 |
|---|---|---|
| source | `backup create` rc=0、归档 mode 0600、`backup verify` rc=0 | 3/3 PASS |
| source | 真实客户端经 Reality 取得 `cold-ok`；`doctor --client-probe` rc=0、`REAL_CLIENT_PASS` | 2/2 PASS |
| target | 全新安装与源机状态不同；归档摘要与源机一致；`backup verify` rc=0 | 3/3 PASS |
| target | `backup restore` rc=0；配置 SHA256 与源机逐字节一致；pre-restore 备份存在 | 3/3 PASS |
| target | 配置 mode 0640、组 `xray`；服务账户可读；`xray run -test -config` rc=0；服务 active | 5/5 PASS |
| target | restore 后 `doctor` rc=0；真实客户端取得 `cold-ok`；`--client-probe` `REAL_CLIENT_PASS` | 4/4 PASS |
| target | 再次 `systemctl restart xray` 后服务 active，真实客户端仍可取得 `cold-ok` | 2/2 PASS |

合计 source 8/8、target 19/19，退出码均为 0；证据
`tests/e2e-diff/evidence/goevo-coldrestore-20261119-cold4/`（含 `run.json`、两侧
`assertions.txt`、每步 `rc.txt` 与脱敏后的 stdout）。归档本身含私钥，运行结束即删除，只保留摘要。

这道用例同时验证了 `backup create --include-geodata` 的修复：源机未下载 GeoData，
此前会因 `/etc/idleleo/share` 不存在而整体失败（`lstat ... no such file or directory`），
现在缺失的可选树记录为 `skipped`，备份仍成功。

## 5. 已知限制

- `Verify` 的硬链接/稀疏文件不保留；归档只恢复普通文件内容与 mode，这是既有契约。
- 快照目录与目标同根时依赖同一文件系统；跨挂载点恢复会退化为“先复制快照再 rename”，不会丢数据。
- `Recover` 只能在目标文件仍可写时回滚；磁盘只读等场景保持 `RECOVERY_NEEDED` 并明确报错。
