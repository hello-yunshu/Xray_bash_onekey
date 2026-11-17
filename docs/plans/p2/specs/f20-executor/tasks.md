# F20 执行器任务清单

对应规格：`docs/plans/p2/specs/f20-executor/spec.md`

- [x] T1 探查实测：固定容器内跑 install（含二次幂等）、status/banned/unban、trust
      IPv4/CIDR/IPv6、jail 启停、uninstall、缺二进制与写根守卫；真实执行 Bash
      `mf_configure_fail2ban` 并与 Go 产物对比（事实见 spec §2）
- [x] T2 规格批准（spec/tasks/checklist 经用户批准）
- [x] T3 编写 `F20_test.py` 的 S1（生成物、manifest、幂等）与 S2（Bash 基线逐字节对比）
- [x] T4 补齐 S3（status/banned/unban）、S4（trust）、S5（jail 启停与所有权）、
      S6（uninstall 与保留）、S7（守卫与错误），每个错误场景断言 rc 与零落盘
- [x] T5 构建 `golang:1.27.4` 二进制，固定 digest 容器内连跑两次，`failed=0`
      且两次 `passed` 一致（两次均 110/110）
- [x] T6 证据整理与 hygiene：`meta.txt`、`commands.log`、`observed.json`、
      `bash-result.json`、`baseline-compare.json`、`f20-work/generated/`（仅生成物，
      发行包文件只留摘要）；`check_evidence_hygiene.py` 0 findings
- [x] T7 更新三处计数：`docs/plans/p2/tasks.md` G-3（22/28，剩余 6）、
      features `README.md`、`FUNCTION_PARITY.md` F20 行
- [x] T8 两次单独提交：`test(parity): add F20 fail2ban executor` 与
      `docs(parity): mark F20 executor checklist complete`（只含本项文件）

## 执行顺序与边界

- T1 已完成；T3 起不得再改本规格之外的行为，实测与规格不符时先记录 `divergent-*`/`gap`。
- 容器内真实写 `/etc/fail2ban`：Bash 与 Go 各自快照、恢复、比对；不得共用同一轮产物。
- 必须使用固定镜像 digest 与真实 `fail2ban-client`；不得用 stub 替换 fail2ban 运行态。
- 不允许删断言、放宽到恒真、或用空 `exit 0` 伪造通过。
- 不修改 `install.sh` 与 `scripts/fail2ban_manager.sh`；不接触真实 VPS；不联网。
