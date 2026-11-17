# F21 执行器任务清单

对应规格：`docs/plans/p2/specs/f21-executor/spec.md`

- [x] T1 探查实测：systemd 容器内真实安装（mode none ws 443）、状态开关、apply/off、
      幂等、失败回滚、Bash `tb_build_block_rules`，整理 31 条事实（见 spec §2）
- [x] T2 规格批准（spec/tasks/checklist 经用户批准）
- [x] T3 编写 `F21_test.py` 的 S1（安装基线）与 S2（状态机、缺 --yes、dry-run、非法输入）
- [x] T4 补齐 S3（首次 apply 规则/sniffing/drop-in/backup/真实重启/探针）与
      S4（二次幂等、status 字段）
- [x] T5 补齐 S5（off 精确恢复、二次 off）与 S6（zz、用户吞流量、缺 geosite 三类回滚）
- [x] T6 实现 S7 Bash 基线：真实 source `scripts/traffic_blocker.sh` 调
      `tb_build_block_rules`，按 JSON 语义对比 5 条内置规则；验证 legacy adoption 不重复；
      产出 `bash-result.json` 与 `baseline-compare.json`
- [x] T7 构建 `golang:1.27.4` 二进制，固定 digest 的 systemd 容器内连跑两次，
      `failed=0` 且两次 `passed` 一致（79/79、79/79）
- [x] T8 证据整理与 hygiene：`meta.txt`、`commands.log`、`observed.json`、
      `bash-result.json`、`baseline-compare.json`、`f21-work/`；
      `check_evidence_hygiene.py` 0 findings
- [x] T9 更新三处计数：`docs/plans/p2/tasks.md` G-3（23/28，剩余 5）、
      features `README.md`、`FUNCTION_PARITY.md` F21 行
- [x] T10 两次单独提交：`test(parity): add F21 traffic block executor` 与
      `docs(parity): mark F21 executor checklist complete`（只含本项文件）

## 执行顺序与边界

- T1 已完成；T3 起不得改生产代码；实测与规格不符时先记录 `divergent-*`/`gap`。
- 夹具必须在真实 systemd 容器内以 root 运行，真实重启 `xray` 并做真实
  `xray -test`；不得用 stub 替换服务或校验器。
- geo 资源只读挂载并在运行期复制，不联网下载；缺失时 exit 2，不算通过。
- 不允许删断言、放宽到恒真、或用空 `exit 0` 伪造通过。
- 不修改 `install.sh` 与 `scripts/traffic_blocker.sh`；不 push/tag/merge；
  不接触真实 VPS；不提交遗留文件（`check_evidence_hygiene.py` 修改、`f02-executor/`、
  `f07-executor/`、` 2` 后缀文件）。
