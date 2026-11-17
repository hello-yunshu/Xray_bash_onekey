# F04 执行器任务清单

对应规格：`docs/plans/p2/specs/f04-executor/spec.md`

- [x] T1 探查实测：固定容器内跑 primary/secondary 默认、reject、多后端与全部拒绝路径，
      确认真实端口、片段、deny 端口、分享字段、`xray -test` 与 `nginx -t`（事实见 spec §2；
      含 publicPort=9443 冲突缺陷）
- [x] T2 规格批准（spec/tasks/checklist 已批准）
- [x] T3 编写 `F04_test.py` 的 S1（primary 默认 + 真实校验）与 S2（secondary、secondary+backend 拒绝）
- [x] T4 补齐 S3（isolate/reject/decoy/未知策略）与 S4（多后端、去重、非法后端、IPv6）、
      S5（角色/默认值/保留端口/传输/serverName 数量），每个拒绝场景断言零写盘
- [x] T5 修复 spec §6 的保留 publicPort 缺陷（balance primary 与 reality-nginx），
      新增 `TestGenerateRejectsReservedPublicPort`，`go test ./internal/xraycfg` 全绿
- [x] T6 实现 S6 真实 Bash 基线：角色 profile、端口改写、本机 upstream、serverNames 自愈、
      isolate 站点/http include、`nginx_reality_conf_add` 全量生成并与 Go 逐字节对比；
      产出 `bash-result.json` 与 `baseline-compare.json`
- [x] T7 实现 S7 汇总：所有有效配置真实 `xray -test`，所有 primary 变体真实 `nginx -t`
- [x] T8 构建 `golang:1.27.4` 二进制，固定 digest 容器内连跑两次，`failed=0` 且 `passed` 一致
      （两次均 214/214）
- [x] T9 证据整理与 hygiene：`meta.txt`、`commands.log`、`observed.json`、`bash-result.json`、
      `baseline-compare.json`、`f04-work/`；`check_evidence_hygiene.py` 0 findings
- [x] T10 更新三处计数：`tasks.md` G-3（21/28，剩余 7）、features `README.md`、
      `FUNCTION_PARITY.md` F04 行
- [x] T11 两次单独提交：`test(parity): add F04 reality balance executor` 与
      `docs(parity): mark F04 executor checklist complete`（只含本项文件；不 push/tag/merge）

## 执行顺序与边界

- T1 已完成；T3 起不得再改本规格之外的行为，实测与规格不符时先记录 `divergent-*`/`gap`。
- T5 的修复只在 S5 断言下生效，禁止顺手改其它模式。
- 每次容器运行必须使用固定镜像 digest、真实 `xray` 与真实 `nginx`；不得用 stub 替换校验器。
- 不允许删断言、放宽到恒真、或用空 `exit 0` 伪造通过。
- 不修改 `install.sh`；不接触真实 VPS、公网 CA；不 push/tag/merge。
