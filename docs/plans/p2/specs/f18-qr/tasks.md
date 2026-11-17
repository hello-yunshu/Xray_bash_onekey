# F18-QR 任务清单

- [x] T1 事实核对：Bash 10 处 `qrencode -o - -t utf8`、依赖声明、真实 qrencode
      4.1.1 输出形态、当前 `--qr` rc=2、`vendor/` 与离线限制（见 spec §2）
- [x] T2 规格批准（spec/tasks/checklist）
- [x] T3 `internal/cli/xray.go`：`--qr` 文本分支；先渲染到内存再打印；
      `--json` 互斥；缺 qrencode 的 rc=1 与安装提示
- [x] T4 `internal/cli/flags.go` 增 `qr` 布尔；中文/英文 help 各补一行说明
- [x] T5 更新 `F18_test.py`：S1 默认不变、S2 `--qr` 与真实 qrencode 逐字节一致、
      S3 守卫、S4 Bash 基线、S5 回归；新增 `qr-compare.json`
- [x] T6 `golang:1.27.4` 构建，固定 `idleleo-e2e` 镜像连跑两次，`failed=0`
      且 `passed` 一致
- [x] T7 证据整理（`meta.txt`/`commands.log`/`observed.json`/`baseline-compare.json`/
      `qr-compare.json`/两次结果）+ `check_evidence_hygiene.py` 0 findings
- [x] T8 更新 `FUNCTION_PARITY.md` F18 行、`docs/plans/p2/tasks.md` F18 条目
- [x] T9 两次单独提交：`feat(xray): add share --qr terminal QR code` 与
      `docs(parity): mark F18 QR checklist complete`
