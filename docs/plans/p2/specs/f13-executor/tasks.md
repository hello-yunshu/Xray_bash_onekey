# F13 任务

- [x] T1 新增 `internal/componentupdate/manifest.go`：清单解析/取值/版本比较/错误
- [x] T2 新增 `internal/componentupdate/update.go`：下载、摘要、备份、激活、健康、回滚
- [x] T3 补单元测试：版本表、降级、坏清单、摘要/大小、回滚、同版本重装
- [x] T4 接入 `update xray|nginx` 与 `--manifest/--json/--container/--no-restart`
- [x] T5 更新 flags 白名单与帮助文本
- [x] T6 `F13_test.py`：xray 成功/重装/降级/坏摘要/坏大小/健康回滚
- [x] T7 `F13_test.py`：nginx 成功与坏配置回滚、真实 `nginx -t`
- [x] T8 `F13_test.py`：清单门禁、旗标 rc=2、真实根门禁、零写盘断言
- [x] T9 固定镜像连跑两次，写证据与 `meta.txt`，hygiene 0 findings
- [x] T10 更新 `FUNCTION_PARITY.md`、tasks G-3 计数、features README
- [x] T11 两次提交：`feat(F13): ...` 与 `test(F13): ...`
