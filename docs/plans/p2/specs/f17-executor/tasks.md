# F17 任务

- [x] T1 新增 `internal/netcfg/classify.go`：IP 字面量、Classify、Validate
- [x] T2 新增 `internal/netcfg/dns.go`：自定义 resolver 的 A/AAAA 查询、接口地址探测
- [x] T3 新增 `internal/netcfg/firewall.go`：family 解析、端口集合、差分执行、逆操作
- [x] T4 补单元测试：9 组 DNS 判定表、family 映射、端口解析、失败回滚
- [x] T5 接入 `net dns` / `net firewall status|apply|revert` 与旗标白名单/帮助
- [x] T6 `F17_test.py`：Python UDP DNS 服务 + 真实 Go 解析 + 判定表
- [x] T7 `F17_test.py`：提取 Bash 判定函数跑同表并比对
- [x] T8 `F17_test.py`：iptables/ip6tables shim、apply/diff/family 切换/dry-run
- [x] T9 `F17_test.py`：故障注入回滚、state 写失败、status/revert、fail-closed
- [x] T10 固定镜像连跑两次，写证据与 `meta.txt`，hygiene 0 findings
- [x] T11 更新 `FUNCTION_PARITY.md`、tasks G-3 计数、features README
- [x] T12 两次提交：`feat(F17): ...` 与 `test(F17): ...`
