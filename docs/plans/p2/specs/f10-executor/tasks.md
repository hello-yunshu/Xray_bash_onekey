# F10 任务

- [x] T1 实现 `internal/deploy/nginxtls.go`（定位、切换、`nginx -t`、回滚）
- [x] T2 接入 `xray tls --version 1.3|1.2+`、`--json`、`--container`
- [x] T3 补 `nginxtls_test.go`：TLS 改写、Reality 双向切换、h3 拒绝、失败还原
- [x] T4 编写 `F10_test.py` 的 Reality 安装与真实 `nginx -t` 初始化
- [x] T5 覆盖 `1.2+` / 重复 no-op / `1.3` 往返与 Bash 基线字节比较
- [x] T6 覆盖 TLS 安装：`1.2+` rc=1、`1.3` 改 `ssl_protocols`
- [x] T7 覆盖回滚、rc=2 旗标、rc=3/rc=1 门禁与只读稳定性
- [x] T8 固定镜像连跑两次，写证据与 `meta.txt`，hygiene 0 findings
- [x] T9 更新 `FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md`、features README
