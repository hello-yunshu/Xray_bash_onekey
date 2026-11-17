# F09 执行器任务

- [x] T1 清理 `.tmp-f09` 原型容器与临时二进制；确认 `golang:1.27.4` 构建环境
- [x] T2 编写 `tests/go-parity/parity/features/F09_test.py` 的沙箱根、metadata、
      nginx 安装树与真实 `xray generate` 初始化
- [x] T3 实现 S2–S5：add/list/remove、重复、保护性拒绝与 JSON 断言
- [x] T4 实现 S6 回滚：破坏主配置 → add rc=1 且无残留 → 恢复后成功
- [x] T5 实现 S7 TLS ws：真实 fragments + 最小 server 块 + `.wsServers` 断言
- [x] T6 实现 S8 Bash 基线：提取 `fm_create_server_file`/`fm_delete_file` 并比较字节
- [x] T7 实现 S9–S10：权限/缺件门禁、只读树摘要与旗标错误
- [x] T8 固定镜像连跑两次，写 `meta.txt`/证据布局并跑 hygiene（0 findings）
- [x] T9 更新 `FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md`，勾选清单并两次提交
