# 已执行证据说明

- `functional_parity.json`：本次 83 组 Bash 固定函数提取片段 vs 测试专用 Go 的 stdout/退出码差分。`full_repo_baseline_executed=false`，不包含正式 Go 核心业务代码，不可作为正式发布资格。
- `functional_parity.md`：摘要。
- `bridge_cli_contract.json`：通过 Go v2 CLI 子进程，按 synthetic Reality/TLS/Relay、故障和篡改样本执行的 39 组检查。`production_migration_certified=false`。
- `bridge_go_tests.txt`：Go v2 代码 `go test ./...`，非生产服务测试。
- `bridge_migration_trial.txt`：脚本真实进行沙盒入口交换和独立恢复。旧入口仅为合成 Bash 占位程序，不是真实 Bash 完整安装。

**发布资格门禁当前必须为红色。** `feature_contracts.json` F01–F28 全部仍未实现 Go 业务功能，不得把这些实验计为 Go 已完整替代原 Bash。
