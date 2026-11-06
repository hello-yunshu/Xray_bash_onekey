# 已执行证据说明

- `functional_parity.json`：本次 83 组差分。Oracle 为 `LIVE_PINNED_CLEAN`：
  独立 checkout 的完整 Bash 仓库，`HEAD=4752f77c58028ac169c429fe7674c20060b30c9e`，
  `install.sh` 干净且与 Git 对象字节一致；不使用方法片段充当基线。
  `full_repo_baseline_executed=true`。
- `functional_parity.md`：摘要。
- `bridge_cli_contract.json`：通过 Go v2 CLI 子进程，按 synthetic Reality/TLS/Relay、故障和篡改样本执行的 39 组检查。`production_migration_certified=false`。
- `bridge_go_tests.txt`：Go v2 代码 `go test ./...`，非生产服务测试。
- `bridge_migration_trial.txt`：脚本真实进行沙盒入口交换和独立恢复。旧入口仅为合成 Bash 占位程序，不是真实 Bash 完整安装。

Go 侧运行的是 `BUNDLED_TOY_GO_DEMO`（`release_certified=false`），只覆盖 7 个纯函数，
不代表 F01–F28 业务能力已迁移。

**发布资格门禁当前必须为红色。** `feature_contracts.json` 中 F01–F28 的 Go 状态全部为未实现，
不得把这些实验计为 Go 已完整替代原 Bash。
