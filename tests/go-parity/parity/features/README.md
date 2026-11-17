# 正式 Go 业务验收夹具

> 2026-11-17 校正：原文「故意没有 `F01_test.py` 到 `F28_test.py`」已过时——本目录现有
> 28 个真实执行器（F01/F02/F03/F04/F05/F06/F07/F08/F09/F10/F11/F12/F13/F14/F15/F16/F17/F18/F19/F20/F21/F22/F23/F24/F25/F26/F27/F28）与 `fixture_support.py`，已补齐 28/28。
> 执行器补到 28/28 的排期见 `docs/plans/p2/tasks.md` P2-G（G-3）。

当前 Go 尚未完成 28 项业务签收（`feature_contracts.json` 仍全部
`PENDING_GO_IMPLEMENTATION`）。生成假测试、空 `exit 0`、预填 VERIFIED 都不可接受。

每完成业务模块，开发者须编写对应 `Fxx_test.py`。接收 `--go-bin <由受控 Git 源码构建的正式 Go 管理器>`、`--bash-repo <固定旧 Bash 基线>`；在隔离 VM/容器中对比有效配置、服务状态、退出码、用户自定义字段、权限及失败恢复。测试必须真实执行新代码；对于已批准的安全差异，断言 Go 的更安全行为，并附批准记录（不能只写 JSON）。

本包的 `check_release_gate.py` 必须在所有 28 个真实测试文件、当前 CI 源码、完整 Bash 基线、Go 源码构建和 L0 native 差分到位前一直返回非零。`GITHUB_ACTIONS` 不是安全令牌；可信度来源于受保护的仓库、工作流、代码审查与实际运行，而不是环境变量字符串。
