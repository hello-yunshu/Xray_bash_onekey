# 交给 Codex / WorkBuddy 的启动提示词

> 不强制使用 `/goal`；建议普通工程执行模式逐阶段推进，并允许智能体使用 GitHub/终端/测试能力。

## 首次执行（复制以下文字即可）

```text
请解压我提供的 Xray Go v4 审计与迁移计划 ZIP，先阅读 README.md、AUDIT_REPORT.md、MIGRATION_TRIAL_REPORT.md、TRACEABILITY_MATRIX.md 和 RELEASE_MIGRATION_CONTRACT.md。你当前只执行 phases/00_基线与契约.md，不执行后续阶段。

以当前 GitHub 仓库真实源码为准，核对 4752f77 基线是否变化。保留 main Bash 稳定，在 develop/go-native 实施。不要改动远程生产用户，不自动触发 Go 迁移；不把 probe 的演示 Go Bridge 当生产代码。

逐条落实本阶段工作包，优先核查 Ubuntu 24.04 Stats CI 失败及旧 Bash Release/API/自动更新链。产出阶段交付文件、实际证据、未解决项及清晰的下一阶段阻断/放行结论。没有证据的验收项目不标完成。
```

## 后续阶段的最短执行模板

```text
现在只执行 phases/0X_对应阶段.md，以上一阶段已验收的契约为准。先核对当前仓库 HEAD 和已有进度，再按阶段内部批次实现、测试和提交。不得跳过当前阶段的退出门禁，不跨阶段提前发布 Go、下载迁移包或切换正式管理器。每一批列出代码 diff、测试命令/结果、功能矩阵状态和失败恢复证据。若发现契约冲突，先提出具体阻断项并保留原行为，不默默改变目标。
```

## 推进顺序和输出要求

`00` 契约 → `01` Go 核心 → `02` Xray 完整能力 → `03` 旧 Bash Bridge 与手动迁移 → `04` 真实验证与正式发布。任何阶段都不能把“有代码、能编译”当成“已完成迁移”。

全部阶段统一要求：只保留 Go 管理核心；只在明确允许的场景使用受控 Shell/Python 辅助工具；轻量、代理安全、服务器稳定优先；不增加 Web、插件商店、通用 Linux Core、跨 VPS 编排或 sing-box 首版开发任务。
