# 对 v4 五阶段计划的最小必要修订（不另增阶段）

本文件是开发计划的补丁建议，不重排五阶段，不把测试原型当成可直接 merge 的实现。

## Phase 00｜应补充的契约

- 补充 `ENTRY_HANDOFF_CONTRACT.md`：旧入口文件/符号链接所有权、内容 SHA256、模式、目标，候选 Go 的可信身份与业务自检、入口漂移拒绝、恢复时第三方改动拒绝。
- `PREPARING` 是**发生任何新 manager/backup 写入之前**的可恢复状态；独立恢复器处理在 `PREPARING` 和 `PREPARED` 均发生的中断。
- 首次迁移需从可信 Release/签名链验证 Go 与 Bridge 的来源，不可只比较来自同一未认证下载位置的 HASH。
- 旧 Bash 的 Stats Ubuntu 24.04 CI 红灯仍是未完成的基线调查；不能把 `release-gate` 单独成功当成全部通过。

## Phase 01｜应补充的原语与测试

- 实现候选文件验证的标准接口 `VerifyCandidate(expectedDigest, executableSelfCheck, version, architecture)`，不得只用 `isExecutable`。
- 受控文件修改时对目标进行操作前和提交前两次身份检查；失败不得静默覆盖第三方改动。
- 状态/恢复报告必须在 manager.json 可能不存在的中断阶段仍可工作。
- 增加故障测试：`journal_preparing_crash`、`entrypoint_drift_before_activate`、`unrelated_entrypoint_after_crash`、`fake_executable_rejected`、`manager_drift`、`candidate_sha_drift` 和并发锁竞争。

## Phase 02｜应补充的真实业务门禁

- Go `status`、`config inspect`、`xray run -test`、Nginx `-t` 作为 Phase 03 候选预验收的真实业务入口，不接受原型里的简易 `--bridge-self-check` 取代这些行为。
- 原生 JSON 的多用户、routing/DNS/outbounds、Reality shortId、证书等**明确是 Go 的完整管理职责**，不能由 Bridge 保留文件但 Go 后续不能编辑。
- Docker、Rill 的支持范围需分别有真实运行记录，不能用本次合成测试通过代替。原 CLI 的 stats JSON 与退出码要具体逐项核对。

## Phase 03｜应补充的恢复行为

- Journal 在首个文件写入前落盘，状态至少支持 `PREPARING/PREPARED/ACTIVATING/COMMITTED/ROLLED_BACK/RECOVERY_REQUIRED`，并记录当次操作真实影响文件的摘要与步骤。生产系统仍应使用实际资源状态机和独立备份。
- 变更路径与恢复路径都必须在**检查入口是否属于本次迁移**后才能覆盖或删除；任何第三方修改转人工 `RECOVERY_REQUIRED`，保留证据。
- Go 候选须有事先固定的版本/摘要、可执行的 CLI 自检及目标环境运行检查；一份可执行文本或错误架构候选绝不能激活。
- 进程在 Journal 与 manager/config 两次持久化写入之间退出：不得留下一份无法自动识别的“半迁移”文件。
- 旧自动更新和手动 TTY 的网络调用要分别记录，拒绝/无 TTY 时 Go 下载请求数应为 0。

## Phase 04｜验收与发布

- 将本审计重现的 `V4-P0-01`～`V4-P0-03` 转成真正的 Go 发布阻断测试。
- 对 Reality/TLS/relay 至少各完成：旧版本采集、候选校验、真实服务验证、入口切换、强杀恢复、旧 cron 恢复、已提交重启后状态稳定。**本包只证明了前三种模式的沙盒入口机制**。
- 交叉编译与目标硬件运行分别列证据；发布前核对 Xray/Nginx/Rill 适配、旧 Bash 维护更新通道以及 CI 红灯。
