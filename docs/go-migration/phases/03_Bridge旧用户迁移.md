# Phase 03｜真正的 Bash → Go 迁移：Bridge、双通道更新与可恢复切换

**阶段性质：** 高风险生产升级路径实施。必须在 Phase 02 的 Go 管理功能达到合约之后，才允许旧用户升级试验；初期仅沙盒/VM，绝不直接面向线上自动推送。

## 0. 三条不能破坏的原则

1. 用户只手动通过**真实 TTY 的更新检查**，独立明确同意后才下载 Go 迁移包；自动更新、Cron、无 TTY、`--yes`、`--allow-major` 都不允许触发 Go 下载、准备或切换。
2. 迁移成功后，只能有一套正式管理器。旧 Bash 可留为受限恢复备份，但不在 PATH、cron 或正式任务里运行。
3. 首次迁移**保留正在运行的 Xray/Nginx、证书、systemd 单元和真实路径**，只切换管理器的解释、配置元数据与正式入口；不为了目录整齐重建服务。

## 1. 实际迁移试验证据如何利用

本包 `probe/` 已真正完成 Go 编译、在沙盒使用**真实 `os.Rename` 原子替换旧入口**、模拟进程退出 code 86 后从独立进程恢复旧 Bash、验证 Reality/Relay 原配置 SHA256 没变，并阻断旧 XTLS。

但它没有处理真实系统服务、任务、签名/下载链，也没有直接重跑旧 Bash 真实安装数据。因此本阶段应把它视为**设计验证和故障测试样板**，而不是复制其代码并宣布完成生产 Bridge。尤其不要直接沿用原型用 JSON base64 保存旧入口的简化备份办法。

## 2. 正式迁移业务拆解

### 03-A｜发布链与迁移发现：先确保不会误升级

1. 确认两个 Release/版本通道：旧 `shell_online_version`/`shell_release_sha256` 仅下载旧 Bash 候选；Go 单独的版本和发行资产；Xray/Nginx 上游更新继续独立。
2. **先发布一个仍符合 Bash `install.sh` 签名/函数、`bash -n`/发布校验和旧版候选合约的 Bridge-aware Bash 小版本。** 旧自动更新可以升级到这个纯 Bash 小版本，但不能因此自动下载 Go。
3. 旧版本用户手动 `--update`：如果先需要升级 Bridge-aware Bash，则先走正常 Bash 更新确认，再由该脚本在下一次手动交互检查中提供 Go 迁移选择；不要依赖旧版 Bash 直接理解未来 Go 格式。
4. 只有满足 `interactive TTY && explicit user command && consent == affirmative` 三条件，才能开始第一次 Go 迁移资产网络请求。需要把 TTY、命令来源和 `auto_update` 环境分支写成显式单元测试。
5. 在同意前展示变更摘要：旧 Bash 版本/模式/角色、Go 版本、必要临时空间、预估影响的管理资产、放弃迁移与故障恢复路径；提示不保证跨版本私有配置自动支持。
6. 下载 Bridge/Go 固定版本 Release 资产、读取明确可信元数据、做架构、SHA256、可执行文件格式与内容校验。不能从浮动 `main/master` 拿 root Shell 执行。
7. **与 Go 新安装器区分**：新用户只下载 Go；老用户走 Bridge-aware Bash 手动更新。Release 的 `latest/download/install.sh` 行为及旧固定-tag 资源下载要做真实验证。

### 03-B｜Bridge 只读审计与差异计划

读取 `install_config.json`、实际 Xray JSON、所有相关 Nginx include、运行 systemd unit 的 `ExecStart/User/Group`、当前服务 active/enabled、证书/ACME 状态、旧 GeoData 与 cron、独立 relay、Rill 状态。

分类：

- **可确定转换**：Reality/TLS/ONLY/relay 的合法旧数据，原生配置合法且与旧元数据基本一致。
- **可修复但不应静默处理**：自有定时任务重复、旧版 GeoData 路径、明显权限或软链问题；先显示即将修改的位置。
- **需人工确认/阻断**：密钥与 runtime 不一致、自定义内容无法安全合并、目标内核不支持、损坏 JSON、角色混装、旧 `XTLS ONLY`、Rill 当前授权状态不可确定。

只读阶段不下载额外包、不写 `/etc`、不触发服务重启。输出机器可读 `plan.json` 和终端说明，二者不能包含私钥明文。

### 03-C｜快照准备与落盘 Journal

1. 更新锁：兼容旧 `/run/lock/idleleo-update.lock`，阻止 Bash/Go 更新、SSL 续期、GeoData 和 Bridge 在同一份资源上并发写入；锁故障时拒绝转换。
2. 备份对象：正式管理入口、旧 manager 安装信息、所有项目拥有的 systemd unit 与配置、准确的 cron 项、需要的证书/密钥引用、重要服务 active/enabled；**绝不自动复制整份 `/root`/全量 crontab 作为自身独占资源。**
3. 恢复执行器：独立于 `/usr/bin/idleleo` 的固定位置，并验证权限、可执行性及备份 SHA256；即使正式入口已坏也能单独恢复。
4. 准备阶段落盘 `PREPARED`（包含旧入口目标、版本、hash、受控资源快照）；使用原子写入与 `fsync`，不把多文件操作说成原子。
5. 读旧 Bash → 输出 `/etc/idleleo/manager/config.json` 的**受控新元数据**，只引用旧 Xray/Nginx/证书运行路径；不复制 UUID/privateKey/shortIds 到无必要的新 JSON。
6. 将规范 Go 状态与当前原生 Xray JSON 对照：多用户、Reality 私钥、公钥兼容、shortId、spiderX、双栈、routing、outbounds、DNS、relay role。一旦冲突，拒绝继续并保持旧 Bash 入口。

### 03-D｜候选 Go 的真实预验收

- Go 候选在独立路径以**只读方式**加载转换后的 manager.json，能查询 `status`、原运行内核状态、节点角色和必要的共享信息。
- 对 Xray 节点执行当前 Xray 的 `run -test`；对需要 Nginx 的路径执行目标 Nginx 的 `-t`；relay 没有 Xray 时不强行要求 Xray 健康。
- 只检查能证明的事实，运行态健康并不等于客户端网络真实可达；因此不要自动更改原节点端口或重新签发证书。
- Rill 如存在，必须遵守独立观察模式与授权契约；若其状态异常不能完成确认，不允许误以为已正常交接。

### 03-E｜入口和任务切换（最后才发生）

1. 写 `ACTIVATING` Journal 并同步落盘。
2. 将 Go 正式二进制写到 `/opt/idleleo/bin/idleleo` 等受控位置；原子替换 `/usr/bin/idleleo` 指向 Go，保留**独立可执行**的旧 Bash 恢复备份。切换前确认同名路径不是用户自建软件。
3. 精确移除或转置本项目旧自动更新/证书续期任务，不能通配删除用户 cron；新的 Go 定时入口必须通过相同资源锁与独立运行策略。
4. 验证 PATH 上只有一个正式管理器，`idleleo status`、版本、运行服务路径、流量输出和预期服务 active/enabled 与操作前一致；不用 Bash `install.sh` 承担日常功能。
5. Go 验证失败先恢复旧 cron/入口和必要的服务状态，最后落盘 `ROLLED_BACK` 或 `RECOVERY_REQUIRED`；**不要在未确认配置真相前删除候选/恢复材料**。
6. 成功 `COMMITTED` 后再执行有界旧 Bash 清理；历史恢复材料存受限目录并给出保留政策。Go 自更新走新通道，不依赖旧 `shell_online_version`。

### 03-F｜强杀/重启后的继续或恢复

**必须覆盖的故障切面：**

- 下载到一半 / Manifest 错误 / 空间不足 / 准备备份失败 → 原 Bash 未变。
- `PREPARED` 写入后中断 → 可通过独立恢复器撤销候选或显式重新验证；不重启旧服务。
- 切换正式 symlink 后 `SIGKILL` → journal 仍显示 `ACTIVATING`，恢复器可识别当前 Go 入口并恢复旧 Bash。
- 移除旧 cron 后强杀 → 通过精确备份恢复旧任务，不能有 Bash/Go 两套自动更新同跑。
- Go 验收成功后、`COMMITTED` 落盘前断电 → 独立恢复逻辑判断，而不是宣称已经完成或无条件重复激活。
- 本来停用的 nginx/xray → 恢复不能误启；恢复失败 → `RECOVERY_REQUIRED`，用户看到精确指引。
- 已 `COMMITTED` 用户之后修改过 Go 配置 → 任何“回 Bash”必须是单独授权的逆向迁移或明确降级策略，不提供静默恢复。

## 3. 测试矩阵（至少这些，避免无限增长）

| ID | 场景 | 预期 |
|---|---|---|
| M01 | auto_update/cron 检查 Bash | **没有** Go 下载请求/新元数据/Go 入口 |
| M02 | `--update --yes --allow-major` 无 TTY | **不迁 Go**，只遵守原 Bash 更新许可 |
| M03 | 真 TTY 手动检查，拒绝 | 不下载 Go；原入口/服务/cron 原样 |
| M04 | 手动同意，但预检显示 XTLS ONLY | 阻断激活，原 Bash 服务保留 |
| M05 | Reality 单用户 + 自定义规则 + 双栈 | Go 只读可接管意图；原生配置 hash 与密钥不变 |
| M06 | Reality 多用户、shortId/spiderX | 用户集合与元数据关联准确，没有静默减少 |
| M07 | Nginx TLS + 已有证书和自定义片段 | 证书不重签、片段不删除、运行原状态保留 |
| M08 | 独立 relay，无 Xray | 不要求 Xray；Nginx Stream 可继续正常转发 |
| M09 | 旧 GeoData cron 与原生刷新并存 | 只清自有旧任务、不会删自定义刷新 |
| M10 | 入口已切 Go、进程异常退出 | 独立恢复器恢复原 Bash 入口和自有任务 |
| M11 | 切换 cron 后进程异常退出 | 能恢复准确的旧 cron 集合，不重复执行 |
| M12 | 数据漂移或目标权限错误 | 拒绝原样覆盖，保留现有运行文件 |
| M13 | 正式 Go 成功后重复 Bridge | 提示已迁移，不重做迁移或删除文件 |
| M14 | Go 安装/版本发布的 latest 路径 | 老 Bash 自动路径仍只下载 Bash Release |
| M15 | 恢复器自身缺失或损坏 | 激活前拒绝；中断后保留备份并报告明确人工路径 |
| M16 | 无 root、无 TTY、SSH EOF | 不绕过授权，不永久等待输入 |

## 4. 必须产生的代码、文档、证据

```text
packaging/install.sh               # 新用户受控 Go 引导
packaging/bridge/                  # 生产 Bridge（与 Go 日常代码分层）
internal/legacybridge/             # 只含必要的旧版解析/转换/事务接口
scripts/legacy-bash-maintenance/   # 符合旧 Bash 更新契约的过渡版本变更
assets/manifest/                   # Go & Bridge 固定版本/摘要
README/CHANGELOG                   # 老用户步骤、支持范围与回滚说明
tests/migration/                   # M01–M16 和样本资产
```

生产 `bridge` 的可执行恢复入口必须明确告知路径、权限、备份保留位置；不得依赖 Go 正式路径可用才恢复。

## 5. 阶段退出门禁

- [ ] 真正的 Bash 手动 TTY 检查更新路径已经与迁移发现接通，不只是 Go Bridge 本体测试通过。
- [ ] 自动更新、`--yes`、`--allow-major`、无 TTY 都不会下载/激活 Go，且有网络调用计数证据。
- [ ] 对 Bash v3.3.4 及选定旧版本进行真正的从运行环境升级测试（至少 Reality、TLS、relay）。
- [ ] 原配置、证书、用户、Reality 密钥、Nginx 自定义片段与服务用户/组保持正确。
- [ ] Go 候选不依赖 Bash 日常业务；PATH、cron、systemd 中只有一套正式管理器。
- [ ] `PREPARED/ACTIVATING/COMMITTED/ROLLBACK_REQUIRED/ROLLED_BACK/RECOVERY_REQUIRED` 的真实中断测试有磁盘和进程结果。
- [ ] 迁移中断恢复入口单独可执行；故障注入失败不会假称恢复成功。
- [ ] Bash 和 Go 新旧 metadata/Release 完全隔离；任何旧 Bash 自动更新目标均是合法 Bash。
- [ ] 未经用户明确确认，**没有**远程生产用户被自动迁移。

## 6. 开发智能体指令

> 只执行 Phase 03，按 `reference/RELEASE_MIGRATION_CONTRACT.md` 完成旧 Bash 的 Bridge-aware 过渡版本、Go 生产 Bridge、统一新安装器、显式 TTY 授权和持久化故障恢复。必须复用 Phase 00 的旧数据/资源归属表，保留已运行 Xray/Nginx 的旧路径和私钥；只在 Go 全功能已通过 Phase 02 后开始真实迁移试验。先复制仓库到隔离 VM，逐条跑 M01–M16；禁止自动升级下载 Go 包、禁止跳过故障测试、禁止在稳定 Bash `main` 上直接发布未验收的 Go 管理器。


## v6 新增验收门槛：老用户状态保持差分

- 对 Reality/TLS/无 TLS/中转和附加自定义文件测试：迁移前后 Xray/Nginx 的**原始配置哈希、实际运行态、密钥、用户数、端口、证书状态**在不请求修改时保持一致。
- `--yes`/`--allow-major`/cron/自动更新不得触发下载 Go/Bridge；TTY 显式授权后方可下载，强制负向测试。
- 使用真实旧版安装产物（经脱敏）跑 prepare/activate/commit/recover；故障点包含 SIGKILL、断电式状态重放、入口被第三方变更、定时任务接管失败。
- **出口门槛**：至少一台隔离 VM 的真实 Bash→Go 迁移、重启以及逆向恢复路径有可重现证据；仅运行 `prototype/run_trial.sh` 不达标。

## v6.1 阶段验收强制补充
- 旧 Bash 的自动更新不能识别/拉取 Go 资产；手动 TTY 明确授权迁移。
- Bridge 必须在真实隔离 VM 处理原始目录/服务与 timer/cron；SIGKILL、重启、失联、入口漂移均需真实环境演练。
- Go 原型黑盒测试是 L1 参考，不是通过生产 Bridge 验收的证据。
