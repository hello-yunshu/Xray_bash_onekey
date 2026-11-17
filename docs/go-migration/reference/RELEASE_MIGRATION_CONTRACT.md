# Bash → Go 发布、发现、授权和单管理器迁移契约（v4）

## 1. 不可再讨论的决定

- 一台目标服务器同一时刻仅运行**一个正式管理器**：迁移前 Bash、成功后 Go；临时候选/备份恢复程序不算第二个正式管理器。
- Bash 稳定 `main` 在开发期不变；Go 在 `develop/go-native`。达到正式门禁才调整主线，保留 `legacy/bash` 和旧 Release。
- 自动更新永远**不能下载、安装、准备或激活 Go 迁移资产**。`-u --yes --allow-major` 不构成 Go 迁移授权。非 TTY 禁止首次迁移。
- Rill、定制 Nginx、证书、GeoData、Xray 当前运行配置的旧路径首次迁移尽量不变，主要转换 Go 管理器的配置和状态。旧 `XTLS ONLY` 无法安全管理时阻断。
- Go Core 只有一个管理二进制；正常业务不调用旧 `install.sh` 或其 `source` 的函数。

## 2. 当前真实发布链

| 发行对象 | 当前基线 | 消费端 | 首版 Go 分流策略 |
|---|---|---|---|
| Bash 脚本 | API `shell_online_version=3.3.4`；Bash Release `v3.3.4` + `shell_release_sha256` | 当前 `scripts/auto_update.sh` + `install.sh -u auto_update` | **继续只发布 Bash 候选**，含 Bridge-aware Bash 小版本 |
| 定制 Nginx | API `nginx_build_online_version=2026.10.15.7679`；manifest 指向架构包 | Bash/Go 的 Nginx 业务模块 | 不改变其现有运行路径；复用 manifest/SHA256 契约 |
| Xray | API `xray_online_version=26.10.31`；上游安装脚本固定 commit/sha | Bash 运行路径、未来 Go Xray 生命周期 | 用 Go 原生管理 Xray 更新/校验；不可静默降级 |
| Go 管理器 | 尚未正式发布 | 新安装器/已迁移 Go 更新器 | **独立版本键、发行资产名、SHA256、候选门禁**；不得写入旧 shell 字段 |
| Bridge | 尚未正式发布 | 只有手动 TTY 旧 Bash 再次明确确认 | 固定候选/可恢复、一旦正式切换即不再日常运行 |

> 具体 Go tag（例如 `go-vX.Y.Z`）和最终静态资产文件名是 Phase 00 的**待冻结命名决定**，上表的分流规则则是硬约束。标签命名必须验证 GitHub Release `latest` 与旧 Bash 固定 URL 互不混淆。

## 3. 从旧 Bash 开始的完整用户路径

1. **旧版本 Bash 更新器**照常检查 `shell_online_version`。如需 Go 入口，先升级到一个通过旧 Bash 校验的 *Bridge-aware Bash* 维护版（仍为 Bash，不下载 Go）。
2. 新维护版仅在**用户通过真实 TTY 明确执行手动检查/更新**时展示：现有状态、可选 Go 迁移、限制、备份方案。用户拒绝：立即返回 Bash；不请求 Go 文件。
3. 用户一次确认准备迁移前可先读取 Go 迁移说明（本地嵌在 Bash 的文本；不得为了展示提示就下载 Bridge 包）。确认后从固定可信 Release 下载 Bridge + Go 候选，校验文件类型/架构/SHA256，申请互斥锁。
4. Bridge **只读扫描**→异常分类→快照/Journal→写入新管理器配置（不搬 Xray/证书）→Go 候选离线校验→复核运行服务健康→独立原子切换 `/usr/bin/idleleo` →清理/转置项目自己的 cron→复核和 `COMMITTED`。
5. **不通过**则保持或恢复旧 Bash 的活动入口和旧任务，保留定位信息。未触达生产可运行配置时，直接丢弃候选；失败中断后由独立恢复执行器处理状态。
6. **成功后**：Go 是唯一正式管理器；旧 Bash 不在 PATH、不会被旧 cron 启动，可在受限的恢复目录保留备份。

## 4. 可验证的“禁止迁移触发”真值表

| 旧 Bash 场景 | 允许下载 Go 迁移包？ | 允许激活 Go？ |
|---|---:|---:|
| cron 自动检查 | 否 | 否 |
| `auto_update.sh` | 否 | 否 |
| 普通开菜单/`--show`/`--stats` | 否 | 否 |
| 无 TTY 的 `--update` | 否 | 否 |
| 无 TTY 的 `--update --yes --allow-major` | 否 | 否 |
| TTY `--update`，用户拒绝 | 否 | 否 |
| TTY `--update`，用户首次同意但预检失败 | 允许仅在明确同意后下载必要候选，不能激活 | 否 |
| TTY `--update`，明确同意、完整预检和健康验证通过 | 是 | 是（事务式） |

## 5. Bridge 正式版最低持久化状态机

`DISCOVERED`（只读）→ `PREPARED`（旧入口/配置/服务/任务状态和密钥引用快照完成）→ `VALIDATED`（Go 候选与转换可用）→ `ACTIVATING`（允许发生入口与自有任务切换）→ `COMMITTED`。失败路径：`ROLLBACK_REQUIRED`→`ROLLED_BACK`，或 `RECOVERY_REQUIRED`（保留备份并停手）。

- 所有状态变更以**持久化 Journal**记录：操作 ID、旧/新版本、旧/新路径、hash、备份快照、准确的已完成步骤、旧服务 active/enabled、旧项目 cron/任务、步骤结果。Journal 写入同卷原子 rename + `fsync`；恢复时拒绝未知 Schema/损坏清单。
- 入口恢复程序单独存放于不可被 `/usr/bin/idleleo` 切换同时覆盖的位置。不要在断点自动一口气重新安装；先读取 Journal 决定安全继续还是恢复。
- 尝试备份前判断磁盘空间/目标是否软链越界；用户原本不存在的资源不应在 rollback 中凭空创建。
- 已 `COMMITTED` 不通过通用 `recover` 隐式回退；正式回退需审查 Go 已改动的配置，并有独立确认与说明。
- 故障点至少覆盖：下载中断、候选校验失败、写 manager 失败、切换前 `SIGKILL`、入口切换后 `SIGKILL`、cron 迁移后中断、服务检查失败、恢复失败。

## 6. 配置真相来源

- `/etc/idleleo/conf/xray/config.json`（或项目确实使用的运行路径）是**现有运行配置事实**。新 manager.json 是**管理意图、受控字段、资源所有权、摘要**，不是一个能覆盖整个 Xray JSON 的影子主配置。
- `privateKey`、UUID、shortId、公钥、额外用户、用户自定义 DNS/outbounds/routing 必须保留；manager.json 尽量引用，不重复保存敏感值。
- 当 Bash install_config 与真实 Xray 内核配置互相矛盾时，Bridge 需显示冲突并阻断激活，不能私自猜测哪一份正确。
- 已废弃 `XTLS ONLY` 需要特殊拒绝；不得误伤 Reality `xtls-rprx-vision`。

## 7. 外部更新与辅助脚本

- 无 Go 额外开放端口、强制 daemon、数据库或 web。
- 保留受控且必要的 ACME Shell、Rill Python / 组件；任何外部命令通过 Go `exec.CommandContext` 的明确 argv、超时、输出脱敏和错误码管理，杜绝字符串拼接 shell。
- 保留 Nginx 定制构建 Release 的 checksum 校验；不要把 SHA 与目标文件取自同一个未锁定的任意 URL 就宣称获得完整发布者验证。
- 不直接删除整份 root crontab、所有 Fail2ban `.local`、系统全局 limits 或自动禁用 SELinux。

## 8. 发布前的不可妥协核验

1. 两条 metadata 字段、tag、artifact、workflow 独立，老脚本自动更新只看到 Bash。
2. 测试 Bridge-aware Bash 的**手动与自动**路径，而非只测试 Go Bridge 程序。
3. Go 实际管理 Xray 的基本命令已先达到 Phase 02 完整性要求。
4. Debian/Ubuntu 代表性 VPS 实测成功迁移和失败恢复；必须记录服务可用性与用户资产原样。
5. 对当前 `Test Install / Stats Readout Ubuntu 24.04` 失败给出根因/修复或明确阻断发布，不能删除失败 job 或宽松跳过。
