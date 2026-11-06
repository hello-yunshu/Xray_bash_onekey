# Phase 02｜完整 Xray/Relay 业务迁移、安全默认值和辅助能力

**阶段性质：** 实现现有 Bash 功能在 Go 中的生产级替代，但**仍不将旧用户自动切到 Go**。Phase 01 已交付统一 CLI、文件事务、锁、服务执行器和配置只读视图。

## 0. 本阶段的“完整”是什么意思

不只实现 Reality 一键安装。必须对照 `reference/TRACEABILITY_MATRIX.md` 的 F01–F28，覆盖 Xray 节点、Reality 主/次级负载均衡、Nginx TLS、无 TLS 可信后端、独立 relay、双栈、用户/分享、证书、统计、备份、更新、GeoData、Rill 受控接口与 Docker 交付边界。

- **可以**把 TCP 优化/测速这种不安全的第三方脚本功能列入“有明确说明的延期/安全替代”，但不能无提示删除其他业务功能。
- **不做** sing-box 全功能、Web、通用 Linux 面板、跨主机管理、动态插件。
- 当前 Bash 的系统级副作用是**反例**，不是需要照搬的“行为兼容”。
- 所有功能必须走 Phase 01 的受控执行/文件变更路径；不得 Go 包调用 16k 行 `install.sh` 来“完成”业务。

## 1. 三组内部交付（不增加总阶段数）

### 02A｜Xray 配置、用户与客户端交付

**A1. 模式/角色建模**

- Reality 原生配置：VLESS、raw、Reality/TLS 相关验证、`xtls-rprx-vision` 合法能力、`minClientVer` 及已有服务端版本差异；需要 Nginx 的 Reality 组合仍保留。
- Nginx+TLS：ws、gRPC、xHTTP 单选与组合、TLSv1.3 配置行为；无 TLS ONLY 默认回环 `127.0.0.1`，选择可信非回环地址必须用户确认。
- Reality 主服务器/二级后端负载均衡，不等同于独立 relay；状态与用户配置转换不混用。
- 数据模型区分 `role`、`tls_mode`、`transport_mode`、`reality_add_nginx`、`reality_balance_role`、`network_mode`；未知历史值不自动映射为“默认 Reality”。

**A2. 配置编辑而非全量覆盖**

- Xray 原生 JSON 是实时配置事实源；生成新配置用于**新安装**。已有节点修改端口/用户/目标时，读取最新 JSON，对指定字段安全编辑，保留用户添加的 DNS、routing、outbounds、stats、未知但合法的键。
- 对 `install_config.id` 与 `inbounds[].settings.clients[]` 的多用户关联建立显式一致性检查，尤其主用户不可误删；维护 Reality `shortIds`/`spiderx_path` 与 `reality_clients`。
- `keep_config / standard_rebuild / mode_switch` 三种重配行为区别明确；模板重建可能删除自定义字段/多用户时提前展示差异、提供备份和确认，默认拒绝高损失操作。
- 配置候选必须以当前 Xray 可执行程序执行 `xray run -test -config <candidate>`；对涉及 Nginx 的工作，要测试包含实际 include 的完整候选 Nginx 上下文，不能仅 `nginx -t` 生产配置后声称候选通过。

**A3. IPv4/IPv6、连接分享**

- DNS A/AAAA、IPv4/IPv6 出口及监听能力、双栈选择、IPv6 URI 字面量中括号、证书/域名对应关系逐项测试。
- 生成 VLESS URI、二维码、Clash 配置；Clash 不兼容的 xHTTP 不生成假支持项，要显示准确限制。
- `--show` 运行时渲染，不依赖旧生成的 info 文件作为可被自动重建的唯一真相；不落盘私钥到额外文件。

**02A 实测：** Reality/TLS/ONLY 与组合至少生成一组真实 Xray 配置通过 `-test`，自定义 DNS/outbounds/routing 变更前后比较，用户增删失败/主用户保护/多用户与 shortId 关联、双栈输出合规。对应 F01–F04/F06–F08/F17–F19/F28。

### 02B｜服务、安全、Nginx 与独立中转

**B1. Xray 安装和更新**

- Go 原生管理 Xray 二进制、文件权限、systemd unit、启动及更新状态。下载只采用固定可信发布通道和哈希校验，拒绝降级；不得用旧 Bash 主安装器在背后做核心决策。
- 正式实现服务前读取 Xray 当前服务账户，保留已有 `User=xray` 或合法既有账户；不能因为 Go 切换让服务变为 root。检查配置、证书、日志目录的可读/可写和所有权。
- 修改服务单位、reload/restart 的边界有回滚：重要端口、用户、TLS、Reality、统计等变更失败后恢复原配置与原 active/enabled。无需重载时不任意重启。

**B2. Nginx 与证书**

- 使用项目定制 Nginx 的固定 Release+manifest+SHA256；保留可识别的安装目录、编译参数、工作账户与证书访问权限；Nginx 更新和 Xray 更新相互独立。
- 生成/调整专有 Nginx include 片段并测试；不能删除用户自定义片段，不能无审计替换现有第三方 Nginx。
- 证书有 `crypto/x509` NotAfter/NotBefore，签发/续期可以使用明确且固定的 acme.sh 受控辅助工具。证书不变化时不自动停服；变化后选择最少干扰的实际生效方式并验证。
- Reality + Nginx SNI Guard 继续保持默认保护；未知 SNI 策略、TLS 版本/权限/监听范围都要经真实服务检查。

**B3. 独立中转/防火墙**

- 只装单目标 Nginx Stream 的 relay：安装、状态、修改 backend、改监听端口、测试目标可达、错误日志、卸载、更新。不得把 relay 与 Reality 主/次级负载均衡混同。
- 项目创建的 firewall 规则要有归属标记/端口集台账和撤销记录；移除规则不能删除同端口的用户其他规则；IPv6 与 IPv4 规则一起维护。
- 不默认修改 `/etc/security/limits.conf` 或禁用 SELinux；遇到 SELinux Enforcing 的访问问题只报告、使用服务级或必要上下文策略，不能偷改整机安全设置。

**02B 实测：** 真实 systemd/Xray/Nginx、故障注入 Nginx -t 与 Xray -test 失败、更新哈希/降级、运行态恢复；relay 必须跑 TCP 字节转发（而非只启动 Nginx）；Reality primary/secondary 与 relay 分别验证。对应 F04/F05/F09–F14/F17。

### 02C｜统计、GeoData、安全辅助、备份与可选 Rill

**C1. 日常运维与统计**

- `--stats`、`--stats --json`、`--stats-watch`、`--stats-reset`、权限与退出码保持旧正式契约。`status/show`/统计读取绝不能下载脚本、修改 Xray JSON、删除旧文件或要求用户确认修复。
- 统计启用/禁用是显式有中断提示的变更，候选配置验证通过后应用；端口默认仅 `127.0.0.1:10085`，无鉴权风险要写进帮助。
- access/error 日志查询、按需清理、敏感输出脱敏、日志保留大小可控；流量阻断不破坏用户自定义路由；GeoData 由 Xray 原生刷新，区分 `managed/custom/absent/invalid`。

**C2. 系统安全辅助**

- Fail2ban 可选安装/管理 trusted/unban/状态，但只能编辑项目自有精确文件，保留第三方 Jail、`jail.local` 和用户单独安装的服务。
- 定时任务（证书/Go/Xray/Nginx 更新）尽量使用明确受控的单位或精确识别 crontab 条目；不能清理整个 root crontab。
- 备份包含有清单、SHA256、文件类型与路径限制的**受控资源**，敏感包 `0600`；恢复不允许越界、符号链接逃逸、硬链接/设备文件等危险成员，跨旧备份归类给 Phase 03 的受控导入。
- TCP 优化/测速若无法在固定可信版本、最小权限内安全实现，则记录延期原因、原命令的拒绝输出和可行替代，不能继续 `curl master`→`bash`。

**C3. Rill 与 Docker（保持独立）**

- Rill 是可选独立 Agent，Go 通过受控固定协议调用；修正 `rill_xray_agent_observe.py` 错误解释器；其授权/观察模式切换与两阶段卸载不能失效，缺 Rill 时 Go 常规操作完全正常。
- 容器镜像仍能管理既有 Xray/Nginx；当前 `docker/docker-entrypoint.sh` 依赖 Bash 入口与 fake-systemctl，Go 容器管理器不能直接假设系统 systemd/D-Bus 可用。Docker runtime adapter 与宿主机 unit adapter 分离；完整容器运行验收在 Phase 04。

**02C 实测：** `--stats --json` 对照并定位原 CI Ubuntu Stats 失败、GeoData 热更新、Fail2ban 非自有规则存活、恶意备份拒绝、Rill 无/有两种情况及 Docker 容器启动检查。对应 F12–F16/F18–F25/F27。

## 2. 旧 CLI 兼容表必须真正落实

Phase 00 已把旧命令划成：

1. **硬兼容**：`--show`、`--backup`、`--restore`、`--stats --json`、`--stats-reset --yes`、`--stats-watch`、`--xray-update`、`--nginx-update`、`--service-*` 等有自动化用途的参数；语义、参数、副作用边界与退出码按单项契约确认，输出不能伪成功。
2. **旧模式明确拒绝**：`--install-xtls`/`XTLS ONLY`；需要有非零状态与解释，不自动回菜单。
3. **安全性改变**：不安全 `--tcp`/测速入口只能提供安全重做或明确废弃帮助；必须在更新说明中列出。
4. **新增 Go 子命令**：`idleleo xray ...`、`idleleo cert ...`、`idleleo relay ...` 等，保持单一执行逻辑，旧 flag 只做薄路由，不能有两份业务实现。

`--update` 在本阶段实现 Go 正常更新的接口，但**老 Bash 手动迁移触发**直到 Phase 03 才接入。不要混为一谈。

## 3. 阶段内部 PR/验收交付

| 批次 | 推荐 PR 范围 | 必须提交的证据 |
|---|---|---|
| 02A-1 | Reality/TLS/ONLY 配置结构与生成 | 当前 Xray 真正 `run -test`、双栈/分享配置解析 |
| 02A-2 | 多用户、shortId、spiderX、原生配置增量变更 | 自定义字段 SHA/JSON 差异、失败回滚及主用户保护 |
| 02B-1 | Xray systemd + 版本/下载 + Nginx 定制发布 | 安装/更新/失败/降级/权限回归 |
| 02B-2 | Reality primary/secondary、relay、Nginx/证书/防火墙 | Nginx -t 与 relay TCP 转发、服务状态恢复 |
| 02C-1 | 统计/日志/GeoData/流量规则 | JSON 合约/退出码、原生刷新/自定义路由不丢 |
| 02C-2 | 备份、Fail2ban、ACME、Rill、Docker 容器适配 | 恶意归档、第三方 Jail 保留、证书中断恢复、Agent 可选性 |

允许根据工程依赖合并小 PR，但不要把所有业务一次提交到一个巨大的“完成 Phase 02”变更。

## 4. 强制失败注入（真实逻辑）

- Add-user 输入 EOF、写入失败、主配置 JSON 不合法、Reality shortId 写入失败：原服务始终恢复正确原状态。
- 修改端口、Nginx TLS、路由、证书：候选校验失败/目标文件无权限/服务重启失败/磁盘满时有明确结果。
- Nginx binary 更新：manifest 不匹配/架构不一致/解压安全/校验失败不替换原版本。
- Root cron 带用户自定义任务、Fail2ban 带自定义 Jail、iptables 带同端口非自有规则：操作后原内容仍在。
- 自定义 Xray `routing/dns/outbounds` + 第二用户保持；不支持的修改拒绝，不能清空。
- 正常未启用的服务不因错误恢复被误启；日志/权限不泄露私钥。

## 5. 阶段退出门禁

- [ ] F01–F24、F26–F28 都有实际 Go 路径/明确批准的拒绝状态和验证记录；F25 有文档化安全取舍。
- [ ] Xray/Reality/TLS/ONLY、主次负载均衡、独立中转所有正常安装模式均已真实配置校验并在适用环境启动。
- [ ] 用户增删、端口与 TLS/规则、重装切换都通过恢复故障注入，原正常服务不因失败遗留停止。
- [ ] 证书、GeoData、统计、IPv6、分享信息、完整备份/恢复都对照旧格式验收。
- [ ] 任何高权限清理不会扫掉非自有 Fail2ban/cron/firewall/自定义 Nginx 文件。
- [ ] Docker 的已交付功能与宿主边界明确，容器启动有实证；Rill 不参与 Go 必需启动链。
- [ ] Go 日常功能不调用旧 Bash 单体管理核心；无 Web daemon/数据库或额外管理端口。
- [ ] 尚未通过的功能显示 `Blocked/Unverified`，不得凭 README 声称“完整 Go 迁移”。
- [ ] 本阶段结束**仍不触发旧用户 Go 迁移**；独立候选已具备下一阶段的必要管理功能。

## 6. 开发智能体指令

> 只执行 Phase 02。逐项核对 F01–F28，在 Go 中完成 Xray 的完整业务原生管理与独立 relay，分 02A/02B/02C 逐组提交和验证。优先保证自定义配置、UUID/Reality 私钥/shortId、证书、旧运行路径与服务状态不丢失。所有系统写入进入 Phase 01 的统一受控变更层；修复 Bash 的风险不能用另一套 Go 隐性副作用替代。不要开发 Web、sing-box、插件商店或生产 Bridge。每组给出真实目标配置的检查结果、失败注入和尚存差异表。


## v6 新增验收门槛：按功能域逐项解除 F01–F28 PENDING

- **02A 配置/用户/分享**：Reality 单/多用户、TLS ws/gRPC/xHTTP 组合、无 TLS 默认回环、SNI/shortId/spiderX、路由/DNS 自定义保留；逐场景 Bash 输入 ↔ Go 配置语义比较，真实 Xray `run -test`。
- **02B Nginx/证书/中转/更新**：旧 Bash 产生的 Nginx 片段 ↔ Go 配置、`nginx -t`、relay TCP 字节转发、证书无变化重启抑制、failpoint 回滚；兼容更新链。
- **02C 辅助/运维**：GeoData、统计 JSON/退出码/负权限、Fail2ban 只清理项目 jail、IPv6/防火墙、Rill 可选与 Docker 入口。
- 每个 PR 至少交付 `fixtures + 双实现差分/安全分歧记录 + 故障注入 + 真实内核校验`，在 `parity/cases/feature_contracts.json` 关联具体证据。
- **出口门槛**：功能矩阵不得存在静默 PENDING；允许经批准的安全性差异与明确废弃，而不是复刻 Bash 问题。

## v6.1 阶段验收强制补充
- 逐功能编写 `parity/features/Fxx_test.py`，不得创建仅输出 PASS 的空壳。先从 F01 Reality、F02 TLS、F05 Relay、F06/F07 用户、F12 证书、F15 GeoData、F20/F21 备份与更新、F26 CLI 开始。
- Bash/Go 使用相同的脱敏输入与初始 VM 状态；比较 Xray/Nginx 解析语义、实际服务状态、出站握手/转发、配置哈希、权限与异常恢复。
- 允许经过批准的安全行为差异，但必须真实测试 Go 的更安全行为，不能修改 Bash oracle 或伪造结果。
