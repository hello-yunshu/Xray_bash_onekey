# 深度源码与发行链审计报告（v4）

## 1. 审计对象、证据等级与限制

- 主仓库：[`hello-yunshu/Xray_bash_onekey`](https://github.com/hello-yunshu/Xray_bash_onekey)，`main` Git tree SHA `4752f77c58028ac169c429fe7674c20060b30c9e`；最新 Release `v3.3.4`，发布时间 2026-11-05 UTC。`install.sh` 16,112 行、约 693,554 字节，Git blob SHA `068887a6f1e3eaf7662bb7a3eead765181b5ad4d`。
- 仓库树可枚举为 295 个条目、253 个文件；`.github/test/` 82 个文件、工作流 7 个、`scripts/` 下 Shell 文件 14 个。**数量不等于测试全部通过或实际覆盖率。**
- 额外核对：[`Xray_bash_onekey_api/xray_shell_versions.json`](https://github.com/hello-yunshu/Xray_bash_onekey_api/blob/main/xray_shell_versions.json)、[`Xray_bash_onekey_Nginx`](https://github.com/hello-yunshu/Xray_bash_onekey_Nginx)、Rill 集成文件、Docker 入口与 GitHub Actions 运行结果。
- **证据标记**：`S` = 源码逻辑直接证实；`CI` = GitHub Actions 实际运行状态；`P` = 本包的隔离 Go 程序已执行；`H` = 合理风险/需求，但尚无实机故障证据。请勿将 H 说成已经复现的生产事故。
- 本次没有从 GitHub 完整克隆源码、没有运行旧版 Bash 的整个测试矩阵、没有 SSH 到 VPS，也没有修改线上文件。源代码审计以 GitHub 接口实际提取的关键文件与函数为范围，**不是对 253 个文件逐行、逐依赖的全覆盖审计**。

## 2. 优势（不要在 Go 中丢掉）

| 编号 | 资产 | 源码依据 | Go 继承原则 |
|---|---|---|---|
| A01 | Xray Reality/TLS/ws/gRPC/xHTTP 与组合模式、用户管理、双栈、分享信息 | [`install.sh` 的安装、用户、菜单分发](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh) | 完整行为映射，禁止“只迁移常见模式” |
| A02 | 独立单目标 Nginx Stream 中转（与 Reality 主/次级模式不同） | `install.sh:11143–11951`；[`test_relay_container.sh`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/.github/test/test_relay_container.sh) | role 单一所有权、纯中转不装 Xray |
| A03 | 重配置快照、配置校验、失败恢复 | `install.sh:14250+`；[`test_reinstall_call_chain.sh`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/.github/test/test_reinstall_call_chain.sh) | 迁移行为预期，不复制巨大 Bash 事务实现 |
| A04 | Nginx 固定 Manifest/SHA256 与更新回滚 | `install.sh:6547+`；[`定制 Nginx`](https://github.com/hello-yunshu/Xray_bash_onekey_Nginx) | 保留发布验证，避免不受控下载 |
| A05 | GeoData 原生热更新及旧 cron 清理 | `install.sh:5516+`；[`test_geodata_native.sh`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/.github/test/test_geodata_native.sh) | 原生机制主导，Bridge 只处理遗留数据 |
| A06 | 证书恢复锁、服务原状态保留 | [`ssl_update.sh`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/scripts/ssl_update.sh) | 保留故障恢复，减少无效停服 |
| A07 | Rill 的独立契约与 CI 测试链 | [`Rill 工作流`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/.github/workflows/rill-xray-agent.yml) | 可选受控适配，不成为 Go 强制依赖 |
| A08 | 数字菜单、窄终端与多语言、JSON stats、固定退出码 | README、`install.sh:12954+`、`install.sh:15858+` | 优先维护 SSH 的成熟体验 |

## 3. 风险与修订台账（按影响排序）

| ID | 等级 / 证据 | 源码位置 | 实际问题 / 设计风险 | 必要处理阶段 |
|---|---|---|---|---|
| R01 | P0/S | [`install.sh#L15111-L15119`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L15111-L15119) | 用户增删先 `service_stop` 后 `add_user && service_start`；配置写失败时无法保证重启 | 00 记录、02 修复；建议 Bash 热修 |
| R02 | P0/S | [`fail2ban_manager.sh#L1087-L1101`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/scripts/fail2ban_manager.sh#L1087-L1101) | 卸载 `rm -f /etc/fail2ban/jail.d/*.local`，可能删除无关 Jail | 00 归属、02 修复；建议 Bash 热修 |
| R03 | P0/S | [`install.sh#L1276-L1296`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L1276-L1296) | Rill `.py` 用 `bash` 启动，失败通过 `|| true` 被吞 | 02；建议 Bash 热修 |
| R04 | P0/S | [`install.sh#L2472-L2485`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L2472-L2485) | 自动改全局 nofile、禁用 SELinux | 00/01/02 禁止默认行为，不倒改用户旧值 |
| R05 | P1/S | [`install.sh#L533-L558`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L533-L558)、`16065+` | 默认菜单经过在线版本下载，网络异常阻断管理入口 | 01 本地菜单必须离线 |
| R06 | P1/S | `install.sh:15903–15956`、`10751–10795` | 纯只读类中的 `--show`/`--stats` 存在文件写入、下载或交互修复路径 | 01/02 命令副作用严格分类 |
| R07 | P1/S | [`install.sh#L9963-L10007`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L9963-L10007) | TLS 变更直接 `sed -i` 然后重启，缺统一候选 Nginx 校验与回退 | 01 安全写入、02 落实 |
| R08 | P1/S | [`install.sh#L8693-L8712`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L8693-L8712) | 以文件 mtime 推算证书 90 天，不读取 X.509 NotAfter | 02 修复 |
| R09 | P1/S | `install.sh:10823+`、`15218+` | TCP/测速从变化的远程 URL 拉脚本执行；`bash -n` 不是签名/哈希来源证明 | 00 资产准入、02 安全重做或明确延期 |
| R10 | P1/H | `install.sh:13828+`、`14250+` | 备份/恢复虽有 SHA256 和暂存，但允许文件成员、软链及全机覆盖范围仍要做恶意归档测试 | 01/02 受控恢复、03 旧档导入 |
| R11 | P1/S | `install.sh:10943–10953`、`7283–7314` | 直接编辑 root cron 相关文件及删除通配匹配可能影响其他软件任务 | 02/03 独占任务指纹与精确撤销 |
| R12 | P1/S | [`file_manager.sh#L160-L210`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/scripts/file_manager.sh#L160-L210) | 单独追加 iptables 并持久化，未必在统一防火墙事务中登记 | 02 收敛到单一所有权 |
| R13 | P1/S | [`ssl_update.sh`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/scripts/ssl_update.sh) | 即使证书未变化也先停 Nginx、可能重启 Xray；已有恢复保护不能消除正常路径中断 | 02 先检查、后必要 reload/restart |
| R14 | P0/S | [`auto_update.sh#L394-L454`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/scripts/auto_update.sh#L394-L454) | 老自动更新依据 `shell_online_version` 运行 Bash `install.sh -u auto_update`；无法直接将旧发行物替换为 Go | 00 发布契约、03 正式 Bridge-aware Bash |
| R15 | P0/S | [`Xray_bash_onekey_api`](https://github.com/hello-yunshu/Xray_bash_onekey_api/blob/main/xray_shell_versions.json) | 目前 `shell_online_version:3.3.4`、`shell_release_sha256` 等用于 Bash；Go 需独立发行字段/资产 | 00/03/04 两条通道独立测试 |
| R16 | P1/S | `install.sh:10931+`、`docker/docker-entrypoint.sh` | 容器依赖假 systemctl、Shell 入口、watchdog；直接用宿主 Go systemd DBus 实现不能覆盖 Docker | 00 明确交付差异、02/04 单独构建验收 |
| R17 | P1/S | `install.sh:9101+`、`10375+` | install_config 与 Xray 原生配置存在 privateKey、UUID、shortId 和自定义 routing 等关系；盲目生成新 JSON 可能覆盖原配置 | 00 字段表、01 读取保护、02 编辑器 |
| R18 | P1/S | `install.sh:12988+`、`README 旧 XTLS 描述` | `XTLS ONLY` 已禁止新建，但历史旧状态仍在；Go 不能激活后才发现无法管理 | 00/03 Bridge 必须阻断 |
| R19 | P1/CI | [主分支失败运行 #42048259341](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/42048259341)、[PR 运行 #42061871135](https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/42061871135) | 2026-11-05 `Test Install` 失败，至少包括 `Stats Readout (ubuntu:24.04)`；本次未获得失败日志，根因**未知** | 00 查明；04 禁止掩盖红灯 |
| R20 | P1/S | [`test-install.yml#release-gate`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/.github/workflows/test-install.yml)、发布工作流 | 看到部分运行中 `release-gate` 单 job 成功、整体工作流失败；需核实引用矩阵状态和 release workflow 的 `qualify` 是否真正阻断发行，不可单凭该 job 绿灯判断通过 | 00/04 对真实需要的 gate 输出做端到端核查 |
| R21 | P1/H | `install.sh:11143+`、`11676+` | relay 独立角色与 Reality primary/secondary 不同；只迁 relay 会漏主次负载均衡 | 00 功能矩阵、02 实测 |
| R22 | P1/H | 旧 `install.sh` 入口和 `/usr/bin/idleleo` symlink | 迁移期间 SSH 断开、`SIGKILL`、重启可能停在入口已换但事务未提交状态 | 03 持久化 journal + 独立恢复执行器；原型 P 验证 |
| R23 | P1/S | `install.sh:4971+`、`ssl_update.sh` | Xray 服务账户、Nginx 读证书组、日志权限有特定约定；迁移后不能凭空改服务用户或权限 | 00 资源图、02/03 实测 |
| R24 | P2/H | Xray/定制 Nginx/Rill 三条发布链 | 多仓库实际发布物版本可能不同步；必须固定测试的精确 Release 与证据 | 00 固定、04 可追溯 |

> **优先级说明**：P0 = 迁移前必须制定并验证保护策略或修复明确危害路径；P1 = 正式发布前必须闭环；P2 = 可以在阶段内核验并记录。R19–R20 是**当前 CI 状态风险**，不应被说成已经找到具体 Stats bug；需下载日志复现定位。

## 4. 发布链特别结论

读取 `Xray_bash_onekey_api` 后确认：Bash 的主版本来源依旧是 `shell_online_version` 和 `shell_release_sha256`；Xray 安装器有固定 commit/sha，定制 Nginx 有自己的构建号和 manifest。旧自动更新调用当前 Bash 路径而非通用安装器。因此：

1. Go 发行资产不得覆盖 Bash 版本字段，也不得把旧版本 `install.sh` 候选文件伪装成 Go 安装器。
2. **必须先发布 Bridge-aware Bash 过渡小版本**，它可被旧 Bash 自动更新安装，但它自己在自动/无 TTY 情况下绝不能下载 Go 迁移包。
3. 只有经过手动 TTY 用户确认，才进入下载 Bridge/Go 候选并迁移。用户拒绝时原 Bash 完全正常。
4. 现有 README 的 `releases/latest/download/install.sh` 仅适用于所指最新 Release 的资产；Go 正式发行时要验证新用户入口与旧版本固定标签下载不串线。
5. 发布时需要直接检查 `qualify` 和 `release-candidate-gate` 的真实成功条件，不能只看 GitHub Release 是否存在。

## 5. 必须回归的功能类别

旧功能总账见 `TRACEABILITY_MATRIX.md`。另外几个容易遗漏的边界：

- JSON `--stats --json` 输出/退出码 `0/1/2/3/4/5/130` 需逐个比对（来源 [`README`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/README.md)）。
- 独立 Relay 无 Xray；Reality 主/次负载均衡仍有 Xray，与 Relay 不是同一角色。
- Docker 容器无需真实 systemd，首版不能直接把容器内 fake-systemctl 契约删掉。
- `privateKey`、`password` 公钥兼容、UUID、shortId、spiderX、multi_user 和 `reality_clients` 不可静默再生成。
- GeoData `managed/custom/absent/invalid` 不同状态需保持对用户自定义配置的尊重。
- Rill Agent 可卸载、可关闭、可观察，Go 管理器无 Rill 时仍能启动；脚本解释器错误需明确修复。
- SELinux、全局文件句柄配置、用户 Fail2ban jail/crontab 的非自有状态不自动“反修复”。

## 6. 审计未完成项（禁止伪称完成）

- 尚未取得 GitHub Actions 失败步骤的原始 stdout/stderr，因此 Stats Ubuntu 24.04 的根因及 release gate 的表观结果差异仍需进一步核实。
- 没有真实 VPS 的证书续期、实际 Xray/Nginx 的热/重载、systemd 系统级权限、IPv6 双栈、Docker 运行态或 arm64 真机执行记录。
- 未对整个仓库运行 SAST、完整 Bash CI、真实代码覆盖率统计，且未验证用户私有配置变体的发生频率。
- 本包的 Go Bridge 原型并不处理真实定时任务、受控下载、Rill 状态、版本升级器及服务停启，请勿直接生产使用。

## 7. 由审计驱动的优先顺序

**先补基线和受控切换契约** → Go 原生读写与核心变更 → Xray 全功能闭环 → 手动 TTY Bridge 和持久恢复 → 完整实机与发布门禁。Bash 需要的高风险热修（R01/R02/R03）可与 Go 并行单独提交，但不得合并成对老用户不受控的“自动迁 Go”。
