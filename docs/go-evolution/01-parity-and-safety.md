# 第一阶段：迁移差异与安全收口

- 分支：`work/go-evolution-audit-20261118`
- 基线：`develop/go-native` = `d4858a1150d3f83202e95aa9dfea2244832c8b3e`
- Bash 对照固定点：`3b2a5045fec4535e189a0b25ca27dc534945bab5`（release/3.3.6）
- 本轮新增实跑：2026-11-18，容器 `e2e-goevo-ops-bash` / `e2e-goevo-ops-go`
- 证据目录：`tests/e2e-diff/evidence/goevo-ops-20261118/p1/`

## 1. 结论

1. 安装/数据面：沿用同日真实全量矩阵 `tests/e2e-diff/evidence/20261118-0605-full`（commit `47a370e5`）。M1–M10 两侧 `rc=0`，L4 首轮与二轮均 `ok`，L6 均通过；E1–E8 全部 PASS。该证据早于基线 5 个提交，期间没有安装路径改动，报告按“同分支、同日、较早提交”标注，不冒充基线逐字节复跑。
2. 运维面：本轮在真实容器内重跑 8 个 OPS 场景（Bash 与 Go 各一套真实安装），得到 7 个有双端输出的差异；其中 5 个可直接对照（OPS-01/11/15/22/29），2 个为受限采集（OPS-12/13 的 Bash 端是 `tail -f`，截取 6 秒）。
3. 发现并修复一个真实缺陷：`tcp status` 在标准 Ubuntu 上因 `/etc/sysctl.d/99-sysctl.conf` 是符号链接而直接报“配置损坏”。修复为只读扫描跳过发行版符号链接，写路径仍拒绝符号链接；同时修正 sysctl 解析把 `-key = value` 的忽略失败前缀当成键名的问题。
4. P0 安全收口与统一变更契约已落地：审计行脱敏、`--private-key-file`、写前共享变更计划 `plan.json`。

## 2. 环境与真实性

| 项 | 事实 |
|---|---|
| 宿主机 | macOS arm64，**没有 Go 工具链** |
| Go 构建/测试 | `golang:1.27.4` 容器，`GOFLAGS='-mod=vendor -buildvcs=false'` |
| 实机镜像 | `idleleo-e2e:24.04`（systemd、Xray 26.10.31、nginx、expect） |
| egress | 容器无法访问公网 DNS，`api.ipify.org`/`raw.githubusercontent.com` 均不可达 |
| 离线安装 | 通过容器内本地响应器提供 `ip.me=198.51.100.10`，并用受信本地 TLS 镜像返回仓库自带的 `config/vless_reality.json`；安装脚本、菜单、systemd、Xray 均为真实执行 |
| 两侧状态 | Bash 与 Go 各自独立安装，`systemctl is-active xray` 均为 `active`，均生成 1 个 Reality 用户 |

离线镜像只替换“内容从哪里下载”，没有改写安装脚本或放宽校验；镜像证书仅加入该一次性容器的信任库。报告不把外部不可达当作产品缺陷，也不把镜像结果当作公网安装证据。

## 3. 安装/数据面（沿用同日实跑）

来源：`tests/e2e-diff/evidence/20261118-0605-full/p2/install-matrix.md`

| 场景 | Bash | Go | 判定 |
|---|---|---|---|
| M1 reality-standard | rc0 / L4×2 ok | rc0 / L4×2 ok | PASS（仅登记布局 ED） |
| M2 reality-nginx | rc0 / L4×2 ok | rc0 / L4×2 ok | PASS |
| M3 reality-transport | rc0 / reality+ws ok | rc0 / reality+ws ok | PASS |
| M4 tls-ws | rc0 / ws ok | rc0 / ws ok | PASS |
| M5 tls-grpc | rc0 / grpc ok | rc0 / grpc ok | PASS |
| M6 tls-xhttp | rc0 / xhttp ok | rc0 / xhttp ok | PASS |
| M7 tls-ws-grpc-xhttp | rc0 / 三传输 ok | rc0 / 三传输 ok | PASS |
| M8 tls-acme | rc0 / ws ok | rc0 / ws ok | PASS |
| M9 none-ws | rc0 / ws ok | rc0 / ws ok | PASS |
| M10 relay-stream | rc0 / relay ok | rc0 / relay ok | PASS |
| E1–E8 配置编辑 | — | 全部 PASS | PASS |

未覆盖：L2 全字段语义 diff、L6 之外的长期稳定性；见原矩阵“未覆盖/未验证”。

## 4. 运维面双端实跑

命令入口：

```bash
BASH_CTR=e2e-goevo-ops-bash GO_CTR=e2e-goevo-ops-go \
OUT=tests/e2e-diff/evidence/goevo-ops-20261118/p1/ops TIMEOUT=45 \
bash tests/e2e-diff/run_ops_probe.sh
```

| OPS | Bash 实际 | Go 实际 | rc（Bash/Go） | 结论 |
|---|---|---|---|---|
| OPS-01 查看用户 | `--show` 打印 Reality UUID/公钥 | `xray user list --path ... --json` 打印同一用户的结构化记录 | 0/0 | 等价；Go 需显式 `--path`（D2） |
| OPS-11 查看配置信息 | 主机、端口、flow、target、serverNames | JSON 含 inbound/host/port，但缺 target、serverNames、flow、publicKey、shortIds | 0/0 | 信息不全（D1） |
| OPS-12 访问日志 | `-xa 20` 持续跟随，截取 6 秒 | `service logs --unit xray --lines 20` 一次性快照 | 124/0 | 语义差异（D3），非失败 |
| OPS-13 错误日志 | `-xe 20` 读独立错误文件并跟随，截取 6 秒 | journal 合并 stderr，一次性快照 | 124/0 | 等价替代（D3） |
| OPS-15 服务重启 | `--service-restart` 成功 | `service restart --container` 成功 | 0/0 | 等价；输出格式不同 |
| OPS-18 TCP 加速 | 交互式开关，未在本轮执行 | `tcp status --json` 修复后 rc0，报告 `cubic`、缺 bbr 警告 | -/0 | 只读证据；修复见 §5 |
| OPS-22 清除日志 | `--clean-logs` 清日志后尝试装 logrotate，离线 apt 失败 | `xray logs clean --yes` 成功截断 | 1/0 | 真实差异（D4） |
| OPS-29 Rill 状态 | `--rill-agent-status` 返回未安装对象 | `rill status --json` 返回未安装对象 | 0/0 | schema 不同（D5） |

OPS-12/13 的 Bash 端是“持续跟随”，`TRUNCATED` 是采集方式导致的正常截断，不记为产品失败；Go 端为一次性快照，属安全替代。

### 差异清单

| ID | 差异 | 影响 | 处置 |
|---|---|---|---|
| D1 | Go `show` 不输出 Reality target/serverNames/flow/publicKey/shortIds | 迁移后“看配置”信息缺失，用户需改用 `xray share`/`config inspect` | 第二阶段补 `show` 字段（只读扩展，不改 schema 版本） |
| D2 | Go `xray user list` 必须显式 `--path`，Bash 自动发现 | 迁移脚本需补参数 | 记录为已知差异；默认路径可从 metadata 推导时再优化，不在本阶段改 |
| D3 | Bash `-xa/-xe` 跟随日志且错误日志独立；Go 用 journal 快照 | 实时排障体验不同 | 安全替代；Go 端可选 `--follow` 作为后续增强 |
| D4 | Bash 清日志顺带安装 logrotate；Go 只截断 | 离线/无 apt 环境 Bash 失败，Go 成功 | Go 行为更可预测；不复制 apt 依赖，写入迁移说明 |
| D5 | `rill status` 字段与文本不同 | 解析脚本需调整 | 安全替代；Go 只做只读状态，不接管 Rill agent |
| D6 | `tcp status` 在发行版 sysctl 符号链接上误报损坏 | 阻断只读诊断 | **已修复**：只读扫描跳过符号链接，写路径仍拒绝 |
| D7 | Go `service restart` 直出 systemctl 文本 | 输出格式差异 | 允许差异；退出码与真实状态一致 |

## 5. 本阶段修复

### 5.1 `tcpcfg` 只读扫描与解析

- `internal/tcpcfg/tcpcfg.go`：`readSource` 在 `!ours` 且错误为 `symlink refused` 时跳过，不再把 `/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf` 判为损坏；托管文件仍拒绝符号链接。
- `parseSysctl`：去掉键首 `-`（procps 的“忽略写失败”前缀），避免生成 `-net.core.default_qdisc` 这种伪键。
- 新增测试：`TestReadSourceSkipsDistributionSymlink`、`TestParseSysctlStripsIgnoreFailurePrefix`。
- 实机复核：Go 容器内 `tcp status --json` 由 rc4 变为 rc0，输出 `conflicts: []`，并给出“内核未列出 bbr”的真实警告。

### 5.2 P0 审计脱敏（commit `2a930874`）

- `internal/host/gate.go`：审计行只保留 `mode/operation/uid/pid/plan/flags`；`operation` 仅前 3 个命令词，未知 flag 的值一律 `<redacted>`，`plan` 为 argv 的 SHA-256 前 8 字节。
- `internal/host/gate_test.go`：金丝雀值不得出现在审计中；未知 flag 值必须被脱敏；同一 argv 的 plan 指纹稳定。
- `internal/cli/xray.go`：新增 `--private-key-file`（与 `--private-key` 互斥、≤4096 字节、非空），并在 `installSpecValues` 中按敏感值处理。

### 5.3 统一变更/回滚契约（commit `7c97256e`）

- 新增 `internal/change/plan.go`：`Operation/Resource/OldSHA256/NewSHA256/Changed/AffectedServices/DisconnectRisk/ValidationSteps/RollbackScope/Ownership/Fingerprint`。
- `internal/deploy/edit.go`：在任何写入前构建计划并写入备份目录 `plan.json`；dry-run 与 apply 的指纹必须一致（`TestEditPlanMatchesDryRunAndApply`）。
- 计划 JSON 不含密钥/口令；指纹对字段顺序不敏感、对内容变化敏感。

## 6. OPS-01..34 全量归类

归类口径：

- **必须迁移**：Go 有等价或更强入口，迁移脚本可直接改命令。
- **安全替代**：语义不同但风险更低/更可预测，需在迁移说明中写清。
- **不再提供**：破坏性或与 Go 设计冲突，明确不实现并给出替代路径。

| OPS | 名称 | 归类 | Go 入口 / 说明 |
|---|---|---|---|
| 01 | 查看用户 | 必须迁移 | `xray user list --path ... [--json]`；需显式路径（D2） |
| 02 | 添加用户 | 必须迁移 | `xray user add` |
| 03 | 删除用户 | 必须迁移 | `xray user remove` |
| 04 | 变更端口 | 必须迁移 | `xray config edit --port` / `change set-inbound-port` |
| 05 | 变更 UUID/映射 | 必须迁移 | `xray user uuid`（一次事务覆盖多 inbound） |
| 06 | 变更 target | 必须迁移 | `xray config edit --target`（默认回源探测，失败零落盘） |
| 07 | 变更 TLS 版本 | 安全替代 | `xray tls --version`；仅托管 Nginx，TLS 站只允许 1.3 |
| 08 | SNI Guard | 必须迁移（新装）/ 安全替代（存量） | `xray install/generate --unknown-sni-policy`；存量改策略需重新生成并走变更计划 |
| 09 | Nginx 负载均衡 | 必须迁移 | `xray balance list/add/remove`；矩阵 PASS |
| 10 | serverNames | 必须迁移 | `--server-names`（generate/install/config edit） |
| 11 | 查看配置信息 | 必须迁移 | `show`；字段缺口见 D1，第二阶段修复 |
| 12 | 实时访问日志 | 安全替代 | `service logs --unit xray` 快照；不再 `tail -f` |
| 13 | 实时错误日志 | 安全替代 | journal 合并 stderr；不再维护独立错误文件 |
| 14 | 端口实时流量 | 不再提供 | `stats` 给累计值；不实现逐端口实时速率 |
| 15 | 服务重启/启动/停止/状态 | 必须迁移 | `service status/start/stop/restart/reload` |
| 16 | 证书状态/有效期/自动更新 | 必须迁移 | `doctor`（到期）、`xray cert renew`、`schedule install`（自动续期） |
| 17a | 更新脚本 | 必须迁移 | `update check/apply`（Go 发布通道，manifest+SHA256） |
| 17b | 更新 Nginx | 必须迁移 | `update nginx` |
| 17c | 配置自动更新 | 安全替代 | `schedule` 的 `cert-renew/geodata-refresh/stats-collect/auto-update`；不静默重写用户配置 |
| 18 | TCP 加速 | 必须迁移 | `tcp plan/apply/rollback/status`；本阶段修复符号链接误报 |
| 19 | Fail2ban | 必须迁移 | `fail2ban status/install/banned/unban/trust/jail`；矩阵 PASS |
| 20 | 流量统计 | 安全替代 | `stats [--json]` 只读查询；不提供 Bash 的菜单式逐项展示 |
| 21 | 流量阻断 | 必须迁移 | `xray block ...`；apply 前 geo 检查 + `xray -test`，失败回滚 |
| 22 | 清除日志 | 安全替代 | `xray logs clean --yes`；不安装 logrotate（D4） |
| 23 | 服务器网速 | 安全替代 | 原生 `speedtest`；参数与 Bash 不同 |
| 24 | 刷新 GeoData | 安全替代 | `schedule run --job geodata-refresh`；受 URL/目录校验 |
| 25 | 备份管理文件 | 必须迁移 | 第二阶段 `backup create`（含 manifest/哈希/0600） |
| 26 | 恢复管理文件 | 必须迁移 | 第二阶段 `backup restore`（校验/暂存/失败回滚） |
| 27 | 清空证书文件 | 不再提供 | 破坏性动作；用 `backup create` + 重新签发/编辑证书 |
| 28 | 卸载 | 必须迁移 | `xray uninstall [--purge]` |
| 29 | Rill AI 状态 | 安全替代 | `rill status` 只读；Go 不接管 Rill agent |
| 30 | 修改语言 | 必须迁移 | 全局 `--lang zh/en/fr/fa/ru/ko`；无菜单内切换 |
| 31 | Reality 负载均衡 | 必须迁移 | `xray balance ... --upstream reality`；矩阵 PASS |
| 32 | 后端故障摘除 | 安全替代 | 生成 `max_fails/fail_timeout` 交给 Nginx；矩阵 PASS |

## 6.1 S1–S9 辅助脚本与 R1/R2 升级链

矩阵的 `subscripts`/`upgrade` 定义在 `tests/e2e-diff/matrix.json`；`run_p2_matrix.sh` 的 scope 只含 `installs/edits/ops`。辅助脚本已由 `tests/e2e-diff/run_s_scripts.sh` 单独实跑（S4–S9，见 §6.2）；S1–S3 仍是交互菜单脚本，其 Go 能力由 OPS 行覆盖。下表把“静态对照结论”和“实跑状态”分开写，避免把静态核对冒充成双端实跑。

| ID | Bash 入口 | Go 入口 | 归类 | 本轮状态 |
|---|---|---|---|---|
| S1 | `scripts/fail2ban_manager.sh` | `fail2ban status/install/banned/unban/trust/jail` | 必须迁移 | 交互菜单无独立驱动；能力由 OPS-19 双端实跑覆盖 |
| S2 | `scripts/traffic_blocker.sh` | `xray block ...` | 必须迁移 | 交互菜单无独立驱动；能力由 OPS-21 双端实跑覆盖 |
| S3 | `scripts/file_manager.sh` | `metadata export/import` + `backup create/restore` | 安全替代 | 交互菜单无独立驱动；能力由 OPS-26 单边与 `goevo-ops-20261119-0412` 覆盖 |
| S4 | `scripts/auto_update.sh` | `schedule install`（`auto-update` job） | 安全替代 | PASS（正常/重复/坏元数据 fail-safe） |
| S5 | `scripts/ssl_update.sh` | `xray cert renew` + `schedule` 的 `cert-renew` | 安全替代 | PASS（Pebble 真实续期/重复/CA 不可达恢复） |
| S6 | `scripts/geo_update.sh` | `schedule run --job geodata-refresh` | 安全替代 | PASS（真实下载/重复/下载失败不破坏现网） |
| S7 | `acme.sh`（`IDLELEO_ACME_LEGACY=1`） | `xray cert issue/renew` | 安全替代 | PASS（下载+安装+`--version/--help`）；真实签发 BLOCKED |
| S8 | `tcp.sh` | `tcp plan/apply/rollback/status` | 必须迁移 | PASS（sandbox 全链路 + 真实内核 fail-closed + 历史脚下载语法校验）；真实内核应用 BLOCKED |
| S9 | `superspeed.sh` | `speedtest` | 安全替代 | PASS（真实测速/重复/失败干净退出 + 历史脚下载语法校验） |

R1（官方升级路径，`idleleo xray install --keep-config`）：

- 同实现重复安装：M1–M10 的第 2 轮分别是 Go `--keep-config`、Bash 交互 keep-config，均 `rc=0`，L6 幂等检查 `ok`。
- **跨实现升级已实跑**（`tests/e2e-diff/run_r1_upgrade.sh`，证据 `goevo-r1r2-20261119-0420-6ad3be97/r1`）：M1（Reality 直连）与 M4（TLS+ws+Nginx）各建一个真实 Bash 安装，再由 Go `xray install --keep-config --binary /usr/local/bin/xray` 接管。
  - U1–U4：配置语义与**字节**均不变、证书/私钥哈希不变、`xray -test` 与 `nginx -t` 通过、服务保持 `active`、监听端口与 cron 表不变。
  - U5：接管前后各跑一次真实客户端（Reality / TLS+ws），均 `rc=0`。
  - U6：`status --json` 报 `.installed=true`，且分类与安装模式一致（Reality/raw、TLS/ws）。
  - U7：注入失败时拒绝接管且前态清单不变，见下。

R2（`idleleo bridge prepare/validate/activate`）：

- 实现与单元测试在 `internal/legacybridge`；实跑用同一 Bash 树，M1/M4 各 5 步全过，终态 `state=COMMITTED`，接管后真实客户端仍连通（同目录 `R2/`）。
- `bridge prepare` 会备份已存在的 metadata；`metadata import --from install_config.json` 在 Bash 树上成功且不改运行配置（OPS-26）。
- `validate` 在 M4 上回退到 Bash 布局的 `/usr/local/nginx/conf/nginx.conf`（修复项，见 `03-final-qualification.md` §6.6）。

升级失败注入（`matrix.json` 的 `upgrade.injections`，证据 `20261119-0440-8c002dde/r1`）：

| ID | 注入 | 结果 |
|---|---|---|
| I1 | 运行配置写入非法 JSON | 拒绝（`xray -test rejected the candidate for <config> `），单元/证书/cron 不变，输入字节不被覆盖，修好后服务恢复 |
| I2 | 移走证书/私钥 | 拒绝并指名缺失的 `xray.crt`，放回后 `xray -test` 与服务恢复 |
| I3 | 443 被占用（全新 Reality 安装） | 拒绝并报 `already in use`，不写运行配置、不写 unit |
| I4 | 配置目录只读挂载 | 拒绝并指名被拒写路径，解除挂载后配置字节不变；回滚无法恢复时保留 recovery journal，`idleleo xray recover` 清除后服务 active |

## 6.2 S4–S9 辅助脚本实跑（`run_s_scripts.sh`）

证据：`tests/e2e-diff/evidence/s-20261119-full/s`，commit `6de5ffb4`，**58 PASS / 0 FAIL**；容器出网开启，`check_evidence_hygiene.py --mask` 0 findings。

前提：S7/S8/S9 的第三方脚本在当前实现中已退役（acme.sh 仅保留一版 legacy 回退，tcp.sh/superspeed.sh 由 Go 取代），因此每行同时验证“历史脚本仍可下载”和“项目自有实现真实可用”，不把“仓库无本体”当作免测理由。

| 行 | 覆盖 | 关键证据 |
|---|---|---|
| S4 | 真实 Bash install 后的 `auto_update.sh`：正常、重复、坏元数据 | 正常/重复均 `rc=0`，日志含 `Script is up to date` 与 `Xray is up to date`；缺字段时 `rc=0` 且注明 `skipping update checks`，`install_config.json` 字节不变 |
| S5 | Bash TLS+ACME 安装 + Pebble，`ssl_update.sh` 真实续期 | 预置 1 天期证书进入续期窗口；续期后证书由 Pebble 签发、两次续期均成功；停掉 Pebble 后 `rc=1`，证书与 `nginx`/`xray` 状态保持不变 |
| S6 | `geo_update.sh` 真实 GitHub Release 下载 | 正常/重复 `rc=0`，两个 `.dat` 非空且版本入 `geo_version.json`；用失败 `curl` 注入后 `rc=1`，现网 `.dat` 哈希不变 |
| S7 | `get.acme.sh` 下载与安装（sha256 `8681df82…`） | 安装成功、`acme.sh --version/--help` `rc=0`；无 legacy 状态时续期 `rc=1` 并报 `acme.sh not found`；**真实签发 BLOCKED**（需真实域名+公网 CA） |
| S8 | `idleleo tcp` 全链路 + 历史 `tcp.sh` 下载 | sandbox 中 `plan/apply/apply(noop)/rollback` 全部 `rc=0`，drop-in 创建与删除、运行时值改回；真实内核因缺 `net.core.default_qdisc`/`bbr` 被正确拒绝（`rc=12`）；`tcp.sh` 下载 sha256 `0b7614e7…` 且 `bash -n` 通过；**真实内核应用 BLOCKED**（需真实 VPS） |
| S9 | `idleleo speedtest` + 历史 `superspeed.sh` 下载 | 真实验速与重复运行 `rc=0`，返回 `server`/`downMbps`；不可达端点 `rc=1` 且无 panic；`superspeed.sh` 下载 sha256 `5593e179…` 且 `bash -n` 通过 |

S7/S8/S9 的 `BLOCKED-*.md` 与 `S5/BLOCKED.md` 模板随证据保存；S1–S3 交互菜单本体没有独立自动化驱动，对应能力分别由 OPS-19/21/26 实跑覆盖。

## 7. 未验证 / 阻塞

- S7 的真实公网 CA 签发、S8 的真实内核 BBR 应用仍为 BLOCKED（分别需要真实域名与真实 VPS 内核），与 §6.2 的 PASS 不冲突：下载/安装/Go 实现与失败闭合均已实测。
- S1–S3 交互菜单本体没有独立自动化驱动；能力结论以 OPS-19/21/26 实跑为准（前两者双端，OPS-26 为 Go 单边）。

- 全量矩阵已于 2026-11-19 在恢复外网后完整重跑（`tests/e2e-diff/evidence/goevo-p3-matrix-0242-a9875aff/p2`，commit `be141822`）：M1–M10 双端两轮 `rc=0`、L4 真实客户端全 `ok`；本条此前的 BLOCKED 结论已被该证据取代。
- OPS-12/13 的 Bash 侧只做了 6 秒有界采集，不能证明长时跟随；Go 快照行为已实测。
- OPS-18 的 Bash 侧是交互菜单，本轮未执行开关动作；Go 侧已由 `goevo-ops-20261119-0412` 单边实跑 `tcp status`。
- OPS 未驱动的 11 行已用对应 F 夹具补齐 Go 单边证据（见 `03-final-qualification.md` §6.5）；连同此前 18 行，共 29 行只有 Go 单边实跑，没有 Bash 对照，双端缺口仍如实保留。
- OPS-09/19/21/31/32 已在上述矩阵中重跑并 PASS。
- S4–S9 已实跑（`s-20261119-full/s`，58/58），S1–S3 交互脚本体未执行，见 6.1/6.2；S7 签发与 S8 真实内核应用仍 BLOCKED。
- R1/R2 与 I1–I4 已实跑（见 6.1），仅 M1/M4 两个场景；M3（reality-transport）与 relay/负载均衡树的接管仍未覆盖。
- 端口预检只覆盖全新 Reality 直连安装；TLS/reality-nginx 由 Nginx 持有公网端口。

## 8. 复现命令

```bash
# Go 单测（宿主机无 Go，统一走容器）
docker run --rm -v "$PWD":/src -w /src \
  -e GOFLAGS='-mod=vendor -buildvcs=false' golang:1.27.4 \
  sh -c 'gofmt -l internal; go vet ./internal/tcpcfg && go test ./internal/tcpcfg ./internal/cli'

# 运维双端探针（需要已安装的 bash/go 容器）
BASH_CTR=e2e-goevo-ops-bash GO_CTR=e2e-goevo-ops-go \
OUT="$PWD/tests/e2e-diff/evidence/goevo-ops-20261118/p1/ops" TIMEOUT=45 \
bash tests/e2e-diff/run_ops_probe.sh

# R1/R2 接管 + I1–I4 失败注入（M1/M4，自建一次性容器）
E2E_ONLY=M1,M4 E2E_PATHS=both bash tests/e2e-diff/run_r1_upgrade.sh

# 矩阵未驱动 OPS 行的 Go 单边实跑
E2E_RUN_ID=ops-local bash tests/e2e-diff/run_ops_sweep.sh
```
