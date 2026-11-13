# bash 版 vs Go 版 Docker 差分测试与无缝升级验证计划（评审稿）

状态：待评审。本稿只描述方案，不含任何代码/脚本改动。

## 1. 目标与非目标

**目标**

1. 在 Docker 里分别以「真实用户视角」跑 bash 版（`install.sh` 菜单）与 Go 版（`idleleo` CLI），把所有可交互操作过一遍，逐项给出可复核的差异结论。
2. 覆盖 bash 版调用到的外部子脚本：`scripts/ssl_update.sh`、`scripts/geo_update.sh`、`scripts/auto_update.sh`、`scripts/fail2ban_manager.sh`、`scripts/traffic_blocker.sh`、`scripts/file_manager.sh`、legacy `/root/.acme.sh/acme.sh`、`tcp.sh`、`superspeed.sh`。
3. 验证「配置可用性 + 无缝升级」：bash 版真实生成可用配置（所有安装模式）→ 升级到 Go 版 → 配置兼容、状态延续、失败可回滚。

**非目标（本轮明确不做）**

- 不修改 `check_release_gate.py` 的 28 项判据，不改 `feature_contracts.json` 与 `assets/go/manifest.json`。
- 不修改 `tcp.sh` / `superspeed.sh` / `acme.sh` / helper / 版本 JSON。
- 不把新套件直接塞进现有必过门禁；先以「可手动触发 + 夜间」形态落地，稳定后再讨论接入。
- 不追求字节级完全一致；差异分「必须一致 / 已登记允许差异 / 待修」三级。

## 2. 被测对象与基线

| 侧 | 入口 | 说明 |
|---|---|---|
| bash | `install.sh`（菜单 1–9 + 非交互 flag） | 主菜单：1 安装向导、2 配置变更、3 查看信息、4 Xray/TLS、5 更新向导、6 其他选项、7 备份恢复、8 语言、9 Rill AI |
| Go | `idleleo`（`internal/cli`） | `xray install/uninstall/recover/share/relay/user/cert`、`config inspect`、`change`、`service`、`update`、`stats`、`schedule`、`bridge`、`metadata`、`tcp`、`speedtest`、`rill` |
| 外部子脚本 | 上述 9 个 | 由 bash 菜单 `menu_action` 分发，部分联网下载，需要离线镜像 |

版本钉住：bash 侧用 `HEAD` 的 `install.sh` + 本地 `SHELL_RELEASE_BASE_OVERRIDE` 镜像；Go 侧用同一 commit 编译的二进制。两侧 commit 记录进证据。

## 3. 运行环境（可比性前提）

| 维度 | 约定 | 理由 |
|---|---|---|
| 基础镜像 | `ubuntu:24.04`，按 digest 钉住，预装 systemd/openssl/curl/jq/nginx 依赖 | 两侧同一镜像，排除发行版差异 |
| 容器形态 | `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock`，`/sbin/init` 启动 | 复用现有 `tests/go-parity/parity/run_realroot_container.sh` 的成熟形态 |
| 隔离粒度 | 一个场景 = 一组全新容器（server + client），跑完即销毁 | 防止前一个场景的状态污染后一个 |
| 网络 | 每个场景独立 `docker network`；`--network=none` 仅用于不需要业务连通性的场景 | 连通性断言需要稳定网段 |
| 离线源 | 本地静态服务容器模拟 GitHub raw/release：`XRAY_QUALIFICATION_MODE=1` + `SHELL_RELEASE_BASE_OVERRIDE=http://mirror`；Xray/Nginx 二进制与版本 JSON 同源镜像；`IDLELEO_VERSIONS_PUBKEY_FILE` 指向 qualification 公钥 | 已在 `install.sh` 中存在该钩子，避免改被测代码 |
| ACME | 本地 Pebble 作为 ACME 目录，签发 `example.com` | 真实 Let's Encrypt 不可在 CI 复现；legacy `acme.sh` 用 `IDLELEO_ACME_LEGACY=1` 单独跑 |
| 输入确定性 | UUID=`7a4ab30c-b199-4840-a31e-316f4f73a72b`、域名=`example.com`、端口池 `443/8443/10086/65535`、固定 SNI | 两侧输入完全相同，差异才归因于实现 |
| 时间/随机 | 不注入 faketime；采集后统一归一化时间戳、PID、临时目录名 | faketime 会改变行为，反而降低可比性 |
| 交互驱动 | 容器内 `expect`/`pexpect` 驱动 TTY；菜单基于 `menu_read`，每步等待提示符再输入 | 保证「真的走菜单」，而不是直接调内部函数 |

**可比性红线**：同一场景两侧必须使用同一镜像 digest、同一容器参数、同一输入、同一观测时刻（服务 ready 后固定等待窗口），且采集脚本是同一份。

## 4. 场景矩阵

### 4.1 安装模式矩阵（两侧一一对应）

bash 向导维度：`Reality`（标准 / +Nginx / +传输 / 负载均衡）、`ws/gRPC/xHTTP`（含组合）、`中转节点（Nginx Stream TCP）`；TLS：`none / 自签 / ACME`。

| ID | 模式 | 传输 | TLS | bash 入口 | Go 入口 |
|---|---|---|---|---|---|
| M1 | reality | raw | reality | 安装向导 → Reality → 标准 | `xray install --mode reality` |
| M2 | reality | raw | reality | Reality → +Nginx | 同 M1（Nginx 由 `--nginx-bin` 控制） |
| M3 | reality | ws/grpc/xhttp | reality | Reality → +传输 | `--mode reality --transport ...` |
| M4 | tls | ws | 自签 | 向导 → ws/gRPC/xHTTP → ws | `--mode tls --transport ws` |
| M5 | tls | grpc | 自签 | 同上 → gRPC | `--mode tls --transport grpc` |
| M6 | tls | xhttp | 自签 | 同上 → xHTTP | `--mode tls --transport xhttp` |
| M7 | tls | ws+grpc+xhttp | 自签 | 同上 → 组合 | `--transport ws+grpc+xhttp` |
| M8 | tls | ws | ACME | 同上 + 证书签发 | `xray cert issue` + `xray install` |
| M9 | none | ws | 无 | 向导 → ws（无 TLS） | `--mode none --transport ws` |
| M10 | relay | stream | 无 | 向导 → 中转节点 | `xray relay --target ... --listen-port ...` |

每个模式在两侧各跑 2 次：全新安装、重复安装（幂等）。

### 4.2 交互操作矩阵（菜单逐项）

| 菜单 | 操作 | bash 驱动 | Go 对照 | 判定 |
|---|---|---|---|---|
| 1 安装向导 | 各模式安装、重装 | 菜单输入序列 | `xray install` 各 flag | 必须一致（产物/连通性） |
| 2 配置变更 | 查看用户、增/删用户 | 菜单 2→1→1/2/3 | `xray user list/add/remove` | 必须一致（配置语义） |
| 2 配置变更 | 改端口 | 菜单 2→2→2 | `change set-inbound-port` | 必须一致 |
| 2 配置变更 | 改 UUID/映射、改 target、TLS 版本、SNI Guard | 菜单 2→2→1/3/4/5 | 无直接对应（bridge/无） | 登记为「Go 暂无」，只记录 bash 基线 |
| 2 配置变更 | Nginx 负载均衡 / serverNames | 菜单 2→3 | 无 | 登记 |
| 3 查看信息 | 配置信息、访问/错误日志、端口流量 | 菜单 3→1..4 | `show` / `config inspect` / `service logs` / `stats` | 必须一致（字段与数值口径） |
| 4 Xray/TLS | 服务重启/启动/停止/查看 | 菜单 4→1→1..4 | `service restart/start/stop/status` | 必须一致（退出码+unit 状态） |
| 4 Xray/TLS | 证书状态/有效期/自动更新 | 菜单 4→2→1..3 | `xray cert renew`、`schedule install/status` | 必须一致（状态字段） |
| 5 更新向导 | 更新脚本/Xray/Nginx/自动更新 | 菜单 5→1..4 | `update check/apply`、`schedule install` | 允许差异（Nginx 更新 Go 无），逐项登记 |
| 6 其他选项 | TCP 加速（BBR） | 菜单 6→1 → `tcp.sh` | `tcp plan/apply` | 必须一致（sysctl/模块状态） |
| 6 其他选项 | Fail2ban | 菜单 6→2 → `fail2ban_manager.sh` | 无 | 登记 |
| 6 其他选项 | 流量统计 | 菜单 6→3 | `stats` | 必须一致（数值口径） |
| 6 其他选项 | 流量阻断 | 菜单 6→4 → `traffic_blocker.sh` | 无 | 登记 |
| 6 其他选项 | 清除日志 | 菜单 6→5 | 无 | 登记 |
| 6 其他选项 | 服务器网速 | 菜单 6→6 → `superspeed.sh` | `speedtest` | 允许差异（样本/服务器），需固定参数 |
| 6 其他选项 | 刷新 GeoData | 菜单 6→7 → `geo_update.sh` | `xray install`（geo 资源） | 必须一致（文件+mtime 语义） |
| 7 备份恢复 | 备份/恢复/清空证书/卸载 | 菜单 7→1..4 | `metadata export/import`、`xray uninstall` | 必须一致（产物+可恢复性） |
| 9 Rill AI | 安装/状态/诊断 | 菜单 9 | `rill status`、`rill_xray_agent_*.sh` | 允许差异（能力面不同），登记 |

### 4.3 外部子脚本矩阵

| 脚本 | 触发路径 | 依赖 stub | 观测点 |
|---|---|---|---|
| `fail2ban_manager.sh` | 菜单 6→2 或 `--fail2ban` | apt 源、`systemctl`、journal | jail 文件、`fail2ban-client status` |
| `traffic_blocker.sh` | 菜单 6→4 | iptables/nft（容器内可用） | 规则集、重启后是否保留 |
| `file_manager.sh` | 菜单 7/其他入口 | 无 | 备份/恢复产物 |
| `auto_update.sh` | 菜单 5→4、cron | 本地 release 镜像 | cron 行、更新后版本 |
| `ssl_update.sh` | cron、`--ssl` 路径 | Pebble、`systemctl reload nginx` | 证书链、reload 命中 |
| `geo_update.sh` | 菜单 6→7、cron | 本地 geo 镜像 | 文件存在与大小 |
| `acme.sh`（legacy） | `IDLELEO_ACME_LEGACY=1` | Pebble + `--server` 覆盖 | 续签 cron、证书 |
| `tcp.sh` | 菜单 6→1、`idleleo tcp` | BBR 模块、sysctl | `net.ipv4.tcp_congestion_control` |
| `superspeed.sh` | 菜单 6→6 | 固定测速端点 | 输出字段与退出码 |

对每个脚本至少跑：首次执行、重复执行、失败路径（网络不可达 / 无 root / 依赖缺失）。

### 4.4 只读命令对照

`--show/--stats/--access-log/--error-log/--rill-agent-status` 与 Go `status/show/config inspect/stats/service logs/rill status` 做字段级对照：字段集合、空值语义、退出码、JSON 契约（`--json`）。

## 5. 对比口径

统一采集器输出 JSON，逐层判定：

| 层 | 采集内容 | 判定规则 |
|---|---|---|
| L0 退出码 | 每条命令 rc / signal / 超时 | 必须一致（除已登记项） |
| L1 产物清单 | `path, type, mode, owner, size, sha256`，覆盖 `/etc/idleleo`、`/usr/local/etc/xray`、`/usr/local/nginx`、`/etc/systemd/system`、`/root/.acme.sh`、cron | 路径+权限必须一致；内容按 L2 |
| L2 配置语义 | `config.json` 用 `jq -S` 规范化后结构化 diff；nginx conf 去注释/排序后 diff | 必须语义等价，键顺序无关；证书类只比 SAN/有效期窗口/指纹，不比序列号 |
| L3 运行时 | `systemctl is-active`、`ss -lntup`、`nginx -t`、`xray -test`、unit 文件规范 | 必须一致 |
| L4 连通性 | 独立 client 容器按协议真实握手并跑业务请求（HTTP 经 inbound、gRPC/ws/xhttp 各一） | 必须成功且时延量级一致；失败即 BLOCKER |
| L5 日志 | 去 ANSI/时间戳/PID/临时路径后抽取 ERROR/WARN 与关键状态行 | 不允许新增未登记错误；允许措辞差异 |
| L6 幂等 | 同命令二次执行 | 结果与一次一致，不产生重复 cron/重复 inbound |

每条差异归入：`MATCH`、`EXPECTED-DIFF`（需登记理由与责任人）、`DIFF-BLOCKER`、`HARNESS-ERROR`（不计入结论）。

## 6. 无缝升级验证

**两条候选路径，都测，评审时定一条为官方路径**

- R1 就地升级：bash 安装完成 → `idleleo xray install --keep-config --container`（或指定本地二进制）。
- R2 legacy bridge：`bridge audit` → `bridge prepare --candidate ... --recovery ...` → `bridge validate --xray ... --nginx ...` → `bridge activate`。

**每个安装模式（M1–M10）执行**

1. bash 安装 → 客户端连通性基线（保存 client 配置与成功证据）。
2. 状态快照：`/etc/idleleo`、`/usr/local/etc/xray`、`/usr/local/nginx`、`/etc/systemd/system`、cron、`/root/.acme.sh` 的 L1 清单 + tar。
3. 执行升级路径（R1，R2 在 M1/M4 上抽测）。
4. 断言：
   - U1 配置语义等价（L2），未传 `--rewrite-config` 时不得静默改写；
   - U2 证书/私钥字节与 mtime 不变；
   - U3 unit 有效、服务 active、监听端口集合不变；
   - U4 `xray -test`、`nginx -t` 通过；
   - U5 客户端**不改配置**仍能连通（核心判据）；
   - U6 `idleleo status --json` 反映与 bash 相同的 mode/transport/role；
   - U7 cron/schedule 迁移无重复、无丢失；
   - U8 回滚演练：`xray uninstall --keep-config` → 恢复快照 → 服务与连通性恢复。
5. 失败注入（至少 4 种）：
   - 配置 JSON 损坏；证书缺失；端口被占用；目标目录只读。
   - 要求：升级命令返回非 0 且错误指向具体项；bash 状态在升级前后 L1 清单完全一致（未半途破坏）；随后按 U8 可恢复。

## 7. 风险与回滚

| 风险 | 影响 | 缓解 |
|---|---|---|
| systemd 在容器内不稳定 | 大量假失败 | 固定已用的 privileged 形态；每个场景启动后等 `is-system-running`；失败重跑 1 次并标记 |
| 子脚本联网下载 | 场景不可复现 | 全量本地镜像 + `SHELL_RELEASE_BASE_OVERRIDE`；断网场景单独跑 |
| 签名/版本校验挡住离线源 | 安装失败 | 使用 qualification 公钥与本地 version JSON，保持签名链路真实 |
| 菜单提示变化导致 keystroke 错位 | 驱动假成功 | 每步等待预期提示文本，超时即 HARNESS-ERROR；禁止「盲发回车」 |
| 归一化规则过宽掩盖真差异 | 假绿 | 归一化规则版本化并评审；BLOCKER 不允许豁免 |
| 场景多导致耗时长 | 反馈慢 | 按模式分片并行；冒烟集（M1/M4/M9 + 升级 R1）优先 |
| privileged 容器在 macOS Docker Desktop 行为差异 | 本地与 CI 不一致 | 以 CI 的 ubuntu runner 为判定基准，本地仅做开发 |
| 失败路径把宿主/CI 搞脏 | 环境污染 | 全部 disposable 容器；快照只写容器内与工作区 evidence 目录 |
| Go 版缺失能力被误判为 bug | 结论失真 | 4.2 中先登记「Go 暂无」，只记录 bash 基线并单列 |
| 升级失败留下半成品状态 | 用户数据风险 | U8/U9 强制验证「失败后 bash 状态原样」+ 快照恢复 |

**回滚原则**：所有验证都在一次性容器内完成；本计划不触碰宿主与现有门禁。若后续接入 CI 后发现不稳定，移除对应 workflow 步骤即可，不影响 28 项判据。

## 8. 执行顺序与产出

| 阶段 | 内容 | 产出 |
|---|---|---|
| P0 基线冻结 | 确认菜单编号/flag（以 `--help` 实测）、镜像 digest、离线镜像与 Pebble、驱动骨架；确认 Go 能力缺口清单 | `matrix.md`（冻结版）+ 能力缺口表 |
| P1 安装冒烟 | M1/M4/M9 两侧各跑通，L0–L4 采集打通 | 冒烟证据 + 采集器自检报告 |
| P2 安装全量 | M1–M10 + 幂等 | 模式对比报告 |
| P3 交互全量 | 4.2 菜单逐项 + 4.4 只读命令 | 交互对比报告 |
| P4 子脚本 | 4.3 九个脚本，正常/重复/失败三态 | 子脚本对比报告 |
| P5 升级正向 | M1–M10 升级 R1，M1/M4 加测 R2 | 升级兼容报告（U1–U7） |
| P6 升级异常 | 4 类失败注入 + U8 回滚 | 回滚演练报告 |
| P7 汇总 | 差异登记表、未覆盖项、建议修复优先级 | 总报告（评审输入） |

每阶段结束先出证据再做下一阶段；P2 未全绿不进入 P5。

## 9. 目录与证据格式（建议）

```
tests/e2e-diff/
  image/            # 统一基础镜像 + 依赖快照
  mirror/           # 本地 raw/release 镜像、geo、测速端点
  cases/            # 场景定义（JSON：模式/输入/入口/断言）
  drivers/          # bash 菜单 pexpect 驱动、Go CLI 驱动、子脚本驱动
  collect/          # 清单/配置/日志/连通性采集与归一化
  evidence/<run-id>/scenario.json   # 输入、两侧产物、逐层 diff、判决
```

证据文件必须可离线复核：包含输入、两侧 commit、镜像 digest、原始采集与归一化后视图。

## 10. 判定门槛（本计划验收标准）

1. 五个安装大类在两侧都能真实装出可连通环境（M1–M10 全过）。
2. 4.2 表中标「必须一致」的项无未登记 `DIFF-BLOCKER`。
3. 九个外部子脚本的正常/重复/失败三态都有记录。
4. 每个模式升级后 U1–U5 全过；U6–U8 通过或有书面登记的例外。
5. 4 类失败注入均满足「命令报错明确 + bash 状态不被打断 + 快照可恢复」。
6. 报告明确列出「Go 暂无对应」的能力清单与建议。

## 11. 需要评审拍板的点

1. 升级官方路径选 R1（`xray install --keep-config`）还是 R2（bridge 三阶段）？建议：R1 为主、R2 作为 legacy 兜底抽测。
2. `EXPECTED-DIFF` 的批准人是谁？建议：每条需写明理由 + 责任人，禁止批量豁免。
3. 连通性断言是否纳入「时延量级」？建议：只判成功/失败与协议正确性，时延仅记录不判定。
4. 是否允许在 P1 之后把冒烟集接入 `go-parity-stage.yml`？建议：先夜间手动触发，连续稳定后再单独提 PR 接入，不动现有 28 项判据。
