# P2 任务清单

前置：`docs/plans/p2/spec.md` 的差异清单 G1–G11 与 D1–D9 按新口径执行（Go 对齐 bash，
真做不到才保留差异并附证据）。不动 `install.sh`；不静默删除安全闸。
（2026-11-16 校正：证书对齐轮改动过 `install.sh`/`scripts/ssl_update.sh` 的证书路径，
属于 S4/S5 证书专项，不算破坏此约束；P2 生成/安装/编辑链路仍未动 install.sh。）

## 2026-11-16 计划审计

对照代码逐项复核本计划与 `docs/go/FUNCTION_PARITY.md`、S6/S7 计划后的真实状态：

**与代码一致（维持勾选）**：T0–T7、T9–T14 全部完成，证据链完整（M1–M7/M9/M10 双侧
两轮、E1–E8、OPS-09/19/21/22/31/32 均有实证）。

**计划缺陷（本次修正）**：
1. 计划只覆盖「diff 对齐」，没有给**发布门禁收口**排期：28 项功能契约至今全部
   `PENDING_GO_IMPLEMENTATION`（执行器 6/28），这才是合并前的真正临界路径。新增 P2-G。
2. T8 收尾提交跨期未清：2026-11-16 证书对齐轮（acme/lego/cli/schedule/install.sh/
   ssl_update.sh + 测试文档）已按三组提交（`7022c09c`/`69dba27f`/`2ea4c8ae`）。
3. M8 在 T7/T14 证据里两次 HARNESS-BLOCKED，但从未立任务。并入 P2-G。
4. E2E 局部跑误导性矩阵（待办区）危害是伪证据，优先级应高于一般待办。并入 P2-G。
5. C6 「续期缺口未解决前不实现」的前置条件实际已消解：webroot HTTP-01 续期链路
   （含用户自备证书不接管语义）已落地，C6 现在缺的是产品拍板而非技术缺口。
   加决策检查点，不再无限期挂着。
6. 周边计划文档过时：`docs/go/S6_S7_PLAN_2026-11-11.md` 中「schedule cert-renew 只做
   监控」「CLI 无 speedtest 命令」等描述与代码不符，已在原文加校正注记；
   `tests/go-parity/parity/features/README.md` 「故意没有 F01–F28」与已有 6 个执行器矛盾，已改。

**不受本计划控制但要记录的外部项**：真实公网 CA 终验（环境缺公网入口，授权降级为
staging 预检）；S0 公开仓库历史清理仍等 GitHub Support；ED-005 到期复核
（`expires=2027-03-31`）挂在 release 门槛。

## T0 差异清单

- [x] 产出 `docs/plans/p2/behavior-diff.md`：G1–G11 逐条标注「可改 / 不可改 / 需拍板」、
  改动层（CLI 校验 / 生成逻辑 / 安装落地）、证据与验证方式。
- 验证：清单覆盖 M3、M10、M4、D3、M2、M9/M5–M7、安全闸七项，以及 G8–G11 三项补强。

## T1 矩阵与 argv

- [x] `matrix.json`：M3 改为 Go 实装 argv；M10 改为 `xray install --role relay`；
  删除 `goStatus:"capability-gap"`；D1–D5 按新口径落库；M5–M7 补 `--binary`；M9 保留监听覆盖。
- [x] `run_p2_matrix.sh` 的 argv 探针补 M4、M2 别名、M3/M10，并修正 rc 采集。
- 验证：`jq` 校验矩阵；探针输出里 M2-alias / M3 rc=0。

## T2 G1 Reality + 单传输（生成逻辑）

- [x] `internal/xraycfg/xraycfg.go` 放开 `ModeReality` 的 ws/grpc/xhttp，生成
  raw Reality 主 inbound + 附加传输 inbound（端口 +1），对齐 bash `reality_add_more`。
- [x] 单测：`TestRealitySingleTransportKeepsRealityPrimary`。
- 验证：`go test ./internal/xraycfg`；P2 M3 两侧 L2/L4 MATCH。

## T3 G2 relay 安装落地（安装落地）

- [x] `internal/nginx`：`EnsureRelayInclude` 在主配置顶层写 marker + include，
  已有用户 `stream {}` 时拒绝。
- [x] `internal/deploy/relay.go`：`InstallRelay` 装 managed Nginx(stream)、写
  `relay-stream.conf`、include、`nginx -t`、启服务、写 metadata；幂等。
- [x] `internal/cli/xray.go` + `flags.go`：`xray install --role relay --target --listen-port --listen`。
- [x] 单测：relay 落盘 / 二次运行不重复 include。
- 验证：P2 M10 两侧 L1–L4 MATCH，L4 经中转容器回源成功。

## T4 G4/G5 重复安装与 CLI 别名

- [x] `internal/deploy/deploy.go`：已有 runtime config 且未显式指定时默认保留并告警
  （对齐 bash 保留配置）；`--keep-config` / `--rewrite-config` 保留为显式开关；
  保留配置时仍生成 Nginx fragments。
- [x] `internal/cli/xray.go`：`--mode reality --nginx-bin` 兼容别名到 `reality-nginx`。
- [x] 更新/新增 deploy 单测：默认接管、显式重写、别名。
- 验证：P2 所有场景第 2 轮 rc=0 且 L6 无新增/漂移；M2 两种 CLI 形态生成等价配置。

## T5 G3 M4 nginx 目录取证

- [x] 用 M4 的 P2 manifest 对比两侧 nginx 二进制目录、fragment 目录、include 路径。
- [x] 仅当存在真实磁盘差异时改 Go；否则在矩阵注明“无差异”。
- 验证：M4 的 L1 路径/权限对比结论写入报告。

## T6 驱动、采集与报告

- [x] `drivers/bash_menu.exp` 覆盖 M2/M3/M5/M6/M7/M9/M10 的实际提示词。
- [x] `drivers/go_install.sh` 第 2 轮传 `--keep-config`；relay 场景不种 xray。
- [x] `collect/logs.sh`、`collect/idempotency.sh`、`collect/l4.sh`、`collect/client_config.py`
  支持多传输与 relay。
- [x] `compare/report.py`：MATCH / ED / BLOCKER / HARNESS-ERROR 分类不变，去掉 capability-gap 分支。
- 验证：`bash collect/self_check.sh`、`python3 compare/report.py --self-test` rc=0。

## T7 全量复跑与矩阵

- [x] 小样：M1/M3/M4/M9/M10 两侧 × 2 轮。
- [x] 全量：M1–M10 × 两侧 × 2 轮；HARNESS-ERROR 仅按规则重跑（M6/M10 bash 首轮超时重跑一次）。
- [x] 产出 `evidence/final-full2-8863b10/p2/install-matrix.md`，附基线对比与保留差异。
- [x] 修复两处测试/实现缺陷：bash 第 2 轮不再用空占位覆盖第 1 轮配置（否则 L6 从未真正验证）；
  重复安装 `--keep-config` 依据 `00-xray.conf` 恢复 Nginx 前置模式（否则前置场景第 2 轮丢 Nginx）。
- 验证：M1–M7/M9/M10 两侧 rc/L4 两轮/rc2/L6 全部通过；M8 仍 HARNESS-BLOCKED；
  剩余 BLOCKER 仅由 pending EXPECTED-DIFF 引起。

## T8 提交与汇报

- [x] 按主题拆 commit：差异清单+spec、Go 生成逻辑、relay 安装、重复安装/别名、矩阵+驱动/runner。
  对应提交：`4983551e`；`8ecc69e3`+`16f38bbc`；`467c1934`+`e209f49d`；
  `196d7378`+`916ac951`+`59b8ac33`；`f8fad8dc`+`2a7c6c85`+`57781355`。
- [x] 证书对齐轮（2026-11-16）单独成组：acme 核心与权限契约、CLI/调度与
  Bash 对齐（install.sh/ssl_update.sh）、测试与文档（DECISIONS D-024、FUNCTION_PARITY
  F12 证据回填）三个 commit：`7022c09c` / `69dba27f` / `2ea4c8ae`。
- [x] 汇报：差异清单分类、每项改法与验证、矩阵前后对比、仍保留的能力缺口。
  产出 `docs/plans/p2/closeout-report.md`。

## T9 G8 relay 文件集合（安装落地）

- [x] `nginx.InstallSpec.RelayOnly`：relay 不创建 `00-xray.conf`/`03-isolate.conf` 占位。
- [x] `RewriteMainConfig`：Stream 分支仅节点模式 include 两个占位文件；节点模式不变。
- [x] 单测：relay 不生成/不 include 占位文件、不含 http glob。
- 验证：M10 两侧 `/etc/idleleo/conf/nginx` 文件集合一致、`nginx -t` ok、L4 回源与 L6 幂等不回归。

## T10 G9/G10 端口策略（生成逻辑）

- [x] 去掉 `base+1`：ws/gRPC 10000–10999、xHTTP 11000–11999 升序候选。
- [x] 生成前 bind 探测避让；排除 9403/9404/9443/9444 与已用端口；65535 不回绕 1。
- [x] `--ws-port/--grpc-port/--xhttp-port` 显式覆盖，越界/重复/保留/占用直接报错。
- [x] 探测跳过时输出 warning，安装前即报错而不是等服务启动失败。
- [x] G10：TLS 回环 inbound 使用传输端口池，Nginx 独占公网端口。
- 验证：M3/M7 两侧 2 轮 rc=0、L4 ok、幂等 ok；第三方占用 10000 时自动选 10001 并留 warning。

## T11 G11 `xray config edit`（CLI + 生成 + 安装落地）

- [x] `internal/xraycfg/edit.go`：spec 还原、patch、严格 diff 白名单、隐含 keep。
- [x] `internal/deploy/edit.go`：`xray -test` 前置、`nginx -t`、备份
  `/etc/idleleo/backup/edit-<ts>/`、快照与重启失败回滚、`--no-restart`、relay 编辑。
- [x] `internal/cli/xrayedit.go` + flags：6 项第一梯队、`--dry-run`/`--yes`/`--json`、
  断线项二次确认、与 `--rewrite-config` 冲突 rc=2。
- [x] 单测：patch 只改目标字段、自检失败零落盘、重启失败回滚、dry-run。
- [x] 矩阵 E1（改前改后）与 E2（重启失败回滚）+ 驱动/runner/报告。
- 验证：E1/E2 PASS；reality、reality-nginx、TLS、relay 手工验证通过。

## T12 规格与文档收口

- [x] 讨论稿升级为正式规格 v1.0（`interactive-config-editing-discussion.md`）。
- [x] `spec.md` 补 G8–G11、D6–D9 与实现文件。
- [x] `behavior-diff.md` 补 G8–G11 与证据。
- 验证：三份文档口径一致，矩阵场景与规格 §11 对应。

## T13 ED 按类审批（护栏 + 批准）

- [x] 113 条 M1–M10 布局差异归并为 13 类（14 个唯一路径，仅合并 conf 两路径）。
- [x] 两条护栏：`paths` 精确匹配（不再按目录前缀吸收）+ `scenarios` 显式列举；
  未列举路径/场景一律 BLOCKER，原 113 条 id 保留在各类 `supersedes`。
- [x] `owner=hello-yunshu`、`approved_by=release-gate`、`expires=2027-03-31`；
  ED 内注明「流程批准，不是双人批准」并附 review 链接。
- [x] ED-001/002/003/004 判 `rejected`（应改 Go）并挂第二梯队；ED-005 登记。
- [x] `report.py` 判定修正：只要存在未抑制路径即 BLOCKER，不再被部分抑制掩盖。
- [x] release 门槛补「ED 到期复核」。
- 验证：`report.py --self-test` 覆盖新增文件/新增场景/拒绝态三例；用
  `final-full2-8863b10` 证据重生成矩阵，M1–M10 判定从 BLOCKER 变为类 ED，
  未抑制差异为 0。

## T14 第二梯队（顺序已拍板）

- [x] S1 target/serverNames 主动回源探测（TCP connect + 证书链/hostname 校验；失败阻断保存）。
  - `internal/deploy/probe.go` / `probe_test.go`：无 SNI 只做 TCP；有 SNI 时按系统根证书
    校验证书链与 hostname（不加 OCSP、不锁 TLS 版本）；失败 rc=2、零落盘、无备份。
  - E3（拒连目标）与 E4（受信本地 CA 回源）均 PASS；E4 证据显示本地 origin 必须协商
    ALPN，否则 Reality 判 invalid 回退（探测本身不背这个锅）。
  - 证据：`tests/e2e-diff/evidence/s1-edit-probe-ca`（全量矩阵，E1–E4 PASS）。
- [x] C4 metadata 补版本与端口/target/serverNames 快照。
  - `internal/store/metadata.go`：新增 `install{engineVersion,port,target,serverNames}`，
    port 必须在 1–65535，否则按损坏处理（rc=4）；旧 metadata 无该字段照常加载。
  - `internal/deploy/deploy.go`：安装时写入快照；端口取「显式 --public-port → 托管 Nginx
    前端 listen → 显式 --port → 运行配置首个 inbound」，与 bash install_config 的 port 同义。
  - `internal/deploy/edit.go`：编辑后用生效配置刷新 target/serverNames，端口/版本不动。
  - 单测：store 快照加载与 port=0 拒绝、安装写入快照、编辑刷新快照；`go test` 三包全绿。
  - 证据：`tests/e2e-diff/evidence/c4-metadata-snapshot-full`（全量矩阵，M1–M7/M9/M10 双侧
    全绿、M8 仍 HARNESS-BLOCKED，E1–E4 全部 PASS）。
- [x] C3 日志轮转/清理（ED-004）。
  - 新增 `idleleo xray logs clean`（`--yes` 必填，截断 Xray/Nginx 日志目录下所有普通
    `*.log`，保留 inode/属主/权限，符号链接与非日志文件不碰）与
    `idleleo xray logs rotate enable|disable`（写入与 bash 同构的
    `etc/logrotate.d/xray_log_cleanup` + `systemd logrotate.service.d` drop-in，
    `logrotate --debug` 通过后才替换，启用 `logrotate.timer`；disable 只删自己的两个文件）。
  - 已知偏差（已登记为主动不对齐 G12，不是 ED）：bash 会自动 `apt`/`dnf` 装 logrotate，
    Go 不碰系统包管理器；缺二进制时在任何写入前失败，并打印 Deb/RHEL/Alpine 三条可直接
    复制的安装命令。后果：全新系统上 `xray logs rotate enable` 需先手动装一次。详见
    `behavior-diff.md`「主动不对齐：G12 不调用系统包管理器」。
  - 验证：单测覆盖截断范围/递归/符号链接/权限、缺二进制不落盘、`--debug` 拒绝不落盘、
    disable 不碰其他 logrotate 文件；容器内实测 clean（freedBytes=20、4 个文件归零、
    keep.txt 保留）、rotate enable（真实 logrotate `--debug` rc=0，配置与 drop-in 内容符）、
    rotate disable（两个文件删除，无残留）。
  - 证据：矩阵 OPS-22 由 `go-missing` 改为 `must-match`，ED-004 从 expected_diffs 移除。
- [x] C1 fail2ban 接入（ED-002）。
  - 新增 `internal/deploy/fail2ban.go` 与 `idleleo fail2ban status|install|uninstall|banned|unban|trust add|del|jail enable|disable`。
  - jail 1:1 对齐 bash：`sshd`（maxretry 5 / bantime 604800 / backend=systemd）、`nginx-badbots`（5/604800）、
    `nginx-botsearch`（604800）、`nginx-no-host`（5 / findtime 120 / 604800）、`nginx-tls-error`
    （8 / findtime 300 / 43200）；全局增量封禁 `1 2 4 8 16 32 64`、上限 180d。阈值与 `ignoreip`
    均原样继承，未放宽、未自动加白。
  - 加固（bash 没有）：日志文件不存在的 jail 不写，只留 warning（否则 fail2ban 起不来）；`sshd` 仅在
    ssh/sshd unit 为 active 时写；候选配置先在 `/etc/fail2ban` 副本上跑 `fail2ban-client -t`，
    不通过则零落盘；已存在且内容不同的 jail 文件不覆盖，只 warning。
  - 卸载：安装时记录 `/etc/idleleo/v1/fail2ban.json` manifest；卸载只删 manifest 内文件，
    manifest 外的 `*.local` 保留并逐个提示「不是 Idleleo 创建的」；manifest 缺失（老安装）列出候选、
    要求 `--force`，且只删已知文件名；不卸载软件包，只重启服务卸载 jail。
  - 安装成功后打印 `SSH_CLIENT`/`SSH_CONNECTION` 来源 IP 与一行
    `idleleo fail2ban trust add --jail sshd --ip <ip>`，**不自动执行**（避免给动态 IP 放行陌生人）。
  - 不调包管理器（G13）：缺 `fail2ban-client` 时打印 deb/rhel/alpine 安装命令并零落盘。
  - 验证：`go test ./internal/deploy -run Fail2ban` 全绿（8 个用例）；容器内真实 fail2ban 1.1.0 实测
    install（4 jail + 跳过 sshd）、status、banned、unban（含二次解封 already_absent）、trust add、
    jail disable、uninstall（保留 `user-custom.local`）。
  - 矩阵：OPS-19 由 `go-missing` 改为 `must-match`，ED-002 从 `expected_diffs.json` 移除。
- [x] S2 负载均衡后端增删 + reality-balance 支持（ED-001）。
  - 新增 `internal/deploy/balance.go` 与 `idleleo xray balance add|list|remove`
    （`--upstream ws|grpc|xhttp|reality`、`--host/--port/--weight`、`--probe`、`--container`、`--json`）。
  - 生成物与 bash 对齐：写 `<host>.<ws|reality>Servers`，行格式
    `server <host>:<port> weight=<w> max_fails=2 fail_timeout=10;`；`xray install --mode
    reality-balance --role primary|secondary` 复用 managed Nginx 并生成 `*.realityServers` include。
  - 主动收紧（G14，不进 ED）：reality-nginx 与二级服务器拒绝增删并指路
    `--mode reality-balance --role primary`；拒绝删空最后后端、本机回环、端口不匹配、
    重复/非法 host、保留端口 `443/9403/9404/9443/9444`；`nginx -t` 失败回滚；
    默认不探测并提示依赖 `max_fails/fail_timeout` 被动摘除，`--probe` 才做 TCP+TLS1.3+SNI。
  - 门槛：`go test ./internal/deploy -run Balance` 全绿；两端必须实跑，缺任一侧记
    HARNESS-ERROR，观测不一致记 BLOCKER，绝不写 PASS。
  - 证据：OPS-09（bash M4 安装 + 菜单 `2>3>1` file_manager 增/列/删 ‖ Go TLS 安装 +
    `balance add|list|remove --upstream ws`）与 OPS-31（bash `1>1>5>1` reality-balance
    主服务器 + 同样菜单路径 ‖ Go `--mode reality-balance --role primary`）双端 PASS：
    `evidence/s2-ops-0434/p2/OPS-09/ops.json`、`.../OPS-31/ops.json`。
  - 矩阵：OPS-09 由 `go-missing` 改为 `must-match`，新增 OPS-31 `must-match`；
    ED-001 从 `expected_diffs.json` 移除。
  - 故障摘除 OPS-32：`max_fails=2 fail_timeout=10` 被动摘除双端 PASS
    （`evidence/ops32-measure-1115/p2/OPS-32/ops.json`，ws 与 reality 两条上游；
    旧口径 `evidence/ops32-failover-0523/p2/OPS-32/ops.json` 已按新 schema 回填，
    `recoveryWindow.stopReason=first-A (pre-revision evidence)`，只保留 first-A）。
    - 测量口径：恢复探测跑满 `60s/120 次`，不再因首个 A 提前停止；判定用
      `stableRecovery`（A 一直选到窗口末尾、相邻 A 间隔 ≤ `fail_timeout=10s`
      且链上至少 3 次 A），`firstRecoveryLatencySeconds` 仅作参照。
    - ws：真实 TLS 流量打到 `backend-a:9001`/`backend-b:9002`，`kill -9` 一个后
      84 次请求零 5xx、全由存活后端返回；`perWorkerFails` 显示 10 个 worker 中
      bash 9 个、Go 10 个达到 `max_fails=2`，静默区间 bash 8.6–12.6s、Go 6.3–12.3s；
      重启后 stable 恢复 bash 13.6s、Go 24.8s（与 first-A 相同）。
    - reality：真实 TLS 1.3 ClientHello 经 stream 入口，84 次连接全到存活端、零连接失败。
      `perWorkerFails` 显示 bash 9 个 worker 只有 4 个达到 `max_fails=2`（其余仅 1 次），
      Go 10 个里有 7 个，因此 first-A 只是取样点：bash first-A 3.96s → stable 17.67s，
      Go first-A/stable 同为 19.36s。标记后端只做 TCP 应答，故只证明 stream 选路与摘除，
      **不外推 Reality 握手**。
    - harness 在两侧删除安装自带的回环后端：`xray balance remove` 按设计拒绝删回环，
      没有对称的菜单入口；删除动作与原因记录在 `ops.json` 的 `loopbackRemovedBy`。
- [x] S3 证书路径/域名（G16/G17）。
  - 入口保持 `xray config edit`：新增 `--domain/--cert/--cert-key`，仅 TLS 生效；
    Reality 指路 `--server-names`，reality/reality-balance 一律拒绝。
  - 可改与不可改：域名、证书路径、私钥路径可改；CA 类型、签发方式、SAN 列表不可改
    （SAN 由证书本身决定，只校验并写入报告），改域名不自动签证书。
  - 写入前交叉校验：证书/私钥必须成对、证书 SAN 必须覆盖目标域名（即「改域名但证书还是
    旧域名」直接拒绝）、不能过期/未生效；30 天内到期与私钥全局可读只 warning。
  - 默认对新域名做本地 TLS 握手（`127.0.0.1:<public-port>`，SNI=新域名，校验 served leaf
    与配置证书一致、SAN、有效期、TLS 1.3；系统根不信任只 warning）；`--no-probe` 关闭；
    服务未监听记 warning 并标 `skipped`，不算通过。`--no-restart` 时同样只标 `skipped`。
  - 仅前端变更时 runtime JSON 不变：不再误判 `NoChanges`，强制重写 Nginx 并 reload；
    **不重启 Xray**，避免无谓断线。
  - 续期链路：`jobs.json` 的 `certDomain/certFile/certKeyFile` 随编辑更新（路径转成相对根）；
    `cert-renew` 优先观测 `cfg.certFile`；不自动重签、不重装 hook。
  - 备份追加 `tls-cert.pem`/`tls-key.pem`（0600，不回显）/`schedule-jobs.json`，失败连同
    `jobs.json` 一起回滚；Bash 根与 `provenance!=native` 的导入根在写入前拒绝（G17）。
  - 单测：`go test ./internal/xraycfg ./internal/deploy ./internal/schedule`（域名/证书
    rewrite、SAN/过期/配对拒绝、近到期与私钥权限 warning、握手 ok/skipped/失败三态、
    备份内容、Bash 根拒绝、jobs.json 更新与观测优先级）。
  - E2E（真 Nginx + 真证书替换，证据先行）：
    `evidence/e5e6-11150953-3f25259/p2/` 下 E5/E6 双 PASS，`install-matrix.md` 中
    E5/E6 行均为 **PASS**（该次只跑 E5/E6，M* 与 E1–E4 行因缺证据记 HARNESS/BLOCKER，
    不代表回归）。
    - E5 成功路径（`.../E5/go/edit/checks.json`，11 项全 true）：M4 TLS/ws 安装 +
      `schedule install` → 同域名新自签对 → `edit --cert/--cert-key`；
      `tlsProbe=ok`、`tlsVersion=TLS 1.3`、独立 openssl 指纹与配置证书一致、
      fragment 指向新对、旧对进入 `edit-<ts>/tls-cert.pem|tls-key.pem`、
      jobs.json 三字段同步为相对路径、runtime sha 逐字节不变、Xray MainPID/
      ActiveEnterTimestamp 不变、改后 L4 PASS。
    - E6 回滚路径（`.../E6/go/edit/checks.json`，10 项全 true）：
      (a) `--domain other.test` 被写前校验拒绝（`does not cover`），全部 sha 与备份数不变；
      (b) 合法新对 + `ExecReload` 置空后仅 `/bin/true`（reload 静默不生效）→ 探针报
      `front at 127.0.0.1:443 serves a certificate that differs...` → 回滚；
      runtime、三个 nginx fragment、jobs.json、served 证书全部还原，旧对在备份中，
      xray/nginx 仍 active，失败点与 stderr 原样入库，回滚后 L4 PASS。
    - 探针新增 reload 竞态重试（5s 窗口，仅重试「证书不符」）：Nginx reload 异步，
      首次实现曾在快速连续编辑时误判并回滚，E5 证据暴露后已修复并有单测
      `TestProbeLocalTLSRetriesTheReloadRace`。
    - 备份改为保存**改前**证书对（manifest 另记 `tlsNewCertFile/tlsNewKeyFile`）：
      首个 E5 设计核对时发现原实现备份的是新对，不满足「旧证书可回滚」。
  - 已知差异：不自动重签（G16，与 G15 分开登记）。
- [x] S4 Reality 握手参数。
  - 实现：`xray config edit` 新增 `--short-id/--short-id-auto/--short-id-remove/
    --short-id-list`、`--rotate-reality-private-key`、`--fp/--spx`；不新开子命令。
    `privateKey` 轮换要求键入 `rotate-reality-key`（非 TTY 用
    `--confirm-reality-rotation`），`--yes` 不够；轮换前打印旧链接并写
    `old-share-uri.txt` 到备份目录；shortId 接受 1–16 偶数 hex（含空串），
    `--short-id ''` 才是显式清空。
  - `fp`/`spx` 存 metadata 的 `shareLinkOnly`，字段与输出都标明
    `share link only; server config unchanged`；纯链接偏好编辑不写 runtime、
    不重启、不 reload，配置 SHA 不变。
  - `reality-balance` 可编辑：只改 Xray inbound 的 `realitySettings`，
    `frontDir=""` 且改前改后 `hashTree(nginxDir)` 必须相同；
    `TestEditRealityBalanceLeavesUpstreamTreeUntouched` 用真实 balance 配置与
    upstream 片段断言树哈希不变，报告 `upstreamUnchanged=true`。
  - 探针：真实 xray 客户端 + 隧道内 TLS 握手 + 认证后的 HTTP 请求。只做
    TLS 握手无法区分「凭据通过」与「Reality 回退到伪装目标」，两者都能握手成功。
  - 单测：`go test ./internal/xraycfg ./internal/deploy ./internal/cli`
    （追加/清空/自动/删除、fp/spx 不改 runtime、轮换保留 sid 与 pbk、
    空 publicPort 时链接仍带 443）。
  - E2E（`evidence/s4-reality-1115c/p2/`，E7/E8 双 PASS，L4 改前/改后均 ok）：
    - E7（13 项全 true）：M1 安装 → 旧链接探通 → `--short-id-auto` 追加
      → 旧/新链接都探通（旧 sid 未断）→ `--short-id-remove` 旧 sid
      → 旧链接失败、新链接成功；两次编辑都记录 Xray 重启。
    - E8（14 项全 true）：轮换后新链接探通、旧链接失败、备份含旧链接；
      注入「重启加载旧配置副本」的 systemd drop-in 后再轮换 → 服务 active
      但新凭据未生效 → 真实握手失败 → `failurePoint=reality-handshake`
      → 自动回滚 → `reality-probe-rollback=ok`，旧链接再探通是断言。
  - 推荐流程（shortId 零断线）：**追加新 id → 客户端切换到新链接 → 删除旧 id**。
    追加和删除都会重启 Xray（秒级重连），但只要旧 id 还在，旧链接就必须一直可用；
    不要先删后加。
  - 已知差异：G18（bash 强制 16 hex，Go 自动生成 8 hex）。
- [x] C2 流量阻断（ED-003）：按 `docs/plans/p2/spec-c2-routing-block.md` 实现（D1–D7）。
  `BlockState` 贯穿 `EditRuntime`，门槛断言已在实装环境跑通（`tests/e2e-diff/evidence/20261115-1401-863cead`，
  OPS-21 Go 侧 25/25）：装阻断 → `config edit --uuid` → `owned_rules` 6 条逐条 deep-equal 仍在、
  用户手写规则仍在、控制站仍回 200+marker；`block off` 后 routing 与 apply 前逐字节一致。
  D5 自定义域名/IP 列表、D6 geo sha256 均已落地并有单测。**遗留：bash 侧对照在本机跑不了
  （容器无 egress，bash 安装器取不到公网 IP 与 geo 文件），OPS-21 总 verdict 仍记 HARNESS-ERROR，
  bash 侧必须换一台有出网能力的主机补跑。**
  期间修掉两个真缺陷：`setApplied` 从未写 `applied` 标记（导致 edit 读不到 BlockState 并拒绝重写
  sniffing）、`waitActive` 把 systemd 的瞬时 active 当成功（配置不可读时 apply 仍报 rc=0）。
- [x] C5 多用户 UUID 单点修改：按 `docs/plans/p2/spec-c5-multi-user-uuid.md` 实现。
  `idleleo xray user uuid --email <e> --new-uuid <v>`，email 为准、UUID 为别名、拒绝索引；
  命中多个 inbound 默认全改，一次 clone、一次断言、一次事务，失败不落半改状态。
  `config edit --uuid` 在多用户配置下改为报错并给出可直接复制的目标命令。
  证据：`tests/e2e-diff/evidence/c5-20261115-142437`（`tests/e2e-diff/run_c5_uuid.sh`，26/26）：
  改 B 后 A/C 旧链接仍 200+marker，B 旧链接快速 blocked、新链接 200，A/C 的 client 对象与
  routing 逐字节不变；`--fault service-fail` 后 rc=9、配置哈希不变、A/B/C 三个 UUID 全部仍是旧值；
  单用户回改后 B 旧链接恢复。多 inbound 的原子性与 dry-run 预览由单测
  `TestSetUserUUIDUpdatesEveryInboundAtomically` 等覆盖（E2E 安装只含一个 inbound）。
  输出明确写“会重启、所有会话秒级中断”，dry-run 同样列出 inbound/老 UUID。
- [x] C6 direct TLS 支持（规格已出：`docs/plans/p2/spec-c6-direct-tls.md`）。
  2026-11-16 校正：原前置「续期缺口未解决前不实现」已消解——webroot HTTP-01 续期链路
  落地（schedule 续期、`.user-managed` 不接管语义、`--takeover` 显式接管），一期
  「不接管续期」方案已无技术阻塞。**剩余为产品拍板**：做则按 spec 分阶段实施；
  不做则显式关闭本项并从验收清单移除。检查点：P2-G 完成前给出结论。
  2026-11-17 落地：按 spec 实施「识别 + 编辑 + 接管证书对」——
  `internal/xraycfg/directtls.go`（窄补丁、成对证书、SAN 覆盖、只改允许叶子）、
  `ModeTLSDirect` 编辑期分流、`internal/deploy/edit.go` 不排续期 + 写后真实握手探测 + 失败回滚、
  metadata 保留安装期 TLS 标签。`go test ./internal/xraycfg ./internal/deploy` 通过；
  `tests/go-parity/parity/features/C6_test.py` 29/29 双跑（`tests/go-parity/evidence/c6-2026-11-17/run1|run2`），
  级别 CONTAINER_VERIFIED。缺口：`--inbound` 单选、Bash 侧无此模式。
- 规则：每项单独提交；发现「照 bash 做反而降低安全性」先停并上报。

## 待办（未排期，不要在当前批次顺手改）

- [x] **ED-003 的 `paths` 已改回事实（2026-11-15）。** 原值 `nftables/iptables ruleset` 是错的：
  bash 的 `scripts/traffic_blocker.sh` 实际生成的是 **Xray 路由规则**（`routing.rules` +
  `blocked` outbound，依赖 `geosite:category-ads-all`、`geoip:private`、国家码、bittorrent
  与 `geoip.dat`/`geosite.dat`），全文没有任何 `nft`/`iptables` 调用。已改为
  `config.json#/routing/rules`、`#/routing/domainStrategy`、`#/inbounds/*/sniffing` 与
  `traffic_blocker.json` 四个语义面，`layer` 由 L3 改为 L2，并把 OPS-21 的 layers 补上 L2。
  核对结果：`docs/plans/p2/spec.md` 没有 C2 段落（原文只在 tasks 里提），因此无可改；
  C2 方案落在新文档 `spec-c2-routing-block.md`。

- [x] **E2E 局部跑（`E2E_ONLY`）会生成一张「局部跑却覆盖全场景」的误导性 `install-matrix.md`。**
  - 现象：`E2E_ONLY="E1,E4" bash tests/e2e-diff/run_p2_matrix.sh` 只跑编辑场景，但
    `compare/report.py` 仍按 `matrix.json` 的全量场景渲染矩阵；未跑的 M1–M10（以及未跑的
    那一侧）没有证据目录，被 report.py 判为「missing evidence」→ **HARNESS-ERROR**。
    结果矩阵里出现 10 行 HARNESS-ERROR，和「全量跑全崩」看起来完全一样。
  - 危害：这是伪证据。后来人翻 `evidence/<run-id>/p2/install-matrix.md` 会把它当成真实
    失败证据：轻则误判 Go/bash 回归，重则把真实回归淹没在这片噪声里，或者反过来被当成
    「已知 HARNESS 问题」而放过。
  - 已修（2026-11-16）：runner 在报告前写 `scope.json`（`runId`/`only`/实跑的
    installs·edits·ops/两侧），`report.py` 仅在 `only` 非空时启用 scope：未跑场景与
    `E3`–`E8` 记 `NOT-RUN`、不再参与 BLOCKER/HARNESS-ERROR 统计；局部跑跳过基线与
    三步改动对比并加首行标注；同侧缺证据仍判 `HARNESS-ERROR`（不能借局部跑藏缺口）；
    无 `scope.json` 的历史证据与全量跑语义逐字节不变（对 `final-full2-8863b10` 做过
    改动前后渲染 diff）。`--self-test` 增补局部跑正反两例。`run_p1_smoke.sh` 不渲染
    矩阵，无需改动。

# P2-G 发布门禁收口（2026-11-16 新增，合并前唯一临界路径）

按此顺序执行，完成标准是 `tests/go-parity/parity/cases/feature_contracts.json`
28 项全部脱离 `PENDING_GO_IMPLEMENTATION` 且 `FUNCTION_PARITY.md` 有正式签收证据。

- [x] **G-1 提交与证据回填**（T8 收尾）：证书对齐轮三个 commit；F12 迁移备注补
  staging 预检、`/etc/idleleo/acme` 账户迁移、`0640/0750 root:idleleo-nginx` 契约、
  `.user-managed`/`.managed-by-idleleo`、`--dry-run`、回滚含 uid/gid 证据
  （`tests/go-parity/evidence/cert-contract-2026-11-16`，单元 + CLI 探测级）。
- [x] **G-2 修 E2E 局部跑伪证据**（见「待办」区详述）：`run_p2_matrix.sh` 写
  `scope.json`，`report.py` 未跑记 `NOT-RUN` 并跳过基线对比，同侧缺证据仍报
  `HARNESS-ERROR`；`--self-test` 补局部跑正反两例，全量证据渲染与改动前逐字节一致。
  理由：后续 G-3 每一项签收都要跑 E2E，不先修会让每轮证据都带噪声。
- [x] **G-3 契约执行器补到 28/28**（现 28：F01/F05/F06/F11/F26/F27/F28 + F12/F14/F15/F22/F25/F16/F19/F23/F07/F18/F08/F02/F03/F04/F20/F21/F09/F10/F24/F13/F17）。
  顺序按「证据已厚、只差写执行器」优先：F12（证书，本轮刚补证）、F14（update）、
  F15（stats）、F22（rill status 只读面）、F25（TCP）、F16（block）、F19（metadata）、
  F06（uuid）、F23（六语言），再补剩余项。每个执行器按 `features/README.md` 契约：真实执行 Go
  新代码、对比固定 Bash 基线、安全差异附批准记录。
  - [x] F04：`F04_test.py` 214/214（连跑两次，CONTAINER_VERIFIED）。覆盖
    primary/secondary 端口与监听、isolate/reject/decoy 策略、多后端/去重/非法后端/
    IPv6、角色与保留端口守卫；每份有效配置真实 `xray -test`，每个 primary 变体
    真实 `nginx -t`；真实执行 Bash 的角色 profile、`modify_inbound_port`、
    `nginx_reality_servers_add`、`nginx_reality_serverNames_add`（含陈旧片段自愈）、
    `write_isolate_site_config` 与 `nginx_reality_conf_add`，两份 stream 配置与 Go
    逐字节一致。修复显式 `--public-port` 命中保留端口时 Nginx 前置与 Xray 后端
    端口冲突（`TestGenerateRejectsReservedPublicPort`）。登记差异：decoy 未生成、
    generate 不自愈陈旧片段、双机数据面/真实服务启动未执行。证据
    `tests/go-parity/evidence/f04-2026-11-17`。
  - [x] F12：`F12_test.py` 在 `idleleo-preview:latest` 内 72/72，含夹具内本地 ACME
    CA（ACME_LOCAL_CA）、权限/回滚/迁移/schedule 替换重载；证据
    `tests/go-parity/evidence/f12-2026-11-16`（连跑两次均全绿）。
  - [x] F14：`F14_test.py` 62/62，签名 manifest、apply/回滚/降级、schedule timer
    与定时真实升级；证据 `tests/go-parity/evidence/f14-2026-11-16`。
  - [x] F15：`F15_test.py` 56/56（真实 Xray 26.11.9 StatsService + HTTP 代理入站
    产生 64 KiB 流量）。Go `stats --json` 原样透传与 Bash `xray_stats.sh --json`
    归一化结果在同一实时计数器上逐值一致（tag 集合、上行/下行/合计、server）；
    另断言 `--pattern`、非 root exit 5（Bash 同为 5）、API down exit 8
    （Bash 基线 2，差异记录在 `exit-code-divergence.json`）、缺配置/坏 JSON/
    缺 api.listen exit 3、坏参数与路径穿越 exit 2、`--watch/--reset/--yes`
    显式拒绝 exit 2、查询零写入；schedule `stats-collect` 写
    `schedule/stats.json`（0640）且 API down 时报告 failed。证据
    `tests/go-parity/evidence/f15-2026-11-16`（连跑两次均 56/56）。
  - [x] F22：`F22_test.py` 54/54（absent/active/stale/installed-unobserved/
    坏 config 五态 + 非 root 只读 + 未迁移子命令显式 exit 2）。同时修复
    投影未读真实观察字段 `capturedAtEpochSeconds`（此前只认 mtime 与
    `observedAt` 等），并补 `legacybridge` 单元测试。Bash 基线
    `install.sh --rill-agent-status`（`RILL_XRAY_AGENT_MANAGER` 指向仓库内
    manager）在 installed/mode 上与 Go 一致；空 root 上 Bash 会新建默认
    config 并报 installed=true，且状态 JSON 不含观察新鲜度，差异记录在
    `baseline-compare.json`。证据 `tests/go-parity/evidence/f22-2026-11-16`
    （连跑两次均 54/54）。
  - [x] F25：`F25_test.py` 78/78（沙箱 `/proc/sys` 普通文件）。覆盖
    status/plan 只读、`--confirm` 门禁、事务写入与幂等、正常/二次
    rollback、漂移时 apply 与 rollback 均 exit 7 且删掉漂移后可恢复、
    pending journal 阻塞与恢复、foreign/99- 冲突/symlink/未知 profile、
    无 bbr 内核 exit 12、非 root 真实 root apply exit 6 与非 root 只读
    status、真实内核不变；投毒 `curl/wget/tcp.sh` 的 PATH 证明从不调用。
    Bash `-tcp` 只执行本地 `tcp.sh` 且已拒绝下载，无法作为等值基线，
    差异记入 `baseline-absence.json`。证据
    `tests/go-parity/evidence/f25-2026-11-16`（连跑两次均 78/78）。
  - [x] F16：`F16_test.py` 94/94（环回 GeoData origin + 一次性 sandbox）。
    `schedule install --geodata-url` 写 0640 配置；成功刷新两资产逐字节一致、
    0644/0755、detail 含字节数与 `sandbox root, no service reload`、state/log
    落盘、二次运行 `runs=2` 无残留、外部 `/usr/local/share/xray` 树不变且不写
    `geo_version.json`。badsha/truncated/empty/html/missing/mixed 六种失败均
    rc=1、旧资产 digest 不变、无 temp/stage 残留、state 记 failed；首次失败
    连目标目录都不创建。未标记 sandbox、非 root 真实 root、`geodataDir`
    逃逸、未知 job 均显式失败且零越界写入。Bash `scripts/geo_update.sh`
    固定 GitHub release、不能作为 hermetic oracle，六条契约以静态比对写入
    `baseline-compare.json`（缺 pinned tag/`geo_version.json`、`xray run -test`、
    stage/restore、旧布局迁移；restart 仅真实 root）。证据
    `tests/go-parity/evidence/f16-2026-11-16`（连跑两次均 94/94）。
  - [x] F19：`F19_test.py` 136/136（连跑两次均全绿，容器级 CONTAINER_VERIFIED）。
    node import 不重写源/运行配置/证书/入口/cron、元数据 0640 且不含密钥、
    重复导入 rc=3 不覆盖、任意 `--from` 与未标记根 rc=2 零写盘；缺配置/坏
    JSON rc=2、缺运行配置 rc=3 且 etc/var/usr 逐字节不变（只新增
    `run/lock/idleleo-update.lock`）；relay 映射 role/tls/transport 且运行摘要为空；
    export 默认只读、`--out` 0600、托管目录与覆盖元数据 rc=2；运行配置漂移
    `matchesMetadata=false`，陈旧/漂移导出 `bridge deactivate` 均 rc=6 且零写盘，
    恢复后交还归档元数据（0640 逐字节）并保持入口/cron/证书/运行配置不变。
    Bash `--backup`/`--restore` 记为 `not-implemented` 写入 `bash-baseline.json`。
    证据 `tests/go-parity/evidence/f19-2026-11-16`，hygiene 0 findings。
  - [x] F06：`F06_test.py` 122/122（连跑两次均全绿，CONTAINER_VERIFIED）。
    list 主用户标记；add 事务 COMMITTED、0640、无残留且非用户字段不变、随机
    v4 与配置一致；重复 email/uuid/shortId、非法 uuid/shortId、缺 `--sandbox`、
    未标记根均 rc=2 零写盘；remove 精确删除二级用户，主用户/未知用户 rc=2；
    `user uuid` 一次改两个 inbound、`--inbound` 收窄、dry-run/无变化零写盘、
    目标重复/非法值 rc=2；validator 拒绝 rc=8、write-fail rc=13、service-fail
    rc=9 且配置逐字节还原、无残留；Bash `UUIDv5_tranc`/`--uuid-reset` 记为
    `not-implemented` 写入 `baseline-compare.json`。证据
    `tests/go-parity/evidence/f06-2026-11-16`，hygiene 0 findings。
  - [x] F23：`F23_test.py` 103/103（连跑两次均全绿，CONTAINER_VERIFIED）。
    六码均接受；zh/en help 不同且顶层命令清单完整；fr/fa/ru/ko 的 version/help
    stdout 与 en 逐字节一致、每次恰好一条英文回退提示，zh/en 无提示；非法
    `de/ZH/zh_CN` 子命令 rc=2 英文 help，`--version/--help` 预校验行为锁定并记入
    差异；`LANG`/`LC_ALL` 与 `etc/idleleo/language.conf` 均被忽略、默认 zh；空根
    status=3、未知命令=2 跨语言一致且只读调用零写盘；无 TTY 输出本地化 `no_tty`，
    45 列 PTY 菜单仍为英文单行提示且无 ANSI，zh/en help 最长行 111/133 列（无窄屏
    适配）；用 `gettext.GNUTranslations` 实测 Bash 六个 `.mo` 均有 `总览`/`信息`
    译文，六语言完整度、回退粒度、language.conf、菜单盒与 ANSI 五类差异写入
    `baseline-compare.json`。证据 `tests/go-parity/evidence/f23-2026-11-16`，
    hygiene 0 findings。TTY 菜单本地化与窄屏适配未对齐，未写成已签收。
  - [x] F07：`F07_test.py` 94/94（连跑两次均全绿，CONTAINER_VERIFIED）。
    `generate --mode reality` 自动 shortId 8 hex 且配置/URI 一致、两次不同；显式
    16 hex 与 4 hex 均落盘进 URI，奇数/17 位/非 hex/空格 rc=2 且不写文件，空值回退
    自动生成；`user add --short-id` 事务 COMMITTED、sid 与 client 各增一项、非用户
    字段不变、mode 0640 保留，重复/非法/非 Reality inbound 均 rc=2 零写盘且无事务
    残留；`share` 的 sid 取首个 accepted sid，metadata `shareLinkOnly` 的 fp/spx
    装饰链接而运行配置 SHA-256 不变，未知用户 rc=1 且无 URI，客户端另配 sID 时链接
    仍用首个 sid（无每用户绑定）；`short-id-list` 每 sid 一行且零写盘。Bash
    `generate_reality_short_id`/`generate_spiderx` 从固定 install.sh 提取后真实执行，
    16 hex 与 spiderX 模板实测；自动形状 8 vs 16、自定义约束、每用户
    `reality_clients` 映射、自动 spiderX、链接模板与 spx 编码六类差异写入
    `baseline-compare.json`。证据 `tests/go-parity/evidence/f07-2026-11-17`，
    hygiene 0 findings。每用户映射与自动 spiderX 仍未实现，未写成已签收。
  - [x] F18：`F18_test.py` 178/178（连跑两次均全绿，CONTAINER_VERIFIED）。
    真实 `generate` 出六份配置（reality raw、reality+ws 伴随入站、TLS ws/grpc/xhttp、
    none ws）后由 `share` 派生：Reality URI 携带 flow/sni/fp/pbk/sid 且无 `target`，
    Clash `reality-opts` 的 public-key/short-id 与 URI 一致；`--public-port` 只改客户端
    视图且配置 SHA-256 不变；Reality 伴随 ws 入站以 `--inbound 1` 出 security=none 链接，
    越界入站 rc=1 且无 URI；回环 security=none 在缺 `--public-security` 时以「ambiguous」
    拒绝、补 tls 后出 TLS 链接并告警 proxy 终止、补 none 出明文链接；xHTTP 不伪造 Clash，
    `clash-xhttp-unsupported` 同时出现在 JSON 与文本输出；`share --qr` 调用真实
    `qrencode -o - -t utf8`（e2e 镜像内 4.1.1），矩阵与同一 URI 的直接调用逐字节一致
    （4994 B/31 行，sha256 相同）；`--qr` 为显式旗标，默认文本与 `--json` 不变，
    `--json --qr` rc=2、缺 qrencode 时 rc=1 且 stdout 为空、未知旗标仍 rc=2；
    Bash `generate_vless_link`/`generate_clash_config` 模板与 10 处 `qrencode` 调用
    静态比对，target、fp、path 编码、mode=auto、none 链接 sni、Clash 键、xHTTP Clash、
    二维码（Go 显式 `--qr` vs Bash 每链自动打印）八类差异写入 `baseline-compare.json`。
    证据 `tests/go-parity/evidence/f18-qr-2026-11-17`，hygiene 0 findings。gap：未做
    手机扫码解码、终端宽度与不同 qrencode 版本未适配、未在真实 VPS 验收。
  - [x] F09：`F09_test.py` 65/65（连跑两次均全绿，CONTAINER_VERIFIED）。
    真实 `generate --mode reality-balance --role primary` 产物 + 真实 nginx 1.24
    `-t` 初始化；`add 10.0.0.2:8443 weight=60` 写出的 60 字节片段与 Bash
    `fm_create_server_file` 逐字节一致（sha256 `7326cff4…`）；list TSV/JSON 按
    host/port 排序且零写盘；重复 host、保留 443、非法 host、端口 0/65536、权重
    101/-1、未知 upstream 均按实测 rc 拒绝；删 loopback/错端口/缺文件 rc=1；
    破坏 nginx.conf 时 add rc=1 且删除新片段，恢复后同一 add 成功；TLS ws 安装
    只接受 ws/grpc/xhttp，reality rc=1；`--probe` 对真实 TLS 1.3+SNI 监听返回
    `probed=true`；缺 metadata rc=3、缺锚点/缺 nginx rc=1。Bash 的列表/JSON、
    重复/保留端口、loopback 删除与 reload 行为记为 approved-difference。gap：
    未在真实 VPS/systemd/防火墙验收，真实根 `/` 的 `--container` 门禁与跨机
    probe 未执行，TLS server 块用最小替身（真实块由 F02 覆盖）。证据
    `tests/go-parity/evidence/f09-2026-11-17`，hygiene 0 findings。
  - [x] F10：`F10_test.py` 38/38（连跑两次均全绿，CONTAINER_VERIFIED）。
    新增 `idleleo xray tls --version 1.3|1.2+`：按 `ssl_protocols` /
    `$ssl_preread_protocol` 定位托管文件，Reality 安装切换 map 条目、TLS 安装
    只允许 1.3（h3/quic 要求，1.2+ rc=1），`nginx -t` 或 reload 失败还原原字节。
    真实 Reality 安装 + 真实 nginx 1.24 `-t` 下，1.2+/1.3 与 TLS 1.3 三种产物
    均与 Bash `tls_type` 逐字节一致；重复调用零写盘；缺 metadata rc=3、缺托管
    前端 rc=1、非法/缺失 `--version` rc=2。Bash 的 1.2 交互循环、sed 直写无回滚、
    重启 nginx+xray 记为 approved-difference。gap：沙箱根跳过 reload，未在真实
    systemd/VPS 验收，未做线上 TLS 握手。证据 `tests/go-parity/evidence/f10-2026-11-17`，
    hygiene 0 findings。
  - [x] F24：`F24_test.py` 58/58（连跑两次，CONTAINER_VERIFIED）。新增
    `idleleo container status/up/down`，无 systemd 时直接管理 xray/nginx 进程与
    pid，真实 nginx 1.24 + 替身 xray 下验证 dry-run/up/down/幂等/二次 down no-op；
    真实根与无 marker 沙箱 rc=2；Dockerfile 多阶段构建并携带 Go 入口，
    entrypoint 的 Go 分支不调用 systemctl；Bash `_start_services/_stop_services`
    真实执行，启停集合一致。gap：无真实 systemd 分支、xray 为替身、本轮不
    `docker build`。证据 `tests/go-parity/evidence/f24-2026-11-17`，hygiene 0 findings。
  - [x] F13：`F13_test.py` 58/58（连跑两次，CONTAINER_VERIFIED）。新增
    `idleleo update xray|nginx`：显式清单（component/version/sha256/sizeBytes/url）
    硬校验（`schemaVersion=1`、`sizeBytes>0`，https 清单/资产拒绝降级 http）、
    拒绝降级 rc=4、同版本 `reinstall`、备份到
    `etc/idleleo/backup/<component>-<ver>-<ts>`、激活后版本与健康检查
    （xray `run -test`、nginx `-t`）、失败自动回滚 rc=6、回滚失败 rc=10，
    仅真实 systemd root 重启。环回 HTTP 清单下验证 xray 成功/重装/降级/
    坏摘要/坏大小/健康回滚；nginx tar.gz 整树替换与坏包回滚（真实 nginx 1.24
    `-t`）；清单/旗标/真实根门禁与零写盘断言；Bash `version_compare` 9 组
    版本表与 Go 逐项一致。gap：未在真实 VPS 更新真实组件、未触发 systemd
    重启、未覆盖 Bash 交互确认/CDN 回退/Layer 2-3。证据
    `tests/go-parity/evidence/f13-2026-11-17`，hygiene 0 findings。
  - [x] F17：`F17_test.py` 113/113（连跑两次，CONTAINER_VERIFIED）。新增
    `idleleo net dns` 与 `net firewall status|apply|revert`：`internal/netcfg`
    复刻 Bash `classify_resolved_ips`/`validate_domain_network_records`
    （显式 ipv4 仍查 AAAA、坏记录 rc=2、无匹配 rc=1），family 由模式推导，
    端口/family 状态落 `etc/idleleo`，apply 差分执行并逐条登记逆操作，
    命令或 state 写失败整单回滚，逆操作失败 rc=10，dry-run 零执行零写盘，
    真实根需 `--container`。进程内权威 UDP DNS 下验证 dual/stale AAAA/
    显式策略/仅 AAAA/无匹配/NXDOMAIN；PATH shim 下验证 4+4 规则、端口差分、
    dual↔ipv4/ipv6 切换、注入 `ip6tables -I` 失败回滚、逆操作失败 rc=10 且
    后续 apply 可收敛、status 缺失规则如实报告且只检查 `managed_families.json`
    记录的族（ipv4-only apply 不写 `rules.v6`）、revert 幂等、
    隐藏 ip6tables fail-closed；Bash 分类函数 6 组与 family 映射 10 行一致。
    gap：无真实 VPS/netfilter、未验证重启持久化、未覆盖 nft/ufw/firewalld。
    证据 `tests/go-parity/evidence/f17-2026-11-17`，hygiene 0 findings。
- [x] **G-4 解 M8 HARNESS-BLOCKED**：已修并双跑通过。
  - 场景内起本地 Pebble（ACME v2，`PEBBLE_VA_ALWAYS_VALID=1`/`PEBBLE_VA_NOSLEEP=1`），
    双侧走真实 HTTP-01；bash 侧用 `SSL_CERT_FILE` 信任 Pebble 根证书，
    `IDLELEO_ACME_DIRECTORY` 指向场景内 directory。
  - Bash 的 PATH 遮蔽（`/usr/bin/idleleo -> install.sh`）导致 ELF 探测失败回退公网 CA；
    按 install.sh 已提交 Bridge 迁移的语义预置软链到 Go 二进制，不改 install.sh。
  - 两侧安装器都不注册续期调度，而 bash 安装后断言必须有活跃调度；双侧统一执行
    `idleleo schedule install`（业务文档化步骤），断言变为 `idleleo-schedule.timer: active`。
  - 结果：两次独立 run（`g4-m8-run7-20261117`、`g4-m8-run9-20261117`）双侧 round1/2 rc=0、
    L4 ws 两轮 ok、L6 ok、Pebble 账号签发（`https://pebble:14000/my-account/...`）。
    run8 因 nginx 下载 `curl: (18)` 网络抖动记 HARNESS-ERROR，按规则换 RUN_ID 重跑。
    L1 差异 26 条与既有 13 类同源，按 policy 单独登记 `ED-C14`；无未抑制路径。
- [x] **G-5 C6 拍板**（见 T14 末项）：已拍板实施并落地（见上条 C6），级别 CONTAINER_VERIFIED。
- [ ] **G-6 验收**：`check_release_gate.py` rc=0；本地/CI 两套跑法口径一致
  （矩阵不许出现局部跑伪证据）；`FUNCTION_PARITY.md` 28 项全部有正式签收行。
  2026-11-17 本地可验证部分已做：
  - 28/28 签收行齐全且 6 列无空值（修掉 F07/F09/F10/F13/F17 备注列未转义 `|` 的断行）；
  - 28/28 可执行夹具存在，`missing tests 0`；22/28 有归档证据目录，6 项（F01/F05/F11/F26/F27/F28）
    仅有 preview 夹具输出；
  - 本地无参数与「工作流同参数」两种跑法都停在同一点：`pending 28`、rc=2；
  - CI 机制阻塞已修（2026-11-17）：`go-release-qualification.yml` 补
    `push: develop/go-native` / `pull_request` 触发、安装 nginx+Xray 前置、以 root 运行闸门
    并显式透传 `GITHUB_SHA`、job 超时提升到 180 分钟、上传夹具证据 artifact；
  - 证据 `tests/go-parity/evidence/g6-2026-11-17/`（release-gate.out、release-gate-with-args.out、
    signoff-audit.md、ci-closeout.md）。
  **未闭合（阻塞，不可伪造）**：G-6 范围内本地与 CI 机制侧的可执行项已全部完成；
  剩余唯一阻塞是账本签收——28 项仍为 `PENDING_GO_IMPLEMENTATION`，需要真实 VPS/VM 签收；
  `workflow_dispatch` 仍只在默认分支可见（分支上改由 push/PR 触发），且本地无
  `GITHUB_ACTIONS`/`GITHUB_SHA`，故 rc=0 只能在受保护 CI 上、账本签收之后取得。
  CI 结清步骤见 `tests/go-parity/evidence/g6-2026-11-17/ci-closeout.md`。

# Task Dependencies

- T2/T3/T4 可并行，T7 依赖 T2–T6，T8 依赖 T7。
- T5 依赖 T7 的 M4 证据，结论可能回写 spec。
- T9–T11 按序独立验收；T12 依赖 T9–T11 完成。
- T13 依赖 T7；T14 依赖 T13（OPS 待办来源）。
- P2-G 内部按 G-1→G-2→G-3→G-6 串行，G-4/G-5 可与 G-3 并行；T8 并入 G-1。
