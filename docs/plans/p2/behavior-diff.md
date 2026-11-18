# P2 Go vs Bash 行为差异清单

口径：**Go 对齐 bash，除非真的做不到**。不动 `install.sh`；不静默删除安全闸。
每项标注改动层：CLI 校验 / 生成逻辑 / 安装落地。

| ID | 场景 | 差异 | 分类 | 改动层 | 结论 |
|----|------|------|------|--------|------|
| G1 | M3 Reality + ws | Go 原 `Generate` 拒绝 `--transport ws`（`unsupported transport "ws" for mode reality`），bash 是 Reality 主 inbound + 附加 ws | 可改 | 生成逻辑 | 已改：Reality 保留 raw 主 inbound，ws/grpc/xhttp 以端口 +1 追加，等同 `reality_add_more` |
| G2 | M10 中转 | bash 装 Nginx Stream、写 `relay-stream.conf`、include 进主配置并起服务；Go 只有 `xray relay` 仅生成 conf | 可改 | 安装落地 | 已改：新增 `xray install --role relay`，复用 managed Nginx(stream) + `EnsureRelayInclude` + `Finalize` |
| G3 | M4 nginx 目录 | 曾怀疑 bash 用 `/usr/local/nginx`、Go 用 `/etc/idleleo/conf/nginx` | 不可改（实为无差异） | 无 | 已复核：两侧二进制目录都是 `/usr/local/nginx`，fragment 目录都是 `/etc/idleleo/conf/nginx`，fragment 文件集合一致；Go 仅多一个 `/etc/idleleo/v1/nginx.json` 元数据。不改 |
| G4 | D3 重复安装 | Go 原在配置存在时非零退出；bash 默认保留配置并幂等接管 | 可改 | 安装落地 + CLI 校验 | 已改：默认保留并告警；`--keep-config` 显式保留、`--rewrite-config` 显式覆盖；保留时仍生成 fragments |
| G5 | M2 CLI 形态 | bash 语义是 `--mode reality --nginx-bin`，Go 用 `--mode reality-nginx` | 可改（兼容别名） | CLI 校验 | 已改：`--mode reality --nginx-bin` 自动映射为 `reality-nginx`，原形态不变 |
| G6 | M9 监听 / M5–M7 `--binary` | 测试 argv 缺参或未显式监听 | 测试侧问题 | 测试 argv | 已改测试：补 `--binary`；M9 显式 `--listen 0.0.0.0 --allow-non-loopback` |
| G7 | 安全闸 | Go 的 loopback 监听保护、配置覆盖保护、容器写入确认 | 需拍板（仅在必须动时） | — | 均未删除。M9 通过显式参数放行；D3 通过 `--rewrite-config` 才覆盖；relay 保留混合安装拒绝 |
| G8 | M10 relay 文件集合 | Go relay 角色多写 `00-xray.conf`/`03-isolate.conf` 占位，主配置凭空 include 两个不存在的文件；bash relay 只有 `relay-stream.conf` | 可改 | 安装落地 | 已改：`InstallSpec.RelayOnly` 控制占位创建；`RewriteMainConfig` 的 Stream 分支仅节点模式 include；M10 两侧文件集合一致 |
| G9 | 附加传输端口 | Go 用 `base+1` 硬偏移，不探测占用、不排除 bash 保留端口 | 可改 | 生成逻辑 | 已改：ws/gRPC 10000–10999、xHTTP 11000–11999 升序候选 + bind 探测 + 保留端口排除 + `--ws-port/--grpc-port/--xhttp-port` 覆盖；65535 不回绕 |
| G10 | TLS 回环端口 | Go TLS 模式回环 inbound 与 Nginx 共用公网端口，重启必 `EADDRINUSE` | 可改 | 生成逻辑 | 已改：回环 inbound 取传输端口池，Nginx 独占公网端口；share 仍用公网端口 |
| G11 | 配置编辑能力 | bash 靠菜单改配置，无配置级自检、patch 语义与回滚 | 可改（Go 领先） | CLI + 生成 + 安装落地 | 已新增 `xray config edit`（规格 `interactive-config-editing-discussion.md` v1.0）：patch、自检、备份、回滚、二次确认、`--dry-run`/`--no-restart`/`--json` |
| G12 | `xray logs rotate enable` | 缺 `logrotate` 时 bash 自动 `pkg_install` 后继续；Go 不调用系统包管理器 | 主动不对齐（已批准） | CLI 校验 + 安装落地 | 保持不自动装包：缺二进制时在任何写入前失败，并打印可直接复制的安装命令；详见下节 |
| G13 | `fail2ban install` | 缺 fail2ban 时 bash 自动 `pkg_install` 后继续；Go 同样不调用系统包管理器 | 主动不对齐（已批准） | CLI 校验 + 安装落地 | 缺 `fail2ban-client` 时失败并打印 deb/rhel/alpine 安装命令，零落盘；与 G12 同一原则 |
| G14 | 负载均衡后端增删 | bash 的 file_manager 只管写文件+重启，不校验角色、不校验重复 host、不拦保留端口、删到空也不拦；Go 收紧 | 主动收紧（Go 更严，不进 ED） | CLI 校验 + 生成逻辑 + 安装落地 | reality-nginx 与二级服务器拒绝增删并指路 `--mode reality-balance --role primary`；拒绝删空最后后端/重复或非法 host/保留端口；`nginx -t` 失败回滚；默认不探测并提示依赖 `max_fails`/`fail_timeout` 被动摘除，`--probe` 才做 TCP+TLS1.3+SNI；详见下节 |
| G19 | 单用户 UUID 轮换 | bash 只能手改 `config.json` 的 `clients[].id` 再重启，没有定位、只改叶子断言与回滚；Go 新增 `xray user uuid` | Go 增量（bash 无对应命令，不进 ED） | CLI + 配置编辑 + 安装落地 | email 为准、UUID 为别名、拒绝索引；命中多个 inbound 时一次 clone、一次事务全改；失败零落盘；输出明确“重启、所有会话秒级中断”，dry-run 同样列出 inbound 与旧 UUID；`config edit --uuid` 在多用户配置下报错并给出可复制的目标命令。证据 `tests/e2e-diff/evidence/c5-20261115-142437`（26/26） |

## 主动不对齐：G12/G13 不调用系统包管理器

这是**主动选择不做**的对齐，不是能力缺口，因此不登记 ED。G12 是 `logrotate`，
G13 是 `fail2ban`，理由与后果相同。

选择：`xray logs rotate enable` 与 `fail2ban install` 在缺少依赖二进制时，于**任何写入前**
失败（rc=1），并打印可直接复制的安装命令；Go 管理器永不调用 `apt`/`dnf`/`apk`。

理由：

- 安装器运行时会以 root 身份拉起发行版包管理器，等于把「联网 + 执行第三方包脚本」
  这一动作塞进一个只读校验命令里；包管理器失败态（锁占用、源不可用、dpkg 中断）
  还会把「写日志轮转配置」变成半完成状态。bash 承担这个风险是因为它整条链路都是
  shell 命令拼装；Go 侧没有必要复制。
- 缺少的二进制是可以被操作者一句话补上的前置条件，报错比静默装包更可预期，
  也符合 Go 侧其他前置条件（`--binary`、`engineVersion`）的处理方式：缺就报错、不猜。
- 单测 `TestEnableLogRotationNeedsTheBinary` 与 `TestFail2banInstallRequiresTheBinary`
  固化该行为：缺二进制时零落盘，不能出现配置写了一半的中间态。

后果（必须写清，避免后来人误判为 bug）：

- **全新系统上 `xray logs rotate enable` 与 `fail2ban install` 都会先失败一次**，
  操作者装完 `logrotate` / `fail2ban` 重跑即可；bash 的 `6>5`、`6>2>1` 流程会自动装包、
  一步到位。这是唯一可感知差异。
- 报错里已给出 Debian/Ubuntu、RHEL/Fedora、Alpine 三条命令，并说明「Bash installs it
  automatically」，操作者不需要查文档。
- `xray logs clean` 不受影响（截断日志不依赖 logrotate）。
- `fail2ban uninstall` 也因此**不会卸载软件包**：只按 manifest 删 Idleleo 写的
  `jail.d/*.local`、自定义 filter 与 drop-in，然后重启服务卸载这些 jail，
  并在输出里明确说明「包仍在，操作者需要自己决定是否卸载」。bash 的卸载会
  `pkg remove` 并顺带删掉 `jail.d/*.local` 全部（包括用户自定义规则），这里刻意不跟。

何时重新评估：若以后 Go 管理器引入统一的「前置依赖解析」层（例如安装流程本身就要
校验并补齐一组宿主依赖，且已有可回滚的事务边界），可以把 logrotate 挂进那个层；
在那之前不做单点特殊处理。

## 主动收紧：G14 负载均衡后端增删

Go 的 `xray balance add|list|remove` 与 bash `2>3>1`（file_manager）在**生成物**上一致：
两侧都写 `<host>.<ws|reality>Servers`，行格式同为
`server <host>:<port> weight=<weight> max_fails=2 fail_timeout=10;`，删除后文件消失。
差异在于 Go 在 CLI 层多挡了几类会让线上 Nginx 失效或误操作的动作，**这是主动收紧，
不是缺口，因此不登记 ED**：

- **角色闸**：`reality-nginx` 与 `reality-balance` 二级服务器的后端不由 `xray balance`
  管理，增删一律拒绝，并在报错里指路 `--mode reality-balance --role primary`；
  只有 TLS 安装与 reality-balance 主服务器可增删。
- **删空最后后端**：`remove` 在只剩 1 个后端时拒绝，避免 upstream 变空导致 `nginx -t`
  失败或 502 面扩大；同时拒绝删除本机回环前端（`127.0.0.1`）与端口不匹配的文件。
- **重复/非法 host 与保留端口**：`add` 拒绝已存在同名后端、非法主机名，以及
  `443/9403/9404/9443/9444`（本机公网 TLS、Xray 回环、Reality 后端入口）。
- **`nginx -t` 失败回滚**：写入后先 `nginx -t`，失败则删除新文件（`remove` 则原子恢复
  原文件）并返回错误，不留半完成状态。
- **默认不探测**：不加 `--probe` 时不做存活探测，输出里明确提示依赖 Nginx 的
  `max_fails=2 fail_timeout=10` 被动摘除；只有 `--probe` 才做 TCP 连接 + TLS 1.3
  + SNI 握手探测（证书信任不参与判定）。

上述守卫由 `go test ./internal/deploy -run Balance` 固化；端到端一致性由 OPS-09
（TLS/ws）与 OPS-31（Reality primary）双端实跑取证。

## 主动不对齐：G18 shortId 长度形态

bash 与 Go 在 shortId 的**长度形态**上刻意不统一：

- bash 安装/校验强制 **16 hex**（8 字节），不是 16 位就拒绝。
- Go 自动生成 **8 hex**（4 字节）；`xray config edit --short-id` 接受
  **1–16 位偶数 hex**（含空串元素），`--short-id ''` 才表示显式清空。

不对齐的理由：

- shortId 是 Reality 的会话判别盐，不是密钥。4 bit/字符，8 hex = 32 bit、
  16 hex = 64 bit，两者都足够；安全强度由 X25519 privateKey 承担，不由 shortId 长度承担。
- 强制 16 位只会**缩小**可用的 id 空间：操作者从旧机器、其他面板或客户端迁移过来的
  合法短 id（2/4/8 位）会被无理由拒绝；Reality 服务端本身接受更短的值。
- Go 侧把「自动生成」和「显式给出」分开：不指定时给 8 hex；指定时按协议允许的范围
  校验（偶数 hex、≤16、允许空），不把 bash 的安装期习惯升级成编辑期约束。

后果：同一台机器上 bash 装出来的 sid 是 16 位，Go 装出来的是 8 位；两端都能互相
接受对方的 id。`xray -test` 与真实 xray 客户端握手均通过（E7 用的就是 Go 生成的
8 位 id）。这是形态差异，不是兼容性缺口，不登记 ED。

## 需拍板 / 仍保留

- 目前无“必须动安全闸才能对齐”的项，故无待拍板项。
- Bash 侧重复安装有一个已观测问题（非 Go 差异）：在服务运行中对已安装节点执行
  “保留配置重新安装”，`port_exist_check` 把自己的 443 判为被占用并回滚
  （`is_project_service_pid` 未识别到本项目进程，具体成因待 bash 侧单独排查）。
  P2 第 2 轮因此在两侧先停 `xray`/`nginx` 再重装，只验证“配置幂等”，
  不把该问题算作通过。是否修 bash 该守卫需另立需求。
- M8（ACME）已解，不再是 HARNESS-BLOCKED：场景内起本地 Pebble（ACME v2，
  `PEBBLE_VA_ALWAYS_VALID=1`/`PEBBLE_VA_NOSLEEP=1`），双侧都走真实 HTTP-01 签发
  （account `https://pebble:14000/...`，notAfter 2027-02-15）。harness 有两个要点：
  一是 install.sh 的 PATH 让 `/usr/bin/idleleo` 指向脚本自身，`idleleo_native_acme_available`
  的 ELF 探测因此失败并回退公网 CA；按 install.sh 的「已提交 Bridge 迁移」语义
  （`install.sh` L13664-L13690）
  预置软链到 Go 二进制即可，不改 install.sh。二是两侧安装器都不自行注册续期调度，
  而 bash 侧安装后断言必须有活跃调度，故双侧安装后统一执行业务文档化的
  `idleleo schedule install`。
- M8 的 L1 布局差异 26 条与 M1–M7/M9/M10 的 13 类同源；按 policy「新增场景必须新开
  ED」单独登记 `ED-C14`，不放宽既有类的场景范围。ACME 专属产物（`cert/`、
  `.well-known/`、`schedule/`）两侧已对齐，不在差异内。
  证据：`tests/e2e-diff/evidence/g4-m8-run7-20261117`、`g4-m8-run9-20261117`
  （run8 因 nginx 下载 `curl: (18)` 网络抖动记 HARNESS-ERROR，按规则换 RUN_ID 重跑）。
- Go 不提供 bash 的“重新进入交互菜单改配置”流程；D3 只对齐“重复安装默认保留配置”的结果，不复制交互体验。若要求交互等价，需另立需求。

## 测试侧修正（不是 Go 缺陷）

- `collect/l4.sh`：macOS bash 3.2 在 `set -u` 下展开空数组 `"${EXTRA[@]}"` 报
  `unbound variable`，导致两侧 L4 都记失败。改为 `${EXTRA[@]+"${EXTRA[@]}"}`。
- `collect/idempotency.sh`：bash 重装会按设计新建
  `/etc/idleleo/backup/reinstall-<ts>-<rand>/`，这是时间戳备份而非幂等漂移。
  L6 仍统计 `backupAddedCount`，但不把它计为 added/removed 失败。
- `drivers/bash_menu.exp` / `matrix.json`：菜单层级修正——安装向导为
  `主菜单 1 > 安装向导 1(Reality) > 2(标准)/3(+传输)`；M2 用 `1>1>1`，
  M3 用 `1>1>3`。M10 第 2 轮补公网 IP 提示；M3 补 ws 端口/路径提示；
  menu 型入口重装后会回到管理菜单，第 2 轮改为发 `0` 正常退出（不再 `exit 124`）。
- `collect/l4.sh` + `collect/client_config.py`：Reality 的附加传输（ws 等）
  是 security=none 的独立 inbound，探测必须用 inbound 端口且不能套 Reality 设置；
  M3 的 ws 探测按此修正。Reality raw 仍走公网 443。
- `run_p2_matrix.sh`：M10 的 origin 容器改为在安装前启动。Nginx 在加载配置时解析
  后端域名，若 origin 尚未运行，`origin.example.com` 会解析到公网地址，导致
  “Empty reply from server”（两侧同样失败，与 Go/bash 差异无关）。

## 安装落地补强（Go）

- `nginx.InstalledArtifact()`：重复安装/重装时先读取已安装的 managed Nginx
  元数据并校验二进制，命中则跳过 artifact 下载；`nginx.Install` 的
  “已安装同 build” 快路径不再要求下载数据。避免第 2 轮因网络抖动重新下载
  整个 Nginx 包而失败（M10 第 2 轮、M5/M6 曾触发）。
- `nginx` 下载重试：bash 用 `curl --retry 2`（无整体超时），Go 原为单次 60s。
  已改为整体 300s、失败重试 2 次，仅对网络错误重试，摘要/大小校验不重试。

## 证据与验证

- G1：`go test ./internal/xraycfg -run RealitySingleTransport`；P2 M3 两侧 L2/L4。
- G2：`go test ./internal/deploy -run Relay`；P2 M10 两侧 L1–L4（客户端经中转容器回源）。
- G3：P2 M4 manifest 中 nginx 目录/权限对比。
- G4/G5：`go test ./internal/deploy`；P2 所有场景第 2 轮 rc=0、L6 无漂移；M2 两种 CLI 形态 generate 等价。
- G8：M10 两侧 `/etc/idleleo/conf/nginx` 文件集合一致（仅 `nginx`、`nginx.default`、`relay-stream.conf`），`nginx -t` 通过，L4 回源与 L6 幂等通过。
- G9：`go test ./internal/xraycfg -run Port`；第三方占用 10000 时自动选 10001 且输出 warning；M3/M7 两侧端口行为对齐。
- G10：`go test ./internal/xraycfg`；M4/M7 两侧 rc/L4/幂等通过，TLS 场景重启成功。
- G11：`go test ./internal/xraycfg ./internal/deploy`；P2 E1/E2 均 PASS（`evidence/step3-edit2/p2/install-matrix.md`）。
- G12：`go test ./internal/deploy -run LogRotation`（`TestEnableLogRotationNeedsTheBinary`
  断言缺二进制时零落盘）；容器内实测缺 `logrotate` 时 rc=1、报错含三条安装命令、
  `/etc/logrotate.d` 与 drop-in 均未创建。
- G13：`go test ./internal/deploy -run Fail2ban`；容器内实测 fail2ban 1.1.0
  （`install` 写入 4 个 jail、sshd 因无活跃 unit 跳过、`unban` 真实解封并复查、
  `trust add` 运行态+持久化、`jail disable` 改 `enabled=false`、`uninstall` 只删
  manifest 内文件并保留用户自定义 `*.local`）。
- G14：`go test ./internal/deploy -run Balance`（角色闸/删空/重复 host/保留端口/
  `nginx -t` 回滚/`--probe` 缺省）；端到端 OPS-09 与 OPS-31 双端 PASS
  （`evidence/s2-ops-0434/p2/OPS-09/ops.json`、`.../OPS-31/ops.json`）：
  bash 走 M4 或 `1>1>5>1` 安装后用菜单 `2>3>1` 在 file_manager 增/列/删，
  Go 用 `xray balance add|list|remove`，两侧 `<host>.wsServers` 与
  `<host>.realityServers` 内容同形、删除后同时消失。
- G15：`max_fails=2 fail_timeout=10` 被动摘除，OPS-32 双端 PASS
  （`evidence/ops32-measure-1115/p2/OPS-32/ops.json`，ws 与 reality 两条上游均 PASS；
  旧 0523 证据按新 schema 回填，因探测在首个 A 提前停止，只保留 first-A 并标注
  `recoveryWindow.stopReason=first-A (pre-revision evidence)`）：
  - **测量口径**：恢复阶段跑满 60s/120 次，判定取 `stableRecovery`（A 持续被选中到
    窗口末尾、相邻 A 间隔 ≤ `fail_timeout=10s`、链上至少 3 次 A）；
    `firstRecoveryLatencySeconds` 只作参照，不能单独当恢复时间。
  - **ws 上游**：M4 / `--mode tls --transport ws` 安装后两侧各起 `backend-a:9001`、
    `backend-b:9002`，客户端经 Nginx TLS 打真实 `/ws` 流量；`kill -9` A 后 84 次请求
    全部由 B 返回、零 5xx/零连接失败。`perWorkerFails`：bash 10 个 worker 中 9 个达到
    `max_fails=2`、1 个只有 1 次；Go 10/10 达到。静默区间 bash 8.6–12.6s、Go 6.3–12.3s；
    重启后 stable 恢复 bash 13.6s、Go 24.8s（两侧 first-A 与 stable 相同）。
  - **reality 上游**：bash `1>1>5>1` / Go `--mode reality-balance --role primary` 安装后
    用同一组后端；客户端发真实 TLS 1.3 ClientHello（SNI 命中 `*.serverNames`）经 stream
    入口，标记后端回明文标记以标识实际对端；`kill -9` A 后 84 次连接全部到 B、
    零连接失败（stream `proxy_next_upstream` 在 connect 失败时重试）。
    `perWorkerFails`：bash 9 个 worker 只有 4 个达到 `max_fails=2`（其余仅 1 次），
    Go 10 个里 7 个达到。因此 first-A 是取样点而非全局恢复：bash first-A 3.96s、
    stable 17.67s；Go first-A 与 stable 同为 19.36s。
  - **per-worker 抖动区间**：upstream 无 `zone`，`max_fails` 计数按 worker 隔离，
    失败次数、摘除时刻与静默时长都逐 worker 不同（本轮静默跨度见
    `perWorkerJitter.quietMin/quietMax/quietSpread`：reality 侧 1.2–12.5s、
    ws 侧 6.3–12.6s，跨度 4–11s）；不存在全局统一静默窗，单次探测的 first-A
    会随命中 worker 抖动。
  - **限制（不得外推）**：reality 侧的对端是普通 TCP 标记服务，不做 Reality 握手；
    本项只证明 nginx stream 的对端选择与被动摘除，不证明 Reality/VLESS 端到端会话。
- G16：TLS 域名/证书编辑**不自动重签**（与 bash 的显式差异，不属于 ED）：
  - `xray config edit --domain/--cert/--cert-key` 只改 Nginx 引用与 `jobs.json` 的
    `certDomain`/`certFile`/`certKeyFile`，**不发起任何 ACME 网络请求**；证书不覆盖新域名
    （SAN/CN 不匹配，即「改域名但证书还是旧域名」）时直接拒绝，零落盘。
  - 续期链路：Go 不使用 certbot/hook；`jobs.json` 是续期唯一取值来源，`cert-renew` 任务
    优先观测 `cfg.certFile`（旧目录扫描仅作回退）。编辑后未重签时，证书仍在 30 天内到期
    只给 warning，并提示 `idleleo schedule run --job cert-renew`（或 `xray cert renew`）。
  - 与 G15 分开登记：G15 是 upstream 被动摘除，本条是证书生命周期，二者不得互相引用为
    「同一差异」。
- G17：Bash 安装根**拒绝编辑**（主动收紧，不进 ED）：
  - 根下存在 `etc/idleleo/conf/install_config.json`，或 `metadata.provenance` 非 `native`
    （`legacy` 等导入根）时，`xray config edit` 在写入前 rc=2、零落盘，报错指路先迁移。
  - 理由：静默只改两套管理链路中的一套，会让重启后的 Bootstrap 配置覆盖本次编辑，比拒绝
    更危险。
- G18：shortId 长度形态（8 hex vs 16 hex）：
  - bash `shortIds_set` 自定义输入用 `^[0-9a-fA-F]{16}$` 校验，自动生成
    `openssl rand -hex 8`（16 hex）；Go `NewShortID` 自动生成 8 hex，
    编辑接受 1–16 位偶数 hex（含空串元素）。
  - E7 用 Go 生成的 8 位 sid 追加/删除，`xray -test` 与真实 xray 客户端握手均通过；
    bash 侧 16 位 sid 由 M1/M2 安装与 L4 覆盖，二者互相接受。
- 全量矩阵：`tests/e2e-diff/evidence/<run-id>/p2/install-matrix.md`。
