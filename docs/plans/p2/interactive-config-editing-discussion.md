# Go 配置编辑正式规格：`xray config edit` v1.0

状态：**已实施并通过 P2 E1/E2 验收**（2026-11-15）。本文由讨论稿升级而来，
实现与本文不一致时以本文为准；未实现项列入 §12。
适用范围：Go 管理的安装（`reality` / `reality-nginx` / `tls` / `none` / relay）。
`install.sh` 不改，bash 菜单不作为对齐目标。

## 1. 设计结论

1. **子命令为主，菜单仅引导**：编辑能力全部落在 `idleleo xray config edit`；
   `idleleo xray` 无参数仍是帮助入口，不再复制 bash 的多级菜单树。
2. **patch 语义 + 隐含 keep**：只改显式指定的字段，其余值原样保留。
3. **单一生成器**：patch 后仍走 `xraycfg.Generate`，保证分享链接、Nginx fragments、
   元数据与安装路径同源。
4. **先自检后落盘**：`xray -test`（Nginx 场景再加 `nginx -t`）通过前不碰现网文件。
5. **失败可回滚**：备份目录 + 配置/Nginx 快照 + 重启失败自动恢复旧配置。
6. **断线项强制二次确认**：端口、监听、传输、UUID、relay 目标改动必须确认；
   非 TTY 环境要求显式 `--yes`，避免脚本静默断线。
7. 第一梯队 6 项全部实现；第二梯队按 §12 排序。

## 2. 命令语法

```
idleleo xray config edit [value flags...] [boolean flags...]
```

### 2.1 值参数

| 参数 | 作用 | 适用安装 | 备注 |
|---|---|---|---|
| `--port N` | 主监听端口 | reality / none / relay 外的节点；Nginx 前置模式表示公网端口 | Nginx 前置时同时更新 `public-port` |
| `--public-port N` | Nginx 公网端口 | reality-nginx / tls | reality-nginx 下等价于 `--port` |
| `--listen ADDR` | Xray 监听地址 | 仅非 Nginx 前置模式 | Nginx 前置模式直接拒绝 |
| `--transport T` | 传输组合 | 全部 | `raw/ws/grpc/xhttp/ws+grpc+xhttp` |
| `--ws-path P` | ws 路径 | 含 ws 的传输 | 与 `--xhttp-path` 互斥 |
| `--xhttp-path P` | xhttp 路径 | 单 xhttp 传输 | multi 传输固定路径，拒绝修改 |
| `--grpc-service-name S` | gRPC serviceName | 含 grpc 的传输 | |
| `--ws-port N` / `--grpc-port N` / `--xhttp-port N` | 附加传输内部端口 | 对应传输存在 | 跳过 bind 探测（见 §7.2） |
| `--target H:P` | Reality 回源目标 | reality / reality-nginx | 非 Reality 拒绝 |
| `--server-names A,B` | Reality serverNames | reality / reality-nginx | 逗号分隔 |
| `--uuid UUID` | 客户端 UUID | 单用户安装 | 多个 inbound UUID 不一致时拒绝，改用 `xray user` |
| `--relay-target H:P` | relay 落地目标 | relay | 触发 relay 编辑分支 |
| `--relay-listen-port N` | relay 监听端口 | relay | 触发 relay 编辑分支 |
| `--path FILE` | 指定 runtime config | 全部 | 默认由安装元数据解析 |

### 2.2 布尔参数

| 参数 | 作用 |
|---|---|
| `--dry-run` | 只输出预览、diff 与新旧 SHA256，不写盘 |
| `--no-restart` | 只落盘，不重启 Xray / 不重载 Nginx |
| `--yes` | 非交互确认断线项；非 TTY 下必需 |
| `--json` | 机读输出（报告结构见 `EditReport`） |
| `--container` | 允许在容器内写入受管目录 |
| `--allow-non-loopback` | 显式放行非回环监听（保留安全闸） |
| `--rewrite-config` | **不允许**；出现即 rc=2（见 §4） |

### 2.3 默认执行序

1. 解析参数；无任何编辑参数 → rc=2，列出可用参数（不进入交互问答）。
2. 以 `DryRun=true` 生成预览，得到 `changed`、`diff`、`disconnect`。
3. 无变化 → 输出 no changes，rc=0。
4. 给了 `--dry-run` → 打印预览，rc=0。
5. 断线项且未给 `--yes`：TTY 下询问 `Continue? [y/N]`（拒绝 rc=1）；
   非 TTY 直接 rc=2 并提示加 `--yes`。
6. 真正执行（`DryRun=false`），成功输出备份目录与新分享链接，rc=0。

## 3. patch 语义与 diff 白名单

读取 runtime config → 还原为 `xraycfg.Spec` → 仅覆盖显式字段 → 同一生成器生成 →
**逐叶子 diff** 校验，只允许本次请求对应的变化：

| 请求 | 允许变化的路径 |
|---|---|
| `--transport` / `--ws-path` / `--xhttp-path` / `--grpc-service-name` | `inbounds[*]` 全部 + `routing.rules[*]`（tag 引用会重排） |
| `--port` | `inbounds[0].port` |
| `--listen` | 每个 `inbounds[*].listen` |
| `--uuid` | 每个 `inbounds[*].settings.clients[0].id`，以及被生成器规范化的 `email` |
| `--target` | `inbounds[0].streamSettings.realitySettings.target` |
| `--server-names` | `inbounds[0].streamSettings.realitySettings.serverNames` |

白名单外的任何差异都拒绝并提示改用 `xray install --rewrite-config`，避免
「只想改一项、却把别人的配置整段重写」。

多用户安装（inbounds 间 UUID 不一致）拒绝 `--uuid`，提示使用
`idleleo xray user add/remove`。

## 4. 与 `--keep-config` / `--rewrite-config` 的关系

- `config edit` **隐含 keep**：不需要也不接受 `--keep-config`。
- `--rewrite-config` 语义是全量重建，与 patch 冲突；同时出现立即 rc=2：
  `xray config edit patches in place; use 'idleleo xray install --rewrite-config' for a full rewrite`。
- `xray install` 行为不变，仍按 D3 默认保留、显式重写。

## 5. 第一梯队 6 项（已实现）

| # | 能力 | 参数 | 关键校验 |
|---|---|---|---|
| 1 | 主监听地址/端口 | `--listen` / `--port` / `--public-port` | Nginx 前置模式禁止 `--listen`；端口 1–65535；端口变更属断线项 |
| 2 | 传输组合与路径 | `--transport` / `--ws-path` / `--xhttp-path` / `--grpc-service-name` | 路径必须匹配传输；ws/xhttp 路径互斥；multi 不放开 xhttp 路径 |
| 3 | target / serverNames / 伪装域名 | `--target` / `--server-names` | 仅 Reality 模式；重生成后做 `xray -test` |
| 4 | UUID（单用户） | `--uuid` | 仅共享 UUID 的安装；断线项 |
| 5 | 多用户增删查 | 复用 `idleleo xray user add/remove/list` | 不在本命令内重复实现 |
| 6 | relay 落地目标与监听端口 | `--relay-target` / `--relay-listen-port` | 仅 relay 安装；`nginx -t` 为唯一自检；失败回滚 |

顺带实现（理由：与第 1、2 项共用同一套校验/自检/回滚，边际成本低且安装期已支持）：
`--ws-port` / `--grpc-port` / `--xhttp-port` 显式覆盖附加传输端口。

## 6. 断线项与二次确认

断线集合（`disconnectProne`）：`port`、`public-port`、`transport`、`uuid`、`listen`；
relay 分支的任何改动均视为断线。

- TTY：打印将变化的字段，询问 `Continue? [y/N]`，非 y 则 rc=1 且零改动。
- 非 TTY：无 `--yes` 直接 rc=2，提示「will drop live connections; re-run with --yes」。
- `--dry-run` 不做确认，也不写盘。
- 非断线项（target、serverNames、路径等）不询问，直接执行——交互只留给真正需要
  人判断的断线风险。

## 7. 自检、备份、重启与回滚

### 7.1 执行流程（`deploy.EditConfig`）

1. 获取更新锁（dry-run 不加锁）。
2. 解析 config 路径，读取并判定安装类型（`editBase`）。
3. patch → 候选配置（内存）。
4. 变更涉及 `--target` / `--server-names` 时探测有效回源：TCP connect 必做，
   目标端口为 443/8443 且已知 serverNames 时再做 TLS 握手（不校验证书链，只验证
   可握手）。失败返回 `origin unreachable`，rc=2、零落盘；dry-run 同样探测。
5. dry-run / 无变化：直接返回报告。
6. 候选写入同目录临时文件 `.edit-candidate-*.json`（0600），执行
   `xray -test -config <tmp>`；失败则删除临时文件并返回错误，**现网零改动**。
7. 写备份目录（§7.3）。
8. 快照 config（内容、mode、uid/gid）与 Nginx 目录常规文件。
9. Nginx 场景：写 fragments → `nginx.Finalize{NoService:true}`（权限 + `nginx -t`）。
10. 原子写 config，保留 mode/uid/gid。
11. 默认 `systemctl restart xray` 并等待 active；`--no-restart` 跳过。
12. 默认再执行 `nginx.Finalize` 完成重载；`--no-restart` 时只校验不重载。
13. 成功：更新管理元数据（transport、runtime sha256、TLS 标记、updatedAt）、
    裁剪旧备份、输出 backup 与新 share URI。

### 7.2 端口探测例外

编辑对象就是当前运行中的服务，生成器若沿用安装期 bind 探测，会把服务自己的监听
判为占用。因此编辑路径设置 `Spec.SkipPortProbe=true`：跳过 bind 探测，
保留范围（1–65535）、重复、保留端口（9403/9404/9443/9444）校验。

### 7.3 备份与保留

- 目录：`/etc/idleleo/backup/edit-<UTC yyyymmddThhmmss>/`
- 内容：`config.json`（改前原文）、`nginx-<文件名>`（Nginx 目录每份常规文件）、
  `manifest.json`（配置路径、changed、diff、创建时间）。
- 保留最近 20 份，多余按时间倒序删除。
- 备份是人工恢复入口：不依赖本工具也能还原。

### 7.4 回滚

任一后续步骤失败（写 Nginx、`nginx -t`、写 config、重启、active 检查、重载）触发：

1. 恢复 config 快照（内容 + 权限）；
2. 恢复 Nginx 目录快照（含删除本次新增文件）；
3. 默认重启 Xray 回到旧配置；
4. 重新 `nginx -t` / 重载；
5. 返回错误并附 `previous configuration restored`；回滚本身失败则并列报告
   首个失败步骤，错误信息不出现 `<nil>`。

relay 分支同理：恢复 `relay-stream.conf` 与 Nginx 快照并重新 `nginx -t`。

## 8. 支持的安装类型

| 安装类型 | 可编辑 | 判定方式 |
|---|---|---|
| reality（无 Nginx） | 是 | 无 `00-xray.conf`，首个 inbound `security=reality` |
| reality-nginx | 是 | `00-xray.conf` 含 `stream {`，且 `.realityServers` 后端 ≤1 |
| reality-balance | 否 | `.realityServers` 后端 >1，提示暂不支持 |
| tls（managed Nginx） | 是 | `00-xray.conf` 无 `stream {`，公网端口取 `listen`，域名取 `server_name` |
| none（纯传输） | 是 | 无 Nginx、无 reality/tls |
| relay | 是（仅 relay 分支） | 存在 `relay-stream.conf`；节点编辑入口直接拒绝并提示用 relay 参数 |
| direct TLS（无 managed Nginx） | 否 | `security=tls` 且无 `00-xray.conf`，提示重装为 `--mode tls` |

TLS 模式下 Xray 回环 inbound 使用传输端口池（G10），Nginx 独占公网端口，
因此编辑后重启不会 `EADDRINUSE`；分享链接仍使用公网端口。

## 9. 脚本化映射（非交互）

| 目标 | 推荐调用 |
|---|---|
| 改端口（确认断线） | `xray config edit --port 8443 --yes --container --json` |
| 只预览 | `xray config edit --uuid <uuid> --dry-run --json` |
| 维护窗口只落盘 | `xray config edit --transport ws --ws-path /x --no-restart --container` |
| 改 Reality 回源 | `xray config edit --target www.example.com:443 --container` |
| 改 serverNames | `xray config edit --server-names a.com,b.com --container` |
| 改 relay 目标 | `xray config edit --relay-target 1.2.3.4:443 --yes --container --json` |
| 非默认配置 | 追加 `--path /path/to/config.json` |

退出码：`0` 成功或 no-op；`1` 交互取消；`2` 用法/拒绝（冲突、缺 `--yes`、
非法组合）；其他非零为自检或执行失败（已回滚时错误信息注明 restored）。

## 10. 实现映射

| 文件 | 职责 |
|---|---|
| `internal/xraycfg/edit.go` | `EditRequest` / `EditResult` / `EditRuntime`；spec 还原、patch、diff 白名单 |
| `internal/xraycfg/xraycfg.go` | `Spec.SkipPortProbe`；TLS 回环端口；端口池与探测 |
| `internal/deploy/edit.go` | `EditConfig` / `EditRelay`；`editBase`、自检、备份、快照、回滚、元数据更新 |
| `internal/cli/xrayedit.go` | 参数映射、预览/报告输出、确认交互、relay 分支 |
| `internal/cli/xray.go`、`flags.go` | `config edit` 分发与 flag 白名单 |
| `internal/deploy/deploy.go` | `service` / `waitActive` seam，供测试注入失败 |
| `tests/e2e-diff/matrix.json` | E1 / E2 场景定义 |
| `tests/e2e-diff/drivers/go_edit.sh` | 改前/改后取证、一次性重启失败注入 |
| `tests/e2e-diff/run_p2_matrix.sh` | 编辑场景调度（安装 → L4 before → edit → L4 after） |
| `tests/e2e-diff/compare/report.py` | “配置编辑场景”表渲染 |

## 11. 验收

### 11.1 单测

- `internal/xraycfg/edit_test.go`：UUID 保留其他值、只改端口、传输重建、target/serverNames、
  未知顶层拒绝、多用户 UUID 拒绝、Nginx 前置 `--listen` 拒绝、空请求 no-op。
- `internal/deploy/edit_test.go`：成功写入 + 备份、自检失败不落盘、重启失败回滚
  （回滚重启成功）、成功重启、dry-run、relay 配置解析。

### 11.2 P2 矩阵（`tests/e2e-diff/matrix.json` → `edits`）

| 场景 | 方法 | 检查项 | 结果 |
|---|---|---|---|
| E1 `config-edit-before-after` | M1 安装 → 取证 → `config edit --uuid ... --yes --container --json` → L4 | editRcZero / configChanged / uuidApplied / shareUriUpdated / serviceActive / backupExists | PASS（`evidence/step3-edit2/p2/install-matrix.md`） |
| E2 `config-edit-restart-rollback` | 注入一次性 Xray 重启失败 → `config edit --port 8443 --yes --container --json` → 期望失败并回滚 | editRcNonZero / rollbackReported / configRestored / serviceActive | PASS（同上） |

E1/E2 的 L4 改前/改后均 ok；报告新增“配置编辑场景（xray config edit，Go）”表。

### 11.3 手工验证（步骤3）

- reality：改端口、改 UUID 成功，备份、元数据、share 同步；dry-run 不写盘。
- `--rewrite-config` → rc=2；非 TTY 无 `--yes` → rc=2。
- fail-once 注入：重启失败后 config SHA 还原、服务 active、错误含 restored。
- reality-nginx：UUID 编辑后 `nginxUpdated/Verified` 为真且 L4 通过。
- TLS：安装、重启、编辑、L4 均通过。

## 12. 已知限制与后续梯队

第二梯队（未实现）：
1. Reality 握手参数（publicKey / shortId / fingerprint / spiderX）。
2. Nginx `serverNames`、负载均衡后端增删。
3. 证书路径/域名（不含自动签发）。

已实现（2026-11-15，第二梯队 S1）：target / serverNames 改动后的**主动回源探测**。
编辑时先做 TCP connect，有 serverNames 时再按系统根证书校验证书链与 hostname（
不额外查 OCSP、不锁 TLS 版本，严格程度与 Reality 的真实要求等价），不可达或链/SNI
不匹配直接拒绝保存（rc=2、零落盘），不再依赖事后看日志或备份恢复。

第三梯队（未实现）：TLS 版本、SNI Guard、证书自动更新开关、流量统计开关。

不支持：`reality-balance`（多后端）、direct TLS、同一安装内多用户 UUID 单点修改。

## 13. 相对 bash 的增益

- 局部补丁，不必重述全部安装参数，也不会丢配置。
- 自检前置：`xray -test` / `nginx -t` 失败零落盘（bash 只在 Nginx 场景有 `nginx -t`）。
- 重启失败自动回滚，并留下可手工恢复的备份目录。
- 全参数可脚本化，`--dry-run --json` 可接入自动化；交互只用于断线确认。
- 改完自动输出新分享链接，不需要手工重跑菜单。
- relay 与节点共用同一编辑入口，bash 需要分别进入不同菜单。
