# C5 规格：多用户 UUID 单改

状态：**待审批**。本文只写方案，不含实现代码。
前置：C2 已收口（`config edit` 保留阻断规则有回归断言）。C5 与 C2 共用同一批写盘事务与备份目录。
审批通过后才进入实现；`tasks.md` 的 C5 条目在证据跑通前保持未勾。

## 0. 结论摘要

1. **两件事分开**：`config edit --uuid` 是“整机凭证重签”（一个 UUID 覆盖所有 inbound），`xray user uuid` 是“单用户换凭证”（只碰一个 client）。多用户配置下前者继续拒绝，且报错文案改为指向后者。
2. **定位以 email 为准**，当前 UUID 作为别名；**不接受索引**（remove 后索引会漂移）。定位失败或命中不唯一一律 rc=2、零写盘。
3. **不重启做不到**：Xray 不读配置热重载，现有 `change.Apply` 提交后必须重启进程。因此**断线面是所有会话的秒级中断**，凭证失效面只有目标用户。这一点不粉饰，输出里明说。
4. **不动 email/flow/level/shortId/路由**：统计归属与路由按 email 匹配，保留 email 就保留归属；shortId 是 inbound 级凭证，不归 C5。
5. **回滚按用户回改**，不提供整文件还原（整文件回滚会覆盖其他人后来的改动）。旧 UUID 在正向命令输出、journal 与备份清单里都能拿到。
6. 验证必须成对：目标用户旧链接**必须断**、新链接**必须通**、其他用户链接**必须不受影响**、路由与 C2 阻断规则**必须逐字节不变**。

## 1. 现状事实

| 事实 | 证据 |
|---|---|
| `xray user` 只有 `list/add/remove`，没有改 UUID 的动作 | `internal/cli/xray.go` 的 `user` 分支（L304-L410） |
| add/remove 走 `App.ChangeUser` → `change.Apply`，带 `XrayValidator`、`CommandService`、`Journal`、`LockPath`、`Finalize: refreshRuntimeSHA` | `internal/app/app.go` `ChangeUser`（L216-L267） |
| 提交后由 service 重启 Xray，失败自动回滚 | 同上；`internal/change` 的 Apply 契约 |
| `config edit --uuid` 只在“各 inbound 的 `clients[0].id` 相同”时放行 | `internal/xraycfg/edit.go` `EditRuntime`（L124-L136）、`editSpecFromRuntime`（L699-L708） |
| 同一 inbound 有第二个用户时，单 UUID 重生成会被 diff 白名单拒绝 | `internal/xraycfg/edit_test.go` `TestEditRefusesMultiUserUUID` |
| UUID 编辑的作用域只放行 `clients[0].id/email` | `editScopeFor`（L342-L349） |
| 分享链接不落盘，按需从运行配置渲染，支持按 email/UUID 选人，命中不唯一时拒绝 | `internal/xraycfg/share.go` `ShareConfig`/`selectClient`（L58-L234） |
| 用户增删的“只改 clients”断言已有现成实现 | `internal/xraycfg/users.go` `assertOnlyUsersChanged`（L209-L228） |
| Go 安装不生成 `stats`/`policy`，`stats` 命令依赖配置里的 `api` inbound | `internal/xraycfg` 无 `stats`/`policy` 生成；`internal/cli/stats.go`、`internal/schedule/schedule.go` 的 `apiListen` |
| `user add/remove` 额外要求 `--sandbox`，与 `config edit` 不一致 | `internal/cli/xray.go` L327-L334 |

## 2. 职责边界（可改 / 不可改）

| | `config edit --uuid` | `xray user uuid`（新增） |
|---|---|---|
| 语义 | 整机凭证重签 | 单用户换凭证 |
| 作用对象 | 每个 inbound 的 `clients[0].id` | 命中的一个或多个 inbound 里的**同一个用户** |
| 实现方式 | 走 Generator 重建 + diff 白名单 | clone → 只改 `clients[i].id` → 只改客户的断言 |
| 多用户配置 | 拒绝（保持现状，文案指向新命令） | 支持 |
| 是否动其他字段 | 可能重算 email 归一化 | 只动 `id` |
| 断线面 | 重启 | 重启 |

硬规则：

- `xray user uuid` **不得**调用 `Generate`、**不得**改 `streamSettings`、**不得**改 `shortIds`，也不得改 `email/flow/level`。
- 单用户命令不负责 shortId 轮换；那是 inbound 级凭证，仍由 `config edit --short-id-*` 负责。输出中写明这个边界，避免运维以为“换了 UUID 就换了全部凭证”。
- `config edit --uuid` 在多用户配置下的报错文案从 `inbounds use different UUIDs; edit users with ...` 改为明确指引：`this install has N>1 users; use 'idleleo xray user uuid'`。

## 3. 目标用户定位

### 3.1 选择器

- **email 是规范选择器**：它是运维可见、路由 `user` 字段与统计键使用的值。
- 当前 UUID 作为别名（`--uuid` 传旧值），兼容手里只有链接的场景。
- **不接受索引**。理由：`remove` 会让索引前移，脚本里缓存的索引会指向别人；这类误改的代价是给别人换了凭证。
- 单次只允许一个选择器；同时给 `--email` 与 `--uuid` 且指向不同用户 → rc=2。

### 3.2 命中多个 inbound

同一用户通常同时出现在 ws / grpc / xhttp 等多个 inbound（同 email、同 UUID）。

- 默认：**所有命中的 inbound 一起改**，否则该用户某个传输会留在旧凭证上，表现为“部分能用”。
- `--inbound N` 可收窄，输出里逐条列出“这些 inbound 仍保留旧 UUID”。收窄是明确的脚枪，不做静默默认；没有额外的确认参数，重启警告本身就是唯一的拦截信息。

### 3.3 定位失败

| 情况 | 行为 |
|---|---|
| 选择器为空 | rc=2，打印用法 |
| 没有命中 | rc=2，列出该配置里所有 email + 索引 + 是否 primary |
| 命中多个 client（手写配置里 email 重复） | rc=2，要求改用 `--uuid` 或显式 `--inbound` |
| `--inbound` 越界 | rc=2，列出合法范围 |
| 新 UUID 与目标当前值相同 | rc=0，`noChanges=true`，不写盘不重启 |
| 新 UUID 与其他任何客户端重复 | rc=2，指出重复位置（inbound/索引/email） |
| 新 UUID 不是 RFC4122 | rc=2 |

所有拒绝都发生在写盘前，且不产生 journal 记录。

### 3.4 primary 用户

- 允许改（index 0）。理由：主凭证泄漏时必须能单独换，不能逼着重装。
- 但输出要提示：这是安装器创建的 primary，`config edit --uuid` 之后仍会把它当默认值；两者不要在同一次运维里混用。

## 4. 影响面

| 面 | 是否受影响 | 依据与要求 |
|---|---|---|
| 该用户的分享链接 | **变** | 链接从运行配置按需渲染（`ShareConfig` + `selectClient`），不落盘。只有目标用户的链接换 UUID；已导出的旧链接副本自然是失效的，输出提示“需重新分发”。 |
| 其他用户的分享链接 | 不变 | 其他 client 的 `id/email/flow` 逐字节不变，断言覆盖。 |
| 流量统计归属 | 不变（前提：email 不动） | Xray 统计键是 `user>>>email>>>...`；C5 明令不改 email。**注意**：Go 安装当前不生成 `stats`/`policy`，也不生成 `api` inbound，所以“按用户统计”本来就不是现成能力；这里只保证不破坏将来接入后的归属键。 |
| 并发限制 / level | 不变 | 限制挂在 `level`/policy 上，与 UUID 无关；C5 不改 `level`。当前 Go 安装同样未生成 policy，属于既有限制。 |
| 路由里按 email 匹配的规则 | 不变 | Xray 的 `user` 选择器匹配 email；email 不动即不受影响。 |
| C2 阻断规则 / 用户 routing | 不变 | 不触碰 `routing`，用逐字节比对断言。 |
| shortId / Reality 私钥 | 不变 | inbound 级凭证，C5 明确不碰。 |
| 监听、端口、传输 | 不变 | 不触碰 `inbounds[].port/listen/streamSettings`。 |
| 重装 / `config edit` | 兼容 | `config edit` 对多用户配置继续拒绝；单用户安装仍可用老路径，两条路径不交叉。 |

若运维需要同时改 email 与 UUID，拆成两次操作：先改 UUID、验证，再单独做 email 变更（本期不提供 email 修改命令，写入边界）。

## 5. 断线影响面

结论：**做不到“只影响该用户”的传输层隔离，只能做到“凭证影响面只有该用户”**。

依据：

1. Xray 只在进程启动时读取配置文件，没有 SIGHUP 式配置重载；本项目 unit 也没有给 `systemctl reload` 定义可用的重载语义。
2. 现有 `user add/remove` 已经把 `runtime.CommandService` 交给 `change.Apply`，提交后就是重启。C5 复用同一事务，不会更温和。
3. 唯一的热更路径是 Xray gRPC API（`xray api adi/rmu` 等），它要求配置里存在 `api` inbound；本项目安装器不生成 `api` inbound（`internal/xraycfg` 无相关生成，`apiListen` 因此取不到地址）。要让热更可用，得新增 loopback API 监听、必要的 stats/policy，属于独立的安全面变更，不在 C5 范围内。

因此输出与文档都按事实写：

- **中断**：整个 Xray 实例重启，所有在线会话短暂断开（秒级）。
- **失效**：重启后只有目标用户的旧 UUID 被拒绝，其他用户用原链接可重连。
- 不承诺“零中断”，也不把重启包装成 reload。

## 6. 回滚

### 6.1 事务级

沿用 `change.Apply`：写前 `xray -test` 失败 → 零写盘；提交后服务起不来或控制探测失败 → 自动回滚配置并重启。C5 不新建事务机制。

### 6.2 单用户退还

- 正向命令输出 `previousUuid`，并写入 journal 条目与备份清单；运维照原样再执行一次即可退回：
  ```
  idleleo xray user uuid --email user-b@idleleo --new-uuid <old-uuid>
  ```
- **不提供整文件还原**：备份目录里的 `config.json` 只用于人工核对与灾难恢复；自动还原会把该用户改回旧值的同时，覆盖其他人后来的变更。
- 退还只影响目标用户，仍然是一次重启；断言与正向对称。
- 幂等：目标已经是旧值 → `noChanges=true`，不写盘不重启，避免重复重启。

### 6.3 备份

`/etc/idleleo/backup/user-uuid-<ts>/`：

- `config.json`：变更前快照（保留现有权限/属主，不因备份放宽）。
- `change.json`：`{ident, email, previousUuid, newUuid, inboundIndices, requestedBy, at}`。
- 按现有备份保留策略轮转，不新造目录结构。

## 7. 验证方式

### 7.1 单测（先跑，成本低）

1. 多用户 fixture（同一 inbound 两个 client）：改 B，断言 A 的 client 对象 `DeepEqual` 不变；B 只有 `id` 变；`email/flow/level` 不变；整份文档的差异路径恰好一个。
2. 跨 inbound 同 email：默认两个 inbound 一起改；`--inbound 0` 时只改一个并报告另一个仍是旧值。
3. 负例：不存在 → 报错且列出候选；email 重复 → 要求 `--uuid`；新 UUID 非法 → 报错；新 UUID 与他人重复 → 报错；同值 → `noChanges`。
4. 断言层复用 `assertOnlyUsersChanged`，并新增一条“除 `clients[*].id` 外零差异”的显式比对。

### 7.2 E2E（新增驱动，双用户对照）

在 `tests/e2e-diff/drivers/` 增加一个驱动（编号在 `matrix.json` 里登记，实现后填 Go argv）。沿用 OPS-21 的本地控制站 fixture，不依赖公网。

| # | 动作 | 期望 |
|---|---|---|
| 1 | 基线：userA 链接、userB 链接分别经代理请求控制站 | 两者都 200 且含 `Example Domain` |
| 2 | `xray user list` | 两个用户都在，B 非 primary |
| 3 | 改 userB UUID | rc=0；`previousUuid` 可读；服务重启一次（`NRestarts` 增量=1） |
| 4 | **该断**：userB 旧链接 | 被拒绝/连接关闭；用耗时上界区分“快速失败”与“网络超时”，并用 Xray 日志确认是认证失败 |
| 5 | **该通**：userB 新链接 | 200 且含 `Example Domain` |
| 6 | **不该断**：userA 原链接 | 200；与基线一致 |
| 7 | **不该变**：A 的 client 字段、`shortIds`、Reality 私钥、`port/listen` | 逐字节一致 |
| 8 | **不该变**：`routing.rules`（含 C2 `owned_rules`） | 与改 UUID 前逐条深度相等 |
| 9 | 回滚：改回旧 UUID | userB 旧链接恢复 200；userA 仍 200；A 的字段仍不变 |
| 10 | 失败注入：validator 失败 | rc≠0，配置哈希不变，未重启 |
| 11 | 失败注入：重启后控制探测失败 | 自动回滚，旧 UUID 恢复可用 |

第 4 步不能只判“失败”：必须是快速拒绝（毫秒级）而不是超时；同时 userA 在同一轮仍能 200，证明不是整体网络问题。

### 7.3 对拍

- bash 没有单用户 UUID 修改命令 → 这是 **Go 增量**，不产生 `expected_diffs.json` 条目。
- 在 `docs/plans/p2/behavior-diff.md` 记录：`xray user uuid` 为 Go-only；bash 侧等价操作是手改 `config.json` + 重启，无对拍价值。
- `matrix.json` 只登记新增的 E2E 用例（单侧 Go 运行），`verdict` 用现有的单侧语义，不冒充双端对拍。

## 8. 安全闸

1. **无额外确认参数**：`--yes` 不在白名单里，传了按未知参数拒绝（rc=2），不做“接受但不产生行为”的假确认；`--dry-run` 打印 email、旧→新 UUID、受影响的 inbound 索引、重启警告。
2. **写前校验**：`xray -test`（带 geo 资产环境）失败即停止，零写盘。
3. **定位唯一性**：命中不唯一、越界、未命中全部拒绝。
4. **凭证冲突**：新 UUID 与其他任何 client 重复即拒绝。
5. **只改一个叶子**：除 `clients[*].id` 外出现任何差异即拒绝提交（在事务内再校验一次）。
6. **重启后探测**：复用控制站探测；失败即回滚并报失败点。
7. **备份与 journal**：见 §6.3；旧 UUID 必须出现在输出、journal、备份清单三处，避免要靠日志考古。
8. **不冒充热更**：帮助文本与输出都写明“会重启、所有会话短暂中断”。
9. **参数门槛**：新动作要求 `--validator`、root 下要求 `--service`（与 `config edit` 一致）；是否顺带去掉 `user add/remove` 的 `--sandbox` 硬要求，见 §9。

## 9. 实现拆分（审批后执行）

1. `internal/xraycfg/users.go`
   - `UpdateUserUUID(raw []byte, inboundIndex int, ident, newUUID string) ([]byte, UserView, UserView, error)`，复用 clone + `assertOnlyUsersChanged` 的手法；新增“只允许 `clients[*].id` 变化”的窄断言。
   - `FindUsers(raw, ident)`：返回全部命中（inbound 索引 + 用户），供多 inbound 默认全改。
2. `internal/app/app.go`
   - `ChangeUserUUID(ctx, override, inbound int, ident, newUUID, ...)`：与 `ChangeUser` 同构（`beginSystemChange` → 元数据基线 → `change.Apply` → `Finalize: refreshRuntimeSHA`），返回 `previous/next` 视图。
3. `internal/cli/xray.go` + `internal/cli/flags.go`
   - `idleleo xray user uuid --email|--uuid <old> --new-uuid <v> [--inbound N] [--dry-run] [--json] [--validator] [--service]`。
   - `config edit --uuid` 的多用户报错文案改指向新命令。
4. 单测：`internal/xraycfg/users_test.go`（§7.1）、`internal/app` 的事务级用例（失败注入）。
5. E2E：`tests/e2e-diff/drivers/` 新驱动 + `matrix.json` 登记；证据入 `tests/e2e-diff/evidence/<run-id>/p2/<case>/{go}/`。
6. 文档：`behavior-diff.md` 记 Go-only 增量；`tasks.md` 勾 C5 并贴证据路径。

## 10. 需要你拍板的点

| # | 事项 | 建议 |
|---|---|---|
| 1 | `config edit --uuid` 保留还是废弃 | **保留**（单用户安装仍用），多用户时显式报错并指向新命令；不做静默委托 |
| 2 | 选择器 | email 为准、UUID 为辅、**拒绝索引** |
| 3 | 同 email 命中多个 inbound | **默认全改**；`--inbound` 需显式，且输出列出仍留旧值的 inbound |
| 4 | 是否允许改 primary | **允许**（泄漏必须能单独换） |
| 5 | 是否本期做 Xray API 热更 | **不做**（要新增 `api` inbound，属独立安全面）；接受“秒级全实例重启” |
| 6 | 回滚形态 | **按用户回改 UUID**，不提供整文件自动还原 |
| 7 | 是否顺带统一 `user add/remove` 的 `--sandbox` 门槛 | 可选；建议只让新动作走 `--validator/--service`，旧动作另开一项清理 |
| 8 | email 修改命令是否同期做 | **不做**；先保证 UUID 单改的边界干净 |
