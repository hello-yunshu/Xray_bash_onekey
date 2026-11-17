# C2 规格：流量阻断（Xray 路由层，ED-003）

状态：**待审批**。本文只写方案，不含实现代码。
前置修正：ED-003 已从 `nftables/iptables ruleset` 改回事实（L2 配置语义，四个 Xray 配置面）。
审批通过后才进入实现；OPS-21 的 `verdict` 在证据实跑通过前保持 `go-missing`。

## 0. 结论摘要

1. C2 只做 **Xray 路由层阻断**，不写 nftables/iptables；内核层封源 IP 归 C1 fail2ban。
2. 与 bash 对齐的目标类型：广告、私有网段、BT、指定国家码；自定义域名/IP 列表作为 Go 增量**纳入**，独立存储、独立启停、单条增删。
3. geo 数据复用现有 `idleleo schedule` 的 `geodata-refresh` job，不新建 timer；缺文件时**拒绝应用**，不降级。D6 已拍板：下载必须校验 sha256（含 `geodataJob`）。
4. 阻断规则与用户手写 routing 规则**合并**，不整段重建；`config edit` 后规则保留。
5. 验证必须同时有正例与对照：阻断项断开的同时，`example.com` 仍要通；再加一条“最后一条规则不是 blocked”的结构断言，防兜底假通过。
6. 显式 `--yes`、写前 `xray -test`（带 geo 资产环境）、重启后控制请求探测失败即回滚。

## 1. 范围界定

### 1.1 只做路由层

bash 的 `scripts/traffic_blocker.sh` 只改三个位置，然后重启 Xray：

| 位置 | 代码 | 写入内容 |
|---|---|---|
| `routing.rules` | `tb_build_block_rules` / `tb_apply_rules` | 若干 `{"type":"field","outboundTag":"blocked",...}` + 一条 direct |
| `routing.domainStrategy` | `tb_apply_rules` | 有国家码或私有网段时写 `IPIfNonMatch`，并保存/恢复旧值 |
| `inbounds[].sniffing` | `tb_apply_rules` | `{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}`，并保存/恢复旧值 |

证据：`scripts/traffic_blocker.sh` 全文 grep `nft|iptables|ip6tables|firewalld|ufw` **零匹配**。
bash 没有任何内核层阻断。

### 1.2 内核层归 C1

- bash：`scripts/fail2ban_manager.sh` 的 jail 只写 `enabled/filter/port/logpath/bantime/maxretry/findtime/backend`，不写 `banaction`。
- Go：`internal/deploy/fail2ban.go` 同样不写 `banaction`。
- 两侧都使用 fail2ban 发行版默认 backend（nftables/iptables multiport），即封源 IP 的能力在 C1。
- 结论：C2 不调用 `nft`/`iptables`，也不接受“顺手加一条防火墙规则”的需求；接口里不出现防火墙参数。

### 1.3 非目标

- 不做 DNS 层拦截（域名仍会被解析，只是出站连接被拒绝）。
- 不做按用户/入站的差异化阻断（bash 没有；入站只用来生成 direct 规则的 inboundTag 列表）。
- 不接管 C1 的封禁、解封、白名单。

## 2. 可阻断的目标类型

| 类型 | bash 是否有 | C2 | 生成规则 | geo 依赖 |
|---|---|---|---|---|
| 广告域名 | 有 | 对齐 | `{"type":"field","outboundTag":"blocked","domain":["geosite:category-ads-all"]}` | geosite.dat |
| 私有网段 | 有 | 对齐 | `{"type":"field","outboundTag":"blocked","ip":["geoip:private"]}` | geoip.dat |
| BT 协议 | 有 | 对齐 | `{"type":"field","outboundTag":"blocked","protocol":["bittorrent"]}` | 无 |
| 指定国家码 | 有 | 对齐 | 每国一条 `domain:["geosite:<cc>"]` + 一条 `ip:["geoip:<cc>"]` | geosite.dat + geoip.dat |
| 自定义域名列表 | **无** | Go 增量（已纳入） | `domain:["domain:foo","full:bar"]` 或纯 `foo` 后缀 | 无 |
| 自定义 IP/CIDR 列表 | **无** | Go 增量（已纳入） | `ip:["1.2.3.4","10.0.0.0/8"]` | 无 |

规则顺序严格照 bash，保证 OPS-21 的 L2 对拍不产生顺序噪音：

1. 国家码：按配置顺序，先全部 domain 规则，再全部 ip 规则
2. BT
3. 广告
4. 私有网段
5. 用户原有规则（保持相对顺序）
6. 默认 direct 规则

自定义列表（若启用）插在“私有网段”之后、“用户原有规则”之前。

## 3. 状态与持久化

复用 bash 的 `/etc/idleleo/conf/xray/traffic_blocker.json`，不另造状态文件：

```json
{
  "country_block": ["cn"],
  "bittorrent": true,
  "private_ip": true,
  "ads": true,
  "custom_domains": {"enabled": false, "items": []},
  "custom_ips": {"enabled": false, "items": []},
  "owned_rules": [],
  "previous_domain_strategy": "AsIs",
  "previous_sniffing": [{"tag": "vless-ws", "sniffing": null}]
}
```

- 前四个键与 bash 完全同义，bash 菜单与 Go CLI 可互相接管。
- 自定义列表与内置四类**分开存储**：`custom_domains`/`custom_ips` 各自有 `enabled` 与 `items`，清空或停用其中一类不会触碰 `ads`/`private_ip`/`bittorrent`/`country_block`。
- 自定义列表**单条增删**：`custom add/remove --value` 只改动目标条目，不要求调用方每次传全量列表；写盘仍是原子整文件替换，但语义是单条操作，重复值幂等。
- `owned_rules` 是 Go 新增键：记录上一次由 C2 写入的完整规则数组，用于精确删除，避免误删用户自己的 blocked 规则。bash 的 jq 操作只增删已知键，不会破坏它。
- `previous_*` 沿用 bash 语义：只在第一次写入时保存，恢复后删除。
- 读取时保留未知键（用 `map[string]any` 合并，不做结构体严格反序列化后回写）。
- 不写 metadata：`traffic_blocker.json` 是唯一事实源，`config edit` 直接读它。

## 4. 规则生成与合并

新增 `internal/xraycfg/block.go`（纯函数，便于单测）：

```go
type RoutingBlock struct {
    Countries      []string
    BitTorrent     bool
    Ads            bool
    PrivateIP      bool
    CustomDomains  []string // 可选
    CustomIPs      []string // 可选
}

type BlockState struct {
    Block           RoutingBlock
    OwnedRules      []any
    PrevDomainStrat string
    PrevSniffing    []inboundSniffing
}

func BuildBlockRules(b RoutingBlock) ([]any, error)
func ApplyRoutingBlock(cfg []byte, st BlockState) (out []byte, applied BlockState, err error)
func RemoveRoutingBlock(cfg []byte, st BlockState) (out []byte, restored BlockState, err error)
```

`ApplyRoutingBlock` 的合并算法：

1. 校验 `.outbounds` 同时存在 `blocked` 与 `direct`，否则拒绝（照 bash 的前置检查）。
2. 从 `.inbounds[].tag` 取 inboundTag 列表；为空则拒绝（照 bash）。
3. 把现有 `.routing.rules` 中与 `OwnedRules` **深度相等**的规则删掉，其余原样保留（用户规则）。
4. 新规则 = `BuildBlockRules` + 用户规则 + 默认 direct（仅当用户规则里没有“无条件的 direct 兜底”时才补，避免重复）。
5. 写回 `.routing.rules`，并更新 `OwnedRules` 为本次生成的阻断规则数组。
6. `domainStrategy`：有国家码或私有网段时设为 `IPIfNonMatch`，首次保存旧值；关闭这些类型时，若当前值仍是 `IPIfNonMatch` 且存在保存值，则恢复。
7. `sniffing`：BT/国家码/广告任一启用时，对所有 inbound 写 bash 同构的 sniffing；首次保存每个 inbound 的原值；全部关闭时按 tag 恢复原值。

硬约束（防“blocked 兜底”）：

- 每条 `outboundTag:"blocked"` 规则必须至少有一个选择器（`domain`/`ip`/`protocol`/`port`/`network`），空选择器直接报错，不写盘。
- 生成的最后一条规则必须是 direct；若用户规则里最后一条是无条件 blocked，`ApplyRoutingBlock` 拒绝并提示先清理。
- 单元测试断言：不存在 `{"type":"field","outboundTag":"blocked"}` 这种无选择器规则。

幂等：

- 同样的 `BlockState` 连续应用两次，`routing.rules` 字节一致，不产生重复规则。
- 国家码列表按传入顺序渲染；空值/重复/非两位字母直接报错，不做静默过滤。

## 5. 与现有配置的关系

### 5.1 不覆盖用户 routing

- 只删与 `OwnedRules` 深度相等的规则；用户手写规则逐条保留，顺序不变。
- 阻断规则放在最前，因此用户规则不能覆盖阻断（这是“阻断”的语义），文档写明。
- 默认 direct 规则只在缺失时补，不重排用户已有的兜底规则。

### 5.2 `config edit` 之后仍然存在

现状：`xraycfg.EditRuntime` 用同一生成器重建配置，再用 `diffRuntime` 白名单拒绝任何未请求的变化。
阻断规则会让 `routing.rules` 出现未请求差异，因此必须扩展：

- `internal/xraycfg/edit.go`
  - `EditDefaults` 增加 `RoutingBlock *BlockState`；`Spec` 增加同名字段。
  - `EditRuntime` 在 `Generate` 后调用 `ApplyRoutingBlock(g.Config, *base.RoutingBlock)`；同时把 live config 中非 owned 的用户规则按 §4 的算法合入。
  - `editScope`：仅当 `RoutingBlock != nil` 时放行 `routing.rules`、`routing.domainStrategy`、`inbounds.*.sniffing` 的差异；否则维持现状（拒绝）。
- `internal/deploy/edit.go`
  - 进入编辑前读取 `traffic_blocker.json`，构造 `BlockState` 传入 `EditDefaults`。
  - `EditReport` 增加 `BlockPreserved bool`、`BlockRuleCount int`，便于取证。
- 结果：`config edit --uuid` 只改 UUID；阻断规则与用户规则逐条保留。单测覆盖。

### 5.3 重装

- 默认 `--keep-config`（现有行为）：运行配置不动，阻断规则天然保留；重装末尾重新断言 geo 文件、asset 环境 drop-in 与状态文件一致性。
- `--rewrite-config`：按生成器重建，再用 `traffic_blocker.json` 重新应用阻断；用户手写 routing 规则按现有契约丢弃，输出中明确警告。
- 漂移检测：`block status` 比对 live `routing.rules` 与 `OwnedRules`；不一致时报告 `drift=true`，并提示重新 `block apply`，不自动改。

### 5.4 卸载

- 删除 `traffic_blocker.json` 与 C2 自己创建的 unit drop-in；运行配置随卸载删除，无需单独恢复。

### 5.5 bash → Go 迁移

bash 没有 `owned_rules`。首次在 Go 侧 apply 时：

- 用已知形态识别“疑似 bash 写入”的 blocked 规则（`geosite:category-ads-all`、`geoip:private`、`geosite:<cc>`、`geoip:<cc>`、`protocol:["bittorrent"]`），从旧集合中移除后再重建。
- 形态不匹配的 blocked 规则一律当作用户规则保留。
- 该迁移只做一次，随后 `owned_rules` 接管。

### 5.6 CLI 形态

状态修改与流量变更分开：所有 `enable/disable/add/remove` 只改状态文件，不重启；只有 `apply`/`off` 会写配置并重启。

```
idleleo xray block status [--json]
idleleo xray block apply [--yes] [--dry-run] [--json]
idleleo xray block off [--yes] [--json]
idleleo xray block ads enable|disable
idleleo xray block private-ip enable|disable
idleleo xray block bittorrent enable|disable
idleleo xray block country add <cc[,cc...]> | remove <cc[,cc...]> | list
idleleo xray block custom add --kind domain|ip --value <v> [--value <v>]
idleleo xray block custom remove --kind domain|ip --value <v> [--value <v>]
idleleo xray block custom enable|disable --kind domain|ip
idleleo xray block custom list [--kind domain|ip] [--json]
```

- `custom add/remove` 是单条操作；`--value` 可重复，重复项幂等，不要求传全量。
- `custom enable/disable` 只切换 `custom_domains.enabled` 或 `custom_ips.enabled`，不影响内置四类。
- `apply` 从状态文件重建规则；`off` 只删 `owned_rules` 并恢复 `domainStrategy`/`sniffing`。
- 所有状态写入原子替换且保留未知键。

## 6. geo 数据依赖

### 6.1 来源与位置

- 来源与 bash 相同：`https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/{geoip.dat,geosite.dat}`。
- 位置：`/etc/idleleo/share/xray`（`internal/schedule` 的 `GeodataDirRel`）。
- 现有链路：`idleleo schedule install` 的 `geodata-refresh` job 下载两个文件，原子写入，成功后在主机根下重启 Xray（`internal/schedule/schedule.go:886`）。C2 不新增 timer。

### 6.2 缺失时拒绝，不降级

- 只对真正需要的文件做检查：广告/国家码需要 `geosite.dat`；私有网段/国家码需要 `geoip.dat`；BT 不需要。
- 缺失时先尝试一次下载（120s 超时、单文件 64 MiB 上限、原子写入 0644）。
- 下载失败或文件不可读 → **rc=2，零写盘、不重启**，消息指出缺哪个文件、来源 URL、以及 `idleleo schedule install` 可开启自动刷新。
- 不允许“规则写一半”或“跳过缺 geo 的规则但报告已启用”。

### 6.3 Xray 如何找到文件

当前 Go 的 unit（`internal/deploy/deploy.go` 的 `unitContent`）没有 `XRAY_LOCATION_ASSET`，Xray 可能找不到 `/etc/idleleo/share/xray`。
Bash 的做法是把默认资产目录软链到 `/etc/idleleo/share/xray`。C2 采用更小侵入的方案：

- 写 drop-in：`/etc/systemd/system/xray.service.d/50-xray-geodata.conf`
  ```
  [Service]
  Environment=XRAY_LOCATION_ASSET=/etc/idleleo/share/xray
  ```
- 写前检查主 unit 与其他 drop-in 是否已设置该变量：
  - 已设置且指向正确目录 → 不写，复用。
  - 已设置但指向别处且那里没有所需 `.dat` → 拒绝并列出冲突文件。
  - 未设置 → 原子写 drop-in + `systemctl daemon-reload`。
- 所有 `xray -test` 调用点带上同样的环境变量：
  - `internal/runtime/runtime.go` 的 `XrayValidator.Validate`
  - `internal/deploy/edit.go` 的 `runXrayTest`
  - `internal/deploy/deploy.go` 安装期 `-test` 调用
  - 实现方式：给 `host.ExecSpec` 增加 `Env []string`，`host.Run` 透传；不影响现有调用。
- `block off` 时，只有 drop-in 是 C2 创建且没有任何阻断规则剩余时才删除它。

### 6.4 更新与校验

- 自动更新：走现有 `geodata-refresh`；它已经会重启 Xray，规则随新数据生效。
- 手动更新：同一 job 的 CLI（现有 `idleleo schedule` 路径），不新增 OPS-24 入口。
- `block status` 输出两个文件的 mtime/size，超过 30 天给 warning（不阻断）。
- 校验（D6 已拍板）：bash 的 `geo_update.sh` 下载后校验 release 的 `.sha256sum`，Go 的 `geodata-refresh` 也必须补上，不得继续使用未校验数据。
  - `internal/schedule/schedule.go` 的 `geodataJob`：下载 `geoip.dat`/`geosite.dat` 后拉取对应 `.sha256sum`，校验通过才原子替换；失败保留旧文件、job 记 `failed`、不重启。
  - C2 的一次性下载走同一校验逻辑，避免两份实现漂移。

## 7. 验证方式

### 7.1 结构断言（先跑，成本低）

1. `xray -test`（带 `XRAY_LOCATION_ASSET`）通过。
2. 每条 blocked 规则都有选择器；最后一条规则是 direct。
3. 同样输入连续 apply 两次，`routing.rules` 字节一致。
4. `domainStrategy`、`sniffing` 的保存/恢复符合 §4。

### 7.2 正向 + 对照（OPS-21 E2E）

新增 `tests/e2e-diff/drivers/ops21_block.sh`，两侧都跑；Go 侧 argv 在实现并通过后写入 `matrix.json`。

| # | 动作 | 期望 |
|---|---|---|
| 1 | 基线：经代理请求 `http://example.com` | 200 且正文含 `Example Domain` |
| 2 | 启用广告 + 私有网段 + 国家码 `cn` + BT | apply rc=0 |
| 3 | **对照**：再请求 `http://example.com` | 仍 200 且含 `Example Domain`（防 blocked 兜底） |
| 4 | 广告域名（`category-ads-all` 内） | 连接被拒；不是 5s 超时（用耗时上界判定） |
| 5 | 私有地址（测试网 origin 的 10/8 地址） | 连接被拒，origin 未收到字节 |
| 6 | `geoip:cn` 地址（如 `223.5.5.5:443`） | 快速被拒（<2s），不依赖 DNS |
| 7 | BT：经 SOCKS 向本地 origin 发 19 字节 BitTorrent 握手 | origin 收到 0 字节；同样目标发普通字节则能收到（对照） |
| 8 | `block off` | 私有地址重新可达；`domainStrategy`/`sniffing` 恢复；`xray -test` 通过 |
| 9 | 阻断生效时执行 `config edit --uuid` | 规则与用户规则逐条保留；`example.com` 仍通；私有地址仍被拒 |
| 10 | 移走 `geosite.dat` 后启用广告 | rc=2，配置哈希不变，服务未重启 |

关键：第 4–6 步不能只判“失败”。要区分“被 blocked 快速拒绝”与“网络不通超时”，用耗时上界 + origin 未收到连接作为证据。

### 7.3 失败注入

- 重启后控制请求失败（模拟规则写坏或资产目录错误）→ 自动回滚配置 + 重启，`failurePoint=block-control-probe`，随后控制请求必须恢复。
- 写盘前 `xray -test` 失败 → 零写盘、不重启。
- 用户规则里存在无条件 blocked → 拒绝 apply，零写盘。

### 7.4 对拍

- OPS-21 在两侧都跑同一组开关，采集 `config.json` 的 `routing.rules`、`routing.domainStrategy`、`inbounds[].sniffing`。
- 归一化只去掉端口/UUID 等易变值；规则数组顺序参与比较（§2 已对齐 bash 顺序）。
- 证据目录沿用 `tests/e2e-diff/evidence/<run-id>/p2/OPS-21/{bash,go}/`。

## 8. 安全闸

1. **显式确认**：`apply` 与 `off` 都要 `--yes`；非交互缺 `--yes` → rc=2，零写盘。
2. **预览**：`--dry-run` 打印将要写入的规则数、`domainStrategy`/`sniffing` 变化、以及“这些对照必须仍然通”。
3. **写前校验**：`xray -test`（含 geo 环境）失败即停止，零写盘。
4. **结构校验**：无选择器规则、缺失 `blocked`/`direct`、无 inboundTag、最后一条为 blocked → 全部拒绝。
5. **重启后探测**：服务 active 后经代理请求 `http://example.com`，必须 200 且含 `Example Domain`；失败即回滚配置并重启，报告失败点。这直接挡住“误把默认出站也拦了”。
6. **备份**：`/etc/idleleo/backup/block-<ts>/` 保存 `config.json`、`traffic_blocker.json`、drop-in 副本；回滚成功后保留备份供人工核对。
7. **私有网段预检**：启用 `private_ip` 时，扫描 `direct` 出站会命中的任何回环/私网目标（例如用户把上游写成 `127.0.0.1`），命中则 warning 并列出，避免把控制链路自己断掉。
8. **重启窗口**：apply/off 都会重启 Xray（秒级断线），输出中明示；不假装热加载。
9. **DNS 说明**：阻断不阻止 DNS 解析，只阻止出站连接；状态输出中写明。

## 9. 实现拆分（审批后执行）

**顺序门槛：第 0 步不做完且断言不过，其余功能一律不算落地。**

0. **BlockState 贯穿 `EditRuntime`（先做）**
   - `internal/xraycfg/block.go`：最小规则构建/合并/恢复。
   - `internal/deploy/block.go`：状态读写 + apply。
   - `internal/xraycfg/edit.go`、`internal/deploy/edit.go`：`BlockState` 贯穿，`config edit` 保留规则。
   - 回归断言（单测 + E2E）：装阻断 → `config edit --uuid` → `owned_rules` 逐条深度相等、用户手写规则仍在、`example.com` 仍通。
1. `internal/xraycfg/block.go` + `block_test.go`：完整规则生成、自定义列表、结构断言、幂等。
2. `internal/deploy/block.go` + `block_test.go`：geo 检查/下载、asset drop-in、备份/回滚、控制探测。
3. `internal/host/exec.go`：`ExecSpec.Env`；`internal/runtime/runtime.go`、`internal/deploy/deploy.go`、`internal/deploy/edit.go` 的 `xray -test` 带 geo 环境。
4. `internal/schedule/schedule.go`：`geodataJob` 补 sha256 校验。
5. `internal/cli/xrayblock.go` + `flags.go`：§5.6 的 CLI。
6. `tests/e2e-diff/drivers/ops21_block.sh` + bash 菜单驱动；`matrix.json` 在证据通过后把 OPS-21 改为 `must-match` 并填 Go argv。
7. 文档：`behavior-diff.md` 记录自定义列表（Go 增量）与 geo 校验；`tasks.md` 勾 C2。
8. `expected_diffs.json`：实现并取证后删除 ED-003。

## 10. 已拍板

| 编号 | 事项 | 决定 |
|---|---|---|
| D1 | 只做路由层，不碰内核 | 采纳 |
| D2 | 复用 `traffic_blocker.json` 作为唯一状态 | 采纳 |
| D3 | bash → Go 首次迁移按已知规则形态去重 | 采纳 |
| D4 | 用户 routing 规则用“精确 owned 删除 + 保留其余”合并 | 采纳 |
| D5 | 自定义域名/IP 列表 | **纳入**：独立存储、独立启停、单条增删 |
| D6 | geo sha256 校验 | **纳入**：`geodataJob` 与 C2 下载都校验 |
| D7 | `apply/off` 均重启 Xray，不尝试热加载 | 采纳 |
| 顺序 | BlockState 贯穿 `EditRuntime` 先做 | **门槛**：回归断言通过前其余不算落地 |

审批已通过。按 §9 顺序实现，第 0 步的断言先跑通，再继续其余功能。
