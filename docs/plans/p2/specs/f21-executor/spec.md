# F21 执行器规格：流量阻断与自定义屏蔽

状态：待批准（批准前不写测试、不跑正式两次容器、不提交）
证据等级：CONTAINER_VERIFIED（固定 digest 的 systemd 容器内真实执行 Go 二进制、
真实 `xray install`、真实 `systemctl restart xray`、真实 `xray -test`、真实 Bash 基线函数）
**明确不宣称完全 VERIFIED：没有真实 VPS；控制探针只做本机 TCP，未做被墙域名/IP 的真实
客户端数据面；Bash 只对比纯规则生成函数，未跑交互式菜单与真实下载流程。**
提交边界：执行器、证据、三处文档计数；`install.sh` 与 `scripts/traffic_blocker.sh` 不改；
不 push、不合并 main、不打 tag/release、不接触真实 VPS；夹具运行期不联网。

## 1. 目标

为 `feature_contracts.json` 的 F21（`流量阻断与自定义阻断`，P2）建立真实夹具
`tests/go-parity/parity/features/F21_test.py`，覆盖：

1. `idleleo xray block` 状态机的全部开关：ads / private-ip / bittorrent / country /
   custom domain / custom ip，以及每类 items 的聚合规则；
2. 首次 `apply` 的真实副作用：`routing.rules` 顺序与内容、`domainStrategy`、
   inbound `sniffing`（`routeOnly`）、backup、geodata systemd drop-in、真实重启与 TCP 控制探针；
3. 二次 `apply` 幂等（配置 sha 不变，`oldSha256==newSha256`，drop-in 复用）；
4. `status` 的配置态与漂移（`drift`）字段；
5. `off` 精确恢复安装时的配置（sha 回到安装值，`AsIs`，sniffing 为 null）；
6. 失败与回滚：缺失 `--yes`、dry-run、非法 country/IP/kind、无 geosite、
   用户最后一条规则吞掉全部流量、xray `-test` 拒绝；
7. 与固定 Bash 基线（`scripts/traffic_blocker.sh` 的 `tb_build_block_rules`）
   真实执行对比；Bash 规则迁移（legacy adoption）不产生重复；
8. 明确登记容器无法覆盖或不应伪造的缺口（真实数据面、Bash 交互流程、非 443 模式等）。

## 2. 已核实事实（2026-11-17 容器实测，非推测）

实测环境：`idleleo-realroot@sha256:d985e8ed154d5c3b13c097f5a1ece90ce434ae03cd5444e7753f334359429aa7`，
容器 PID 1 为真实 systemd（`systemctl is-system-running` = `running`），
Xray `26.11.9 (676eaf6, go1.27.3 linux/arm64)`（`sha256 c2d1e6…`，见 `meta.txt`），
Go 二进制 `sha256 cf9e804f43e70f7b2dfd49692a7aa6f6d39809822262dfcdc40d80159b22496d`，
Bash 基线 `scripts/traffic_blocker.sh`（sha 记录在 `meta.txt`）。
geo 资源为 Loyalsoldier `geoip.dat` / `geosite.dat`（sha 与大小记录在 `meta.txt`），
通过 `IDLELEO_GEO_DIR` 只读挂载。

| # | 事实 | 实测值 / 证据 |
|---|---|---|
| 1 | 安装前置 | `idleleo xray install --mode none --transport ws --path /f21 --port 443 --allow-non-loopback --container`：`validatorExit=0`、`warnings=[]`、`serviceActive=active`、`serviceEnabled=enabled` |
| 2 | 安装后的配置 | 入站 `VLESS-ws-in`：`port=443`、`listen=127.0.0.1`、`protocol=vless`、`network=ws`；outbounds 标签 `[direct, blocked]`；`routing.domainStrategy=AsIs`，唯一规则为 `inboundTag=[VLESS-ws-in] -> direct` |
| 3 | 无状态时 `status` | `configured=false`、`applied=false`、`drift=false`、6 类开关全 false、`ownedRuleCount=0` |
| 4 | 状态开关 | `ads enable`、`private-ip enable`、`bittorrent enable`、`country add cn`、`custom add --kind domain --value example.org`、`custom add --kind ip --value 192.0.2.0/24`、`custom enable --kind domain`、`custom enable --kind ip` 全部 `rc=0` |
| 5 | 首次 `apply --yes` | `rc=0`；`applied=true`、`ownedRuleCount=7`、`domainStrategy=IPIfNonMatch`、`sniffingEnabled=true`、`serviceRestarted=true`、`controlProbe="ok: tcp control on 127.0.0.1:443 (...)"`、`assetEnv="created etc/systemd/system/xray.service.d/50-xray-geodata.conf"`，并给出 `backupDir`、`oldSha256`、`newSha256` |
| 6 | 生成规则（顺序） | `domain=[geosite:cn]`、`ip=[geoip:cn]`、`protocol=[bittorrent]`、`domain=[geosite:category-ads-all]`、`ip=[geoip:private]`、`domain=[domain:example.org]`、`ip=[192.0.2.0/24]`，均 `outboundTag=blocked`；最后追加 `inboundTag=[VLESS-ws-in] -> direct` |
| 7 | 自定义聚合 | 同类自定义值聚合成一条规则：多个 domain 在一条 `domain` 数组，多个 IP 在一条 `ip` 数组；不按值拆规则 |
| 8 | sniffing | 所有入站写入 `sniffing.enabled=true`、`routeOnly=true`、`destOverride=["http","tls","quic"]` |
| 9 | geodata drop-in | `/etc/systemd/system/xray.service.d/50-xray-geodata.conf` 内容为 `[Service]` + `Environment=XRAY_LOCATION_ASSET=/etc/idleleo/share/xray`；`systemctl show -p Environment xray` 可见同一值 |
| 10 | backup | `backupDir=/etc/idleleo/backup/block-<UTC 时间戳>`，含 `config.json`、`traffic_blocker.json`、`meta`（`config=<路径>`） |
| 11 | 二次 `apply` 幂等 | `rc=0`；`oldSha256==newSha256`；配置 sha 不变；`assetEnv="reused existing XRAY_LOCATION_ASSET"` |
| 12 | `status`（已应用） | `configured=true`、`applied=true`、`drift=false`、`ads=true`、`privateIp=true`、`bittorrent=true`、`countries=["cn"]`、`customDomains={enabled:true,items:["example.org"]}`、`customIps={enabled:true,items:["192.0.2.0/24"]}`、`ownedRuleCount=7`，并给出 `geosite`/`geoip` 的 `path/size/mtime` |
| 13 | `off --yes` | `rc=0`；`applied=false`、`ownedRuleCount=0`、`domainStrategy=AsIs`、`sniffingEnabled=false`、`serviceRestarted=true`、`controlProbe="not probed: block off only removes rules"`；`newSha256` 精确等于安装时配置 sha |
| 14 | `off` 后配置 | 仅剩 `inboundTag=[VLESS-ws-in] -> direct`；`domainStrategy=AsIs`；`sniffing=null`；开关状态仍保留（不重置用户选择），`status.applied=false` |
| 15 | 缺 `--yes` | `rc=2`，stderr `applying traffic blocking rewrites routing rules and restarts xray; re-run with --yes to confirm`，配置 sha 不变 |
| 16 | `--dry-run` | `rc=0`；`applied=false`、`ownedRuleCount=1`（当时仅 ads）、`serviceRestarted=false`；配置 sha 不变 |
| 17 | 非法 country | `country add china` → `rc=1`，`country code "china" must be two letters`，零写盘 |
| 18 | 非法 IP | `custom add --kind ip --value 999.1.1.1` → `rc=1`，`custom IP "999.1.1.1" is not an address or CIDR`，零写盘 |
| 19 | 非法 kind | `custom add --kind url --value x` → `rc=1`，`--kind must be domain or ip (got "url")`，零写盘 |
| 20 | 未知 country 的 `-test` 回滚 | `country add zz` 被状态接受；`apply` `rc=1`，`xray -test rejected the candidate (exit 23): ; traffic blocking was not applied`；配置 sha 不变、`systemctl is-active xray` 仍 `active`；报告 `applied=false`、`ownedRuleCount=3`（ads + `zz` 的 domain/ip 两条） |
| 21 | 用户规则吞流量 | 在配置最后追加无条件 `outboundTag=blocked` → `apply` `rc=1`，`the last user routing rule blocks everything; remove it before applying traffic blocking`，零写盘 |
| 22 | 缺 geosite | 移走 `geosite.dat` 并加 `--geodata-url http://127.0.0.1:1` → `rc=1`，stderr `GeoData files geosite.dat are missing and the download failed: ...; traffic blocking was not applied`，配置 sha 不变 |
| 23 | Bash 基线 `tb_build_block_rules` | `country_block=["cn"]`、`ads=true`、`bittorrent=true`、`private_ip=true` 时输出 5 条规则，与 Go 前 5 条语义一致；Bash 无 custom 列表规则 |
| 24 | legacy adoption | 把 Bash 的 5 条规则 + 用户 `direct` 规则写入配置后 `apply`：`rc=0`，不产生重复的 `geosite:cn` 等规则，用户规则保留，`ownedRuleCount=7` |
| 25 | 真实配置校验 | 应用后的 `/etc/idleleo/conf/xray/config.json` 直接跑 `/usr/local/bin/xray -test -config ...`：`Configuration OK.`，`rc=0`（仅有 WebSocket 弃用警告） |
| 26 | 写根守卫 | `block` 子命令没有 `--root`（`unknown flag: --root`，`rc=2`）；写操作必须 `--container` + `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY`，缺 token `rc=1`（stderr `container root writes require ...`）；`status` 只读无需 token |
| 27 | `uninstall --purge` 残留 | 安装卸载后 `/etc/idleleo/conf/xray/traffic_blocker.json`、`/etc/idleleo/backup/block-*`、`share/xray/*.dat` 仍存在，夹具必须先清理再安装 |
| 28 | 非 443 的 mode=none 探针 | `--mode none --port 10086` 时 `base.PublicPort=0`，控制探针固定拨 `127.0.0.1:443`，`apply` 失败回滚；夹具改用 443（该行为登记为缺口） |
| 29 | 预设国家可用性 | 固定 geosite 中仅 `cn` 可用；`ru/ir/kp/gb/au/tr` 均被 `xray -test` 拒绝（exit 23），与 Bash 预设列表不一致（数据集限制，登记为缺口） |
| 30 | 二次 `off` | 首次 `off` 后再执行 `off --yes`：`rc=1`，stderr `no traffic-block rules are installed`；配置 sha 不变，状态文件与开关保留（`status.configured=true`、`ads=true`、`countries=["cn"]`） |
| 31 | systemd 启动频率限制 | 容器内 10 秒窗口第 6 次 `systemctl restart xray` 返回失败，journal 为 `start-limit-hit`（`StartLimitBurst=5`）；`systemctl reset-failed xray` 后恢复。夹具在每个会重启服务的场景前清计数 |

## 3. 设计决定

- **执行器是证据补齐，不改生产代码。** 本轮实测没有需要修复的小缺陷；
  事实 28/29 是既有行为/数据集限制，登记为 gap，不在本轮顺手改。
- 夹具在 **systemd 容器**内以 root 真实写 `/`：先 `uninstall --purge` 并清理
  `traffic_blocker.json`/`backup/`，再 `xray install --mode none --transport ws --port 443`，
  确保每次运行从同一个安装基线开始。容器一次性，退出即丢弃。
- geo 资源通过 `IDLELEO_GEO_DIR` 只读挂载，夹具复制到 `/etc/idleleo/share/xray` 后
  不再联网；缺失时报 `UNSUPPORTED_ENVIRONMENT`（exit 2），不伪装通过。
- xray 通过 `--xray-bin` 传入（与 F04 一致），不下载、不替换校验器。
- Bash 基线直接 `source scripts/traffic_blocker.sh`（设置 `xray_conf_dir`/`idleleo_dir`
  到临时目录），只调用纯函数 `tb_build_block_rules`；`jq` 用真实二进制。
  Bash 规则的键顺序与 Go 不同，用 JSON 语义比较（`jq -S`），不伪造字节一致。
- 所有失败场景都断言 `rc`、配置 sha 不变、`systemctl is-active xray=active`，绝不空 `exit 0`。

## 4. 场景

- **S1 前置与安装**：root、systemd、xray 二进制、geo 目录、Go 二进制、Bash 仓库均存在；
  清理残留后安装；断言事实 1–2。
- **S2 状态机与轻量守卫**：事实 3、4、15、16、17–19，均断言零写盘。
- **S3 首次 apply**：事实 5–10、25；核对规则数组、sniffing、domainStrategy、drop-in、
  backup 三个文件、真实重启与 TCP 探针。
- **S4 幂等与 status**：事实 11–12。
- **S5 off 恢复**：事实 13–15；二次 `off` 按事实 30 断言 `rc=1`、配置与开关不变。
- **S6 失败与回滚**：事实 20–22；每次失败后配置 sha 回到失败前值，服务仍 active。
- **S7 Bash 基线与迁移**：事实 23–24；`baseline-compare.json` 记录 aligned 5 条与
  approved-difference（custom 列表为 Go 扩展）。
- **S8 证据汇总**：`observed.json`、`bash-result.json`、`baseline-compare.json`；
  gap 不能写成 aligned。

## 5. 证据与命令

```
docker run --rm --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
  -v /tmp/f21out:/work/bin:ro \
  -v "$PWD/tests/go-parity/.cache/xray-linux-arm64/xray:/opt/xray/xray:ro" \
  -v "$IDLELEO_GEO_DIR:/geo:ro" \
  -v "$PWD:/work/repo:ro" \
  -v "$PWD/tests/go-parity/evidence/f21-2026-11-17:/work/evidence" \
  -e IDLELEO_PREVIEW_EVIDENCE=/work/evidence -e IDLELEO_GEO_DIR=/geo \
  idleleo-realroot@sha256:d985e8ed154d5c3b13c097f5a1ece90ce434ae03cd5444e7753f334359429aa7 \
  python3 -I /work/repo/tests/go-parity/parity/features/F21_test.py \
  --go-bin /work/bin/idleleo --xray-bin /opt/xray/xray --bash-repo /work/repo
```

两次独立容器各跑一次，要求 `failed=0` 且两次 `passed` 一致；证据包括
`meta.txt`、`commands.log`、`observed.json`、`bash-result.json`、
`baseline-compare.json`、`run1/run2-fixture-result.json` 与 `f21-work/`
（仅状态/规则/drop-in 摘要，不含 geo 原始文件）。最后跑
`python3 tests/go-parity/parity/scripts/check_evidence_hygiene.py` 要求 0 findings。

## 6. 差异登记

| 项 | 状态 | 说明 |
|---|---|---|
| 内置 5 条规则（country domain/ip、bittorrent、ads、private） | aligned | Bash `tb_build_block_rules` 与 Go 语义一致，顺序一致 |
| 自定义 domain/IP 列表 | approved-difference | Bash 无此功能；Go 聚合为每条 kind 一条规则 |
| `domainStrategy=IPIfNonMatch` 与 `sniffing.routeOnly` | approved-difference | Go 在 apply 时统一设置，Bash 行为未在纯函数中体现 |
| 状态文件 `owned_rules`/`previous_*` 字段 | approved-difference | Go 追加字段，Bash 未知键保留 |
| JSON 报告与 `--dry-run`/`--yes` | approved-difference | Go CLI 新增能力 |
| 非 443 的 mode=none 控制探针 | gap | 探针固定 443，非 443 安装会误判失败；本轮不修 |
| 预设国家 ru/ir/kp/gb/au/tr | gap | 固定 geosite 数据集不含这些代码，`-test` 拒绝；与 Bash 预设一致失效 |
| Bash 交互式 apply/off 与真实下载 | gap | 只对比纯规则生成；菜单、下载、完整配置写入未执行 |
| 无规则时再次 `off` | approved-difference | Go `rc=1`、`no traffic-block rules are installed`，配置与开关不变；Bash 无对应命令（事实 30） |
| systemd 启动频率限制 | harness note | 默认 `StartLimitBurst=5/10s`，夹具在每个重启场景前 `systemctl reset-failed xray`（事实 31），不改变产品行为 |
| `uninstall --purge` 残留 block 状态/备份 | gap | Go 卸载不清理这两类文件；Bash 对应语义未对比 |
| 真实客户端数据面（被墙域名/IP 请求） | gap | 控制探针只做本机 TCP；OPS-21 的请求级证据另行记录 |

## 7. 缺口（明确不宣称）

1. 没有真实 VPS、真实 DNS、真实被墙目标；不能宣称生产数据面已验证。
2. 控制探针为非 reality 模式下 `127.0.0.1:<publicPort>` 的 TCP 连接，不发起 HTTP 请求。
3. reality 模式的握手探针需要外网到 target，本夹具不覆盖；改用 mode none。
4. geo 下载成功路径未测，只测离线失败路径；首次 apply 前手动放置 geo。
5. Bash 的菜单流程、下载器、`tb_apply_rules` 完整写盘未对比。
6. 多国家、非 `cn` 预设受固定 geosite 数据集限制，只能验证回滚。
7. `off` 之后的状态文件保留开关值，这是 Go 的既定语义，未与 Bash 的选项重置行为对比。

## 8. 提交边界

- 新增 `tests/go-parity/parity/features/F21_test.py`、本目录三份文档、
  `tests/go-parity/evidence/f21-2026-11-17/`。
- 更新 `docs/go/FUNCTION_PARITY.md` F21 行、`docs/plans/p2/tasks.md` G-3、
  `tests/go-parity/parity/features/README.md` 计数。
- **不改** `install.sh`、`scripts/traffic_blocker.sh`、生产 Go 代码；不提交遗留文件。
- 不 push、不合并 main、不打 tag/release、不接触真实 VPS、不用公网 ACME CA。
