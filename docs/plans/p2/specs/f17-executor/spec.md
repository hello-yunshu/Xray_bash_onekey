# F17 执行器与双栈/DNS/防火墙规格（`net` 命令）

状态：待实施（Spec Mode，2026-11-17）。目标级别 CONTAINER_VERIFIED。
对应 Bash：`install.sh` 的 `classify_resolved_ips()`（2082）、
`managed_fw_families_for_mode()`（3368）、`firewall_add_managed_port()`（3505）、
`firewall_add_output_port()`（3532）、`reconcile_managed_firewall()`（3922）、
`apply_managed_firewall_transaction()`（4025）、
`validate_domain_network_records()`（6309）。
Bash 测试：`test_dual_stack.sh`、`test_dns_multi_record.sh`、
`test_firewall_ipv6.sh`、`test_firewall_transaction_complete.sh`。

## 1. 范围

新增只读的 `idleleo net dns` 与事务化的 `idleleo net firewall`，覆盖：
按 family 分类解析结果、A/AAAA 与服务器公网能力校验、按模式选择 netfilter family、
端口集合差分、失败反向回滚、状态文件持久化。不实现 Bash 的交互确认、端口修改向导、
baseline owned rules 与 reinstall 全局回滚。

### 1.1 包 `internal/netcfg`

`classify.go`：

- `IsIPv4Literal`、`IsIPv6Literal`、`Classify(records []string) (v4, v6 []string)`：
  逐条判定，IPv6 优先；保持输入顺序；空行跳过；不做去重（与 Bash 一致）。
- `Validate(public4, public6 string, records []string, policy string) (Report, error)`，
  `Report{Mode string; HasA, HasAAAA, AOK, AAAAOK, BadA, BadAAAA bool}`，逐条复刻
  6309 的判定：
  - `AOK = public4 != "" && len(v4)>0 && contains(v4, public4)`；`AAAAOK` 对称；
  - `policy=ipv4`：`AOK` → mode=ipv4，若 `hasAAAA && !AAAAOK` 则 `badAAAA`；
    否则 mode=none；
  - `policy=ipv6`：对称；
  - `auto/其他`：AOK&&AAAAOK → dual；仅 AOK → ipv4 且 `hasAAAA` 即 `badAAAA`；
    仅 AAAAOK → ipv6 且 `hasA` 即 `badA`；否则 none；
  - 错误值 `ErrBadRecords`（badA/badAAAA）与 `ErrNoMatch`（mode=none），CLI 映射
    rc=2 / rc=1。

`dns.go`：

- `Lookup(ctx, domain, resolverAddr) ([]string, error)`：`net.Resolver` 自定义 `Dial`
  指向 `resolverAddr`（UDP，`--resolver` 缺省用系统解析器）；先 `LookupIP(ctx,"ip4",domain)`
  再 `"ip6"`，按 v4→v6 拼接并转为字符串。失败返回空集与错误（不伪造记录）。
- `LocalPublicIPs() (v4, v6 string)`：遍历非 loopback、up 的接口，取第一个全局单播
  IPv4/IPv6；无则为空。Go 不做出站 echo 探测（见差异）。

`firewall.go`：

- `type FamilySet []string`；`FamiliesForMode(mode string, hasIPv6 bool) FamilySet`：
  `ipv6→[ip6tables]`；`dual→[iptables,ip6tables]`；`ipv4|manual→[iptables]`；
  `auto/空→[iptables] + hasIPv6 时 [ip6tables]`。
- `type Ports struct{ TCP, UDP []int }`：解析、去重、升序。
- `type Spec{Root string; New Ports; Mode string; PreviousFamilies FamilySet;
  DryRun bool; AllowContainerWrites bool}`；
  `type Report{Old, New Ports; OldFamilies, NewFamilies []string; Commands []Command;
  Persisted bool; RolledBack bool; Warnings []string}`。
- `Status(root)`：读 `<root>/etc/idleleo/managed_ports.json`，对当前工具可用 family
  逐端口执行 `-C INPUT/-C OUTPUT`，输出 `present/missing`，只读。
- `Apply(ctx, spec)`：
  1. 新 family 按 `FamiliesForMode`；旧 family 优先读
     `<root>/etc/idleleo/managed_families.json`，缺失时取「当前可用工具的并集」
     （保守，防止遗留另一 family 规则）；
  2. fail closed：新 family 任一工具不存在 → rc=1，零变更；
  3. 旧端口读取 `managed_ports.json`（缺失视为空）；
  4. 按 3922 的算法生成命令序列并执行：
     - 失去的 family：对该 family 的每个旧端口
       `-D INPUT -p tcp --dport N -j ACCEPT`、`-D OUTPUT ... --sport`；
     - 新增的 family：对每个新端口先 `-C` 再 `-I`；
     - 共同 family：旧-新删除、新端口逐项 `-C`/`-I`；
     - 删除用 `while -C` 循环 `-D`，添加先 `-C` 后 `-I`；协议 tcp/udp 均做 INPUT+OUTPUT；
  5. 每执行一条成功命令登记逆操作；任一失败 → 逆序执行逆操作，返回 rc=1 且
     `rolled_back=true`；逆操作失败 → rc=10；
  6. 成功后原子写 `managed_ports.json`（`{"tcp":[...],"udp":[...]}`）与
     `managed_families.json`；写失败 → 反向回滚并 rc=1（回滚失败 rc=10）；
  7. 持久化旧∪新 family：`iptables-save`→`<root>/etc/iptables/rules.v4`、
     `ip6tables-save`→`rules.v6`（0644 原子替换）；失败只写 warning 且 `persisted=false`；
     回滚阶段的持久化失败 → rc=10；
  8. `DryRun` 只返回命令列表，不执行、不建目录、不写状态。
- `Revert(ctx, spec)`：新端口为空、family 不变，复用 `Apply`。

### 1.2 CLI

- `internal/cli/net.go`：`net dns`、`net firewall status|apply|revert`。
- `net dns` 参数：`--domain`（必填）、`--resolver host:port`、
  `--policy auto|ipv4|ipv6`（默认 auto）、`--server-ipv4`、`--server-ipv6`
  （缺省用 `LocalPublicIPs`）、`--json`。
- `net firewall` 参数：`--tcp a,b`、`--udp a,b`、`--family auto|ipv4|ipv6|dual|manual`、
  `--json`、`--container`、`--dry-run`（仅 apply/revert）；端口 1-65535，非法 rc=2。
- `cli.go` dispatch 增加 `case "net"`；`flags.go` 增加四个命令白名单与
  `domain/resolver/policy/server-ipv4/server-ipv6/tcp/udp/family` 值旗标；
  帮助文本进 `i18n.go`。
- 真实根写入门禁：`host.RequireSystemWrite(root, ack)`；`status/dns` 只读。

## 2. 设计决定

- D1 校验语义逐条复刻 6309，包括显式 family 下另一族坏记录仍 rc=2。
- D2 DNS 查询先 A 后 AAAA，保持 family 与顺序；解析失败不伪造结果。
- D3 防火墙按端口集合与 family 集合做差分，不按「当前端口」整表重写。
- D4 所有变更命令登记逆操作；状态写失败同样反向回滚。
- D5 旧 family 状态缺失时取可用工具并集，宁可多删也不留陈旧规则。
- D6 持久化沿用 `iptables-save` 文件，不调用 systemd/service。

## 3. 分类

| 项 | 分类 | 说明 |
|---|---|---|
| 解析分类 | aligned | `Classify` 与 `classify_resolved_ips` 同序同 family |
| 双栈判定 | aligned | 9 组策略/记录表逐项一致（rc 0/1/2） |
| 公网能力来源 | approved-difference | Go 用本机接口地址，可被旗标覆盖；Bash 做出站 echo |
| 防火墙规则形状 | aligned | `-C/-I/-D INPUT dport`、`OUTPUT sport`、`--family` 映射一致 |
| 事务/回滚 | approved-difference | Go 逆操作栈；Bash 全局 pending 状态重试 |
| 状态文件 | aligned | `etc/idleleo/managed_ports.json` 同结构 |
| family 记录 | new-go-behavior | 额外 `managed_families.json` |
| 持久化 | approved-difference | 只写 rules.v4/v6，不调用 service/systemctl |

## 4. 场景（`tests/go-parity/parity/features/F17_test.py`）

- S1 fixture 内启动 Python UDP DNS 服务，按查询名返回 A/AAAA；
  `net dns --resolver 127.0.0.1:<port>` 走真实 Go 解析。
- S2 双栈表：auto dual / 仅 A 且 AAAA 错 / 仅 AAAA 且 A 错 / 仅 A 无 AAAA /
  两者皆无 / 显式 ipv4 匹配+AAAA 错 / 显式 ipv4 无 AAAA / 显式 ipv6 对称 /
  空记录；断言 `mode/hasA/hasAAAA/aOK/aaaaOK/badA/badAAAA` 与 rc。
- S3 Bash 基线：提取 `classify_resolved_ips`、`validate_domain_network_records`、
  `ip_lists_overlap`，mock `get_public_ip`/`resolve_domain_ips`/`log_echo`，跑同一张表，
  逐项比对；差异写入 `baseline-compare.json`。
- S4 防火墙 shim：PATH 内 `iptables`/`ip6tables`/`*-save` 维护规则文件，支持
  `-C/-I/-D/-S` 与 `FAKE_FW_FAIL_ON` 单次故障注入。
  - apply tcp/udp 443（ipv4）→ 四类规则与 state 正确；
  - 443→8443 → 旧规则删除、新规则添加；
  - ipv4→dual → ip6tables 获得规则；dual→ipv6 → v4 规则全部删除；
  - 中途注入失败 → rc=1、规则文件摘要与 state 恢复原状；
  - state 目录只读 → rc=1 且规则反向恢复；
  - `--dry-run` → 只输出命令，零执行零写盘；
  - `status` → present/missing 与 shim 一致；`revert` → 清空受管规则与 state，
    二次 revert no-op；
  - `--family dual` 但 PATH 无 ip6tables → rc=1 零变更。
- S5 门禁：非法端口/未知 `--policy/--family`/未知旗标 rc=2；真实根未确认 rc=2；
  无 marker 沙箱 rc=2。
- S6 解析器失败：DNS 服务返回 NXDOMAIN → rc=1，`mode=none`，不写任何东西。

## 5. 缺口

- 规则执行在 shim 上，未验证真实内核 netfilter、IPv6 路由或远端连通性。
- 未在真实双栈 VPS 验收；未覆盖 Bash 的 baseline owned rules / reinstall 全局回滚。
- 持久化只写 rules 文件，不验证重启后加载（依赖宿主 netfilter-persistent）。
- Go 不做外部 echo 探测，接口地址不等于公网可达地址。

## 6. 文件清单

新增：`internal/netcfg/{classify,dns,firewall}.go`、
`internal/netcfg/{classify,dns,firewall}_test.go`、`internal/cli/net.go`、
`tests/go-parity/parity/features/F17_test.py`、本 spec 三件套。
修改：`internal/cli/cli.go`、`internal/cli/flags.go`、`internal/i18n/i18n.go`、
`docs/go/FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md`、
`tests/go-parity/parity/features/README.md`。

## 7. 验收与审批

- 固定镜像双跑全绿；证据 `tests/go-parity/evidence/f17-2026-11-17`；
  hygiene 0 findings；单元测试 `go test ./internal/netcfg ./internal/cli`。
- 需要用户批准：新增 `net` 命令面、DNS 解析器旗标、防火墙状态文件与退出码语义。
