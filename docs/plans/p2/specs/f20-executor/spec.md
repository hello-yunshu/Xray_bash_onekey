# F20 执行器规格：Fail2ban 接入

状态：待批准（批准前不写测试、不跑正式两次容器、不提交）
证据等级：CONTAINER_VERIFIED（固定 digest 容器内真实执行 Go 二进制、真实 fail2ban 1.0.2、
真实 `fail2ban-client -x start`、真实 Bash 基线函数、真实封禁/解封/信任运行态）
**明确不宣称完全 VERIFIED：容器内没有 systemd/journal，sshd jail 两侧都被跳过；
真实 systemd 重启、真实 SSH 暴力破解触发、真实 iptables 规则效果、真实 VPS 均未验证。**
提交边界：执行器、证据、三处文档计数；`install.sh` 与 `scripts/fail2ban_manager.sh` 不改；
不 push、不合并 main、不打 tag/release、不接触真实 VPS、不联网。

## 1. 目标

为 `feature_contracts.json` 的 F20（`Fail2ban 防爆破`，P1）建立真实夹具
`tests/go-parity/parity/features/F20_test.py`，覆盖：

1. `idleleo fail2ban install` 的生成物：4 个 Nginx jail、`jail.local`、增量封禁、
   两个过滤器、systemd drop-in、manifest；二次运行幂等；
2. 与固定 Bash 基线（`scripts/fail2ban_manager.sh`）真实执行后的文件逐字节对比；
3. 真实 fail2ban 运行态：`status`、`banned`、`unban`（含 already-absent）；
4. `trust add|del` 的运行态 ignoreip 与 `zzz-idleleo-trust.local` 持久化（IPv4/CIDR/IPv6）；
5. `jail enable|disable` 的文件语义与「非托管 jail 拒绝」；
6. `uninstall` 按 manifest 删除、保留操作员文件、二次运行幂等；
7. 守卫与错误路径：缺二进制零落盘、非法 IP/CIDR、未知 jail、sandbox marker、
   `--container` 写根确认；
8. 明确登记容器无法覆盖的缺口（SSH journal、systemd 重启、真实封禁数据面）。

## 2. 已核实事实（2026-11-17 容器实测，非推测）

实测环境：`idleleo-e2e@sha256:3012978e415b9bec250f738ddc7246a64837896fbeb52ed27571d8f3b8b24002`，
`Fail2Ban v1.0.2`，镜像内 `systemctl` 为真实 systemd 二进制但容器 PID 1 不是 systemd；
Go 二进制 `sha256 cf9e804f43e70f7b2dfd49692a7aa6f6d39809822262dfcdc40d80159b22496d`；
Bash 基线 `scripts/fail2ban_manager.sh` `sha256 8400787a9585ef591a7480e843e7e166a7d861256693df9950d4e1c2402f4b39`。

| # | 事实 | 实测值 / 证据 |
|---|---|---|
| 1 | install 首次（`--root / --container`） | `rc=0`；`jails` 5 项：`sshd` `written=false`（`reason` = `no active ssh/sshd unit: systemd cannot read SSH logs`），其余 4 个 `written=true` |
| 2 | install `files` | 9 条：`jail.local`、`jail.d/nginx-{badbots,botsearch,no-host,tls-error}.local`、`jail.d/zzz-idleleo-incremental.local`、`filter.d/nginx-{no-host,tls-error}.conf`、`etc/systemd/system/fail2ban.service.d/restart-policy.conf`；`warnings` 仅 `restart fail2ban failed: systemctl restart fail2ban failed (exit 1)`；`serviceRestarted=false` |
| 3 | manifest | `/etc/idleleo/v1/fail2ban.json`：`version=1`，9 条相对路径（与事实 2 的文件集合一致） |
| 4 | 二次 install 幂等 | 两次运行后 `/etc/fail2ban` 全树 `sha256sum` 完全相同（`diff` 空），`rc=0` |
| 5 | `nginx-badbots.local` | `enabled=true`、`port=http,https,8080`、`filter=apache-badbots`、`logpath=/usr/local/nginx/logs/access.log`、`bantime=604800`、`maxretry=5`（无 `findtime`） |
| 6 | `nginx-botsearch.local` | `enabled=true`、`filter=nginx-botsearch`、`logpath` 两行（`access.log` + 缩进 11 空格的 `error.log`）、`bantime=604800`（无 `maxretry`/`findtime`） |
| 7 | `nginx-no-host.local` | `enabled=true`、`filter=nginx-no-host`、`logpath=sni_error.log`、`bantime=604800`、`maxretry=5`、`findtime=120` |
| 8 | `nginx-tls-error.local` | `enabled=true`、`filter=nginx-tls-error`、`logpath=tls_error.log`、`bantime=43200`、`maxretry=8`、`findtime=300` |
| 9 | `jail.local` | 与镜像包内 `/etc/fail2ban/jail.conf` 字节相同（`diff -q` rc=0） |
| 10 | 增量封禁 | `zzz-idleleo-incremental.local`：`[DEFAULT]`、`bantime.increment=true`、`bantime.multipliers = 1 2 4 8 16 32 64`、`bantime.maxtime=180d`、`bantime.rndtime=10m`、`bantime.overalljails=false` |
| 11 | 过滤器 | `nginx-no-host.conf` 与 `nginx-tls-error.conf` 内容相同：`datepattern = %%d/%%b/%%Y:%%H:%%M:%%S %%z`、`failregex = ^<HOST> \[[^\]]*\] "[^"]*" \S* \d+$`、`ignoreregex =` |
| 12 | Bash 基线真实执行 | 真实 `mf_configure_fail2ban`（`tls_mode=Reality`、`reality_add_nginx=on`、真实 systemctl/journalctl）：`rc=0`，日志 `systemd 无法读取 SSH 日志` / `跳过启用 SSH 规则`；`jail.d` 产出 5 个文件（无 `sshd.local`） |
| 13 | Bash vs Go 逐字节 | `diff -ru bash-after/jail.d go-after/jail.d` 仅 `Only in bash-after: sshd.local`（该轮 Bash 误用 stub systemctl）；改用真实 systemctl 后两侧都无 `sshd.local`，4 个 jail、`jail.local`、incremental、2 个过滤器完全一致 |
| 14 | `status --json` | `installed=true`，4 个 jail（badbots/botsearch/no-host/tls-error），`currentlyBanned=0`，`raw` 含 `Number of jail: 4` |
| 15 | `banned --jail nginx-no-host` | 先用真实 `fail2ban-client set nginx-no-host banip 192.0.2.10`，再查询：`bannedIPs=["192.0.2.10"]`、`currentlyBanned=1`、`totalBanned=1` |
| 16 | `unban` | 首次 `rc=0`、`unbanned=true`、`wasBanned=true`、`remainingIPs=[]`；二次 `rc=0`、`alreadyAbsent=true`、`unbanned=false` |
| 17 | `unban` 错误 | 非法 IP `nope` → `rc=1`，`invalid IP address: nope`；未知 jail → `rc=1`，`jail "nope" is not active`；`banned` 未知 jail → `rc=1`（`fail2ban-client status nope failed (exit 255)`） |
| 18 | `trust add` | `rc=0`，`applied=true`、`persisted=true`；运行态 `fail2ban-client get nginx-no-host ignoreip` 含 `192.0.2.55`；写入 `jail.d/zzz-idleleo-trust.local`（头部 `# Managed by Idleleo...`，`[jail]` + `ignoreip = <值>`） |
| 19 | `trust del` | `rc=0`；文件仅剩头注释；再次 `trust add` IPv6 `2001:db8::1` 成功并写入同一文件；非法 CIDR `192.0.2.5/33`、未知 jail 均 `rc=1` |
| 20 | `jail disable/enable` | 文件 `enabled  = false` / `enabled  = true` 正确翻转；容器无 systemd → `serviceRestarted=false` 且 `warnings` 含 `restart fail2ban failed`；`jail disable --name user-custom`（非托管）`rc=1`，`jail "user-custom" is not managed by Idleleo` |
| 21 | `uninstall` | `removed` 10 条（manifest 9 条 + `zzz-idleleo-trust.local`）；`preserved=["/etc/fail2ban/jail.d/user-custom.local"]`；`needForce=false`；`warnings` 含 restart 失败与「包仍安装」；manifest 删除后再次 `uninstall` `rc=2`、`needForce=true`、`candidates` 仅列操作员文件、零删除；加 `--force` 后 `rc=0`、`removed=[]`、操作员文件仍在 |
| 22 | 缺二进制 | `PATH` 无 `fail2ban-client` 时 `install --root <sandbox>` `rc=1`，stderr 打印 Debian/RHEL/Alpine 三条命令与「Go 不调包管理器」，沙盒内除 marker 外零文件 |
| 23 | 写根守卫 | `--root` 沙盒目录必须含 `.idleleo-phase01-sandbox`（`I_ACCEPT_DISPOSABLE_SANDBOX`）；写真实根必须 `--container` + `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY` |

## 3. 设计决定

- **执行器是证据补齐，不改生产代码。** 本轮实测未发现需要修复的 Go 缺陷；
  所有 Bash 差异均属既有批准口径（G13 不调包管理器、ED-002 按 manifest 卸载）。
- 执行器在容器内以 root 真实写 `/etc/fail2ban`：先 `cp -a` 快照，跑 Bash 基线，
  快照产物后恢复；再跑 Go，快照产物；两侧用 `diff -ru` 对比。容器一次性，退出即丢弃。
- Bash 基线直接 `source scripts/fail2ban_manager.sh`（该脚本是独立文件，不是
  `install.sh` 内联函数），只 stub `log_echo`/`judge`/`gettext`/颜色变量；
  `systemctl`/`journalctl` 用真实二进制，使两侧都因「无 systemd」跳过 sshd，口径一致。
- 运行态验证前用真实 `fail2ban-client -x start` 启动 daemon；封禁样本用
  `fail2ban-client set ... banip 192.0.2.10` 制造，不伪造日志、不改过滤器。
- 所有错误码按实测断言：CLI 业务错误为 `rc=1`（不是 `xray generate` 的 `rc=2`），
  执行器不套用 F04 的退出码假设。
- 固定输入：`192.0.2.0/24` 与 `2001:db8::1` 文档地址；不写真实 IP、不联网。
- 容器不可覆盖项写入 `baseline-compare.json` 状态 `gap`，不写成 aligned。

### 3.1 必须登记的差异

| 契约 | Go 行为 | Bash 行为 | 状态 |
|---|---|---|---|
| 4 个 Nginx jail 文件 | 事实 5–8 的键值与顺序 | 与 Go 逐字节一致 | `aligned` |
| `jail.local` / incremental / 过滤器 | 事实 9–11 | 与 Go 逐字节一致 | `aligned` |
| sshd jail | 无活动 SSH unit 时不写，返回 reason | 同样跳过并打印中文日志 | `aligned`（容器内） |
| 缺 fail2ban 包 | `rc=1`、打印三平台命令、零落盘 | 自动 `apt`/`dnf`/`apk` 安装 | `approved-difference`（G13） |
| 卸载 | 按 manifest 删除，保留 manifest 外文件，二次 `rc=0` | `rm -f /etc/fail2ban/jail.d/*.local` 等通配删除 | `approved-difference`（ED-002） |
| trust 持久化 | 独立 `zzz-idleleo-trust.local` | 改写对应 `[jail]` 的 `ignoreip` | `approved-difference`（更集中，语义等价） |
| `jail enable/disable` | 只允许 manifest 内文件 | 交互菜单编辑模块 | `approved-difference`（Go 收紧所有权） |
| 服务重启 | 容器内 systemctl 失败 → warning、`serviceRestarted=false` | 同样失败但不报告结构化结果 | `gap`（无 systemd） |
| SSH journal 触发 | 未执行 | 未执行 | `gap`（无 journal/sshd） |
| 真实封禁数据面 | 未验证 iptables 规则 | 未验证 | `gap` |

## 4. 测试计划（S1–S8）

- **S1 安装生成物**：首次 install 的 `jails`/`files`/`warnings`/`serviceRestarted`；
  4 个 jail 的键值逐项断言；`jail.local` 与包内 `jail.conf` 同 sha；incremental 与过滤器内容；
  manifest 9 条；二次 install 全树 sha 不变。
- **S2 Bash 基线**：真实执行 `mf_configure_fail2ban`，断言 `rc=0`、日志含跳过 SSH、
  `jail.d` 文件集合；与 Go 产物逐字节 diff（排除容器内双方都不存在的 `sshd.local`）；
  `bash-result.json` + `baseline-compare.json`。
- **S3 运行态**：`fail2ban-client -x start`；`status` 4 jail；`banip` 后 `banned` 命中；
  `unban` 首次/二次语义；未知 jail 与非法 IP 的 rc。
- **S4 trust**：IPv4 add → 运行态 ignoreip + 文件；del 清空；IPv6 add/del；
  非法 CIDR 与未知 jail `rc=1`。
- **S5 jail 启停**：disable/enable 的文件翻转与 `serviceRestarted=false` warning；
  非托管 jail `rc=1`。
- **S6 卸载**：预置 `user-custom.local`；uninstall 的 removed/preserved/needForce；
  文件实际消失；二次 uninstall 幂等。
- **S7 守卫与错误**：缺二进制（sandbox + 空 PATH）rc=1 且零落盘；
  sandbox marker 缺失时拒绝；`--root /` 无 `--container` 拒绝；非法参数 rc。
- **S8 汇总**：所有断言写入 `observed.json`；缺口与 harness 适配写入 `baseline-compare.json`。

## 5. 证据与运行命令

```bash
# 构建（宿主）
docker run --rm -v "$PWD":/src -w /src -v /tmp/f20out:/out -e CGO_ENABLED=0 \
  golang:1.27.4 go build -trimpath -o /out/idleleo ./cmd/idleleo

# 正式运行（每个 run 一个新容器）
docker run --rm --privileged --tmpfs /run --tmpfs /run/lock \
  -v "$PWD":/work/repo:ro -v /tmp/f20out:/work/bin:ro \
  -v "$PWD/tests/go-parity/evidence/f20-2026-11-17:/work/evidence" \
  idleleo-e2e@sha256:3012978e415b9bec250f738ddc7246a64837896fbeb52ed27571d8f3b8b24002 \
  python3 -I /work/repo/tests/go-parity/parity/features/F20_test.py \
    --go-bin /work/bin/idleleo --bash-repo /work/repo
```

证据目录：`meta.txt`（镜像 digest、fail2ban 版本、二进制 sha、两次 passed/failed、
GAP 清单）、`commands.log`、`observed.json`、`bash-result.json`、`baseline-compare.json`、
`f20-work/`（Bash/Go 两侧产物快照）。

## 6. 容器无法覆盖的缺口（不伪造）

1. 真实 systemd：`systemctl restart fail2ban` 在容器内失败，只验证到 warning 与
   `serviceRestarted=false`；真实重启后的 jail 生效未验证。
2. 真实 SSH journal：无 sshd 服务与 journal，`sshd.local` 两侧都不生成；
   模板文本只做了源码/文件一致性对比，未做运行态触发。
3. 真实封禁数据面：未验证 jail 命中日志后 iptables/ipset 规则实际阻断连接。
4. fail2ban 版本差异：容器为 1.0.2（P2 C1 曾在 1.1.0 手工实测），
   1.1.x 的配置兼容性未在本执行器覆盖。
5. 真实 VPS 与生产 `/etc/fail2ban` 的权限/属主差异未验证。

## 7. 提交边界

1. `test(parity): add F20 fail2ban executor`：`F20_test.py`、证据目录、
   `FUNCTION_PARITY.md` F20 行、`docs/plans/p2/tasks.md` G-3、features `README.md`。
2. `docs(parity): mark F20 executor checklist complete`：仅 tasks/checklist 勾选。
3. 不提交：`check_evidence_hygiene.py` 的遗留修改、`f02-executor/`、`f07-executor/`、
   所有 ` 2` 后缀文件；不 push/tag/merge。
