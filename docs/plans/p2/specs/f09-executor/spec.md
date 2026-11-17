# F09 契约执行器规格：Nginx upstream 文件管理

状态：`APPROVED`（2026-11-17，用户批准立项后实施）
证据级别上限：`CONTAINER_VERIFIED`（真实 Go 二进制 + 真实 nginx `-t`；无真实 VPS、无公网、无 systemd 依赖）

## 1. 范围

F09 的 Bash 基线是 `scripts/file_manager.sh`，由安装菜单以
`nginx_upstream_server_set` 进入，按上游选择 `.realityServers`、
`.wsServers`、`.grpcServers`、`.xhttpServers` 文件，增删 `server host:port
weight=N max_fails=2 fail_timeout=10;` 行。Go 侧对应命令已经存在：

```
idleleo [--root ROOT] xray balance list   --upstream reality|ws|grpc|xhttp [--json]
idleleo [--root ROOT] xray balance add    --upstream NAME --host H --port N [--weight W] [--probe] [--json]
idleleo [--root ROOT] xray balance remove --upstream NAME --host H[:PORT] [--json]
```

本立项只补“可重放、可对照”的契约执行器与证据；**除非执行器暴露真实缺陷，
不改生产代码**。若发现缺陷，修复必须最小化并单独在本规格“差异登记”中记录。

不在范围：

* serverNames（`*.serverNames`）与 `fm_edit_file` 的交互式编辑流程；
* 真实 systemd reload（沙箱根按设计跳过并告警，真实根由既有 F04/F20 覆盖）；
* 防火墙端口放行（Bash 交互分支需要 iptables，容器内不执行）。

## 2. 实测事实（2026-11-17）

环境：`idleleo-preview@sha256:ba371758104034125c9519079ef15838d8d4faf9eb23a0a1721bc0789b1234de`
（Ubuntu 24.04.5，nginx 1.24.0、bash 5.2.21、jq 1.7、真实 `ngx_stream_module`）。
Go 二进制由 `golang:1.27.4`、`CGO_ENABLED=0`、`-trimpath`、`-mod=vendor` 构建。

| # | 事实 | 实测结果 |
|---|------|----------|
| 1 | Bash 文件正文 | `server ${host}:${port} weight=${weight} max_fails=2 fail_timeout=10;` + `\n`（`file_manager.sh:180-181`） |
| 2 | Go 文件正文 | 相同输入下与 Bash 逐字节一致（`10.0.0.2:8443 weight=60` 时 60 字节，末字节 `0x0a`） |
| 3 | 文件名 | 两侧都是 `${host}.${extension}`；Go 对 IPv6 保留 `::1.realityServers`，正文用 `net.JoinHostPort` 写成 `[::1]:8443` |
| 4 | 默认权重 | 两侧都是 50；Bash 通过 `read_optimize ... 0 100`，Go 缺省 `--weight` 时写 50 |
| 5 | Reality 安装 | 只允许 `--upstream reality`；锚点 `00-xray.conf` 必须含 `*.realityServers;`，否则 rc=1 并提示 `reality-nginx is not managed by 'xray balance'` |
| 6 | TLS 安装 | 只允许 `ws|grpc|xhttp`；锚点 `02-xray-server.conf` 必须含对应 `*.wsServers;` 等，否则 rc=1 |
| 7 | 新增成功 | 真写文件 → 真实 `nginx -t` → 沙箱根跳过 reload；rc=0，JSON 含 `changed=true`、`file`、两条 warning（未探测、reload skipped） |
| 8 | `nginx -t` 失败 | rc=1，新文件被删除，stderr 带 `nginx -t rejected ... the new backend file was removed` |
| 9 | 保留端口 | 443/9403/9404/9443/9444 rc=1：`port 443 is reserved by the managed install` |
| 10 | 非法主机 | 空格等字符 rc=1：`invalid backend host "bad host"` |
| 11 | 端口/权重越界 | 0/65536 rc=1；权重 101/-1 rc=1；非整数端口 rc=2（旗标解析） |
| 12 | 重复主机 | 同 host 再 add rc=1：`a backend for host ... already exists` |
| 13 | 删除保护 | 删 loopback rc=1：`refusing to remove the local 127.0.0.1 backend`；端口不匹配 rc=1；文件不存在 rc=1 |
| 14 | 列表排序 | 按 host、port 升序；文本为 TSV `host\tport\tweight\tfile`，`--json` 为 `{upstream,backends,changed,probed,warnings}` |
| 15 | Bash 删除 | `fm_delete_file` 直接 `rm`，无 loopback/最后一个后端/端口校验（`file_manager.sh:267-282`） |
| 16 | Bash 列表 | 只打印文件名表格，无 JSON、无 host/port/weight 字段（`file_manager.sh:75-135`） |
| 17 | 沙箱根门禁 | `--root` 只要不是 `/` 就按沙箱处理，`balance` 不要求 `.idleleo-phase01-sandbox`；缺 metadata rc=3，缺锚点 rc=1，缺 nginx 二进制 rc=1 且删除新文件 |
| 18 | `--probe` | 需要 metadata `install.serverNames`；对目标做 TLS 1.3 + SNI 握手，成功时 `probed=true` 且不再输出“未探测”告警；127.0.0.0/8 一律按 loopback 处理 |

## 3. 设计决定

1. **执行器驱动真实 nginx，而不是替身。** 沙箱根里放
   `usr/local/nginx/sbin/nginx`（指向镜像内 `/usr/sbin/nginx`），主配置
   `load_module .../ngx_stream_module.so` 后包含生成的 upstream 锚点；这样
   `AddBalance` 的 `nginx -t` 是真实语法检查，rollback 也是真实删除。
2. **Reality 用真实 `xray generate --mode reality-balance --role primary`
   产物。** 生成 `00-xray.conf` 与 `127.0.0.1.realityServers`，仅把
   `/etc/idleleo/conf/nginx`、`/usr/local/nginx` 前缀改写到沙箱根（F04 同样
   做法）。这样锚点、loopback 行、端口都来自生产代码。
3. **TLS 用真实 `xray generate --mode tls --transport ws` 的 fragments。**
   复制 `02-xray-server.conf`（upstream）与 `127.0.0.1.wsServers`；`nginx-out`
   的 server 块含 `quic` 指令，镜像内 nginx 1.24 不支持，因此 `-t` 用最小
   `server { listen 9443; location / { proxy_pass http://xray-ws-server; } }`
   替代。server 块本身由 F02 覆盖，F09 只关心 upstream 文件。
4. **Bash 基线用函数级提取执行。** 从 `scripts/file_manager.sh` 提取
   `fm_create_server_file`、`fm_delete_file`，注入 `log_echo/gettext/read_optimize/
   fm_list_files/fm_restart_nginx_and_check_status` 桩，执行后比较文件字节；
   列表/JSON/保护性校验按“批准差异”登记，不伪装成 parity。
5. **只做只读断言和沙箱内写。** 每次场景独立 `root`；写操作后比较完整文件、
   rc、stdout/stderr；不触碰宿主目录、不启 systemd、不读真实 VPS。
6. **不新增 Go 依赖、不改 `install.sh`、不改旗标白名单。** 执行器只用 Python
   标准库与镜像内工具。

## 4. 基线对照

`aligned`：

* 文件正文与文件名（同 host/port/weight，含权重缺省 50 与 IPv6 括号写法）；
* 真实 `nginx -t` 失败时不留半份配置（Go 删除新文件；Bash 依赖重启失败后人工修复，
  仅在“失败不静默”这一层对齐）。

`approved-difference`（记入 `baseline-compare.json`）：

* Go 拒绝保留端口、80/443 类冲突、非法 host、重复 host、越界权重；
  Bash 只做字符/范围输入校验，会覆盖或写入冲突文件。
* Go 拒绝删除 loopback 与端口不匹配的后端；Bash `rm` 无保护。
* Go `list` 输出 host/port/weight/JSON；Bash 只输出文件名表格。
* Go 在沙箱根跳过 reload 并告警；Bash 总是 `nginx -s reload`/重启。
* Go 默认不做存活探测并明确告警；Bash 完全依赖 nginx 被动摘除。

`new-go-behavior`：`--json`、`--probe`、`--root` 沙箱、`--container` 真实根门禁。

## 5. 场景

* **S1 初始化**：真实 `generate` 出 reality-balance 主节点配置、`00-xray.conf`、
  loopback fragment；`nginx -t` 成功；`balance list` 返回 loopback 一行，树摘要不变。
* **S2 新增**：`add 10.0.0.2:8443 weight=60` rc=0；文件字节等于 Bash
  `fm_create_server_file` 产物；`list` 排序为 `10.0.0.2`、`127.0.0.1`；
  `--json` 的 `changed/file/warnings` 正确；配置树只多一个文件。
* **S3 幂等/重复**：同 host 再 add rc=1，文件与树摘要不变。
* **S4 删除**：`remove 10.0.0.2:8443` rc=0，文件消失、loopback 保留；
  再删同一文件 rc=1。
* **S5 保护**：删 loopback、错端口、越界端口/权重、非法 host、保留端口均按事实表
  rc/消息拒绝；未知 upstream 与 TLS 安装上的 reality 均 rc=1。
* **S6 回滚**：主配置注入非法指令后 add rc=1，新文件不存在；恢复主配置后 add 成功。
* **S7 TLS**：真实 TLS ws 产物 + 最小 server 块；`add --upstream ws` rc=0，
  文件后缀 `.wsServers`；reality 在此安装 rc=1。
* **S8 Bash 基线**：提取 `fm_create_server_file` 写同 host/port/weight，
  字节与 Go 完全一致；提取 `fm_delete_file` 验证其无 loopback 保护（批准差异）。
* **S9 权限/环境**：沙箱根不要求 marker；缺 metadata rc=3、缺锚点 rc=1、
  缺 nginx 二进制 rc=1 且删除新文件；真实根 `/` 无 `--container` 的写入门禁
  不在容器内执行，登记为缺口。
* **S10 只读**：`list`、`list --json`、`list --upstream nope`、
  未知旗标、缺 `--upstream` 的 rc 与输出；`list` 前后树摘要一致。

## 6. 缺口登记

* 未在真实 VPS、真实 systemd、真实防火墙环境执行；reload 分支只验证“跳过并告警”。
* 真实根 `/` 的 `--container` 写入门禁未在容器内执行（无法安全模拟宿主根）。
* `--probe` 的 TLS 1.3 + SNI 握手在容器自身非 loopback 地址上验证，不验证跨机网络、
  证书链与真实上游服务。
* Bash 交互菜单、`fm_edit_file`、serverNames 不执行；只覆盖文件读写契约。
* nginx 1.24 不支持 http3/quic，TLS server 块用最小替身，真实 server 块由 F02 覆盖。
* 未覆盖非 Linux 文件系统大小写/长文件名差异。

## 7. 证据与验收

固定镜像：`idleleo-preview@sha256:ba371758104034125c9519079ef15838d8d4faf9eb23a0a1721bc0789b1234de`。

每个场景一个全新容器（容器内布局 `/work/bin/idleleo`、`/work/repo`、
`/work/evidence`），连跑两次；两次 `fixture-result.json` 均为 failed=0 且断言数一致。
证据目录：`tests/go-parity/evidence/f09-2026-11-17/`，包含
`meta.txt`、`commands.log`、`observed.json`、`baseline-compare.json`、
`f09-work/`、两次 `runN-*`。提交前运行
`python3 tests/go-parity/tools/check_evidence_hygiene.py`，要求 0 findings。

## 8. 提交边界

1. `test(F09): prove nginx upstream file parity`
   —— `tests/go-parity/parity/features/F09_test.py`、证据目录、
   `docs/go/FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md`、本规格。
2. `docs(parity): mark F09 checklist complete`
   —— `docs/plans/p2/specs/f09-executor/tasks.md`、`checklist.md`。

不提交：`check_evidence_hygiene.py` 的遗留修改、` 2` 后缀文件、
`f02-executor/`、`f07-executor/`、`.tmp-f09/`；不 push、不合并 main、
不打 tag/release、不接触真实 VPS、不使用公网 ACME。
