# Nginx 线独立复检规格（重新分级版）

- 状态：A1-A7 与 CFG-1～CFG-9 已实施；Block 3 待真实 root
- 分级口径：**不要求无条件复现 bash，但主功能必须一致**
  - A 类：主功能不一致，直接影响可用性/安全 → 必改
  - B 类：实现细节或更严格/更保守 → 可接受，登记为有意分叉
  - C 类：Go 侧独立缺陷，与 bash 无关也必须修
- 非目标：F13 Nginx 更新/回滚；Block 3 privileged 真实 root 验收（排在整改之后）

## 0. 复检证据（本轮已实测）

```text
docker run --rm -v <repo>:/src -w /src -e GOFLAGS=-mod=vendor \
  golang:1.27.4 go test -count=1 ./internal/nginx/ ./internal/deploy/
ok  github.com/hello-yunshu/Xray_bash_onekey/internal/nginx  0.073s
ok  github.com/hello-yunshu/Xray_bash_onekey/internal/deploy 1.643s
```

线上 manifest v2026.10.15.7679：`schema_version=1`、`tag` 与 `nginx_build` 一致、x86 `size_bytes=9285803`、`binary_sha256` 存在，Go 校验不会误拒当前版本。

单测覆盖：权限位、stream 占位、`nginx -t` 失败回滚旧树、同 build 跳过、卸载非 purge 保留 conf。

### 0.1 复检结论

- 产物层（下载/manifest/SHA256/解包/ELF）：**主功能可用**，当前线上产物实测可通过；剩余为加固项。
- 安装事务：A1-A7 已全部落地并单测覆盖；真实 root 等价性仍需 Block 3。
- 权限与回滚：A3/A4/A5 已修（symlink 跳过、权限断言、回滚聚合）。
- Xray 协作配置：CFG-1～CFG-9 已按 bash 功能对齐，含一处**端口冲突缺陷**（Reality+Nginx 默认 443 与 Nginx 抢端口）已修复。
- 结论：代码级可认为“主功能一致”；Block 3 未通过前不得宣称真实等价。

## 1. A 类：主功能不一致，必改（最小集合）

### A1 默认缺少本机 IP 403 防护（安全默认行为）

- 现象：Go 仅在显式 `--local-ip` 时插入 403；默认安装不防护，直接访问 IP 可进入代理。
- 证据：[install.go L494-L506](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L494-L506)、[xray.go L438](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/cli/xray.go#L438)；bash 无条件插入 [install.sh L4840](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/install.sh#L4840)。
- 判定：仅静态推断；默认配置存在 `error_page ... 504` 锚点（上一轮实测）。
- 修法：
  - `internal/host/net.go` 新增 `LocalAddress(ctx)`（`ip -4 route get 1.1.1.1` 取 `src`，回退 `hostname -I` 首个非回环）。
  - `deploy.Install` 在 `LocalIP==""` 时探测；失败记 warning，不阻断。
  - `RewriteMainConfig` 返回 warning；`error_page` 锚点放宽为 `^\s*error_page\b.*\b504\b`；未命中必须告警，禁止静默跳过。
- 测试：`TestInstallAddsLocalIPGuardByDefault`、`TestRewriteWarnsWhenAnchorMissing`。

### A2 卸载后无法干净重装（跨实现状态污染）

- 现象一：Go 非 purge 保留 `/etc/idleleo/conf/nginx`；重装时旧片段仍被 `*.conf` include，行为被污染。
- 现象二：卸载 stop 失败仍删除安装树；删除失败只记 warning，CLI 仍成功。
- 证据：[install.go L409-L417](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L409-L417)、[L391-L397](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L391-L397)、[L431-L433](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L431-L433)；bash 无条件删除 [install.sh L11443-L11457](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/install.sh#L11443-L11457)。
- 判定：静态推断；真实目录状态待 Block 3。
- 修法（建议默认值，可改）：
  - `nginx.Uninstall` 默认 `PurgeConf=true`；`deploy.Uninstall` 透传；另保留显式 `--keep-nginx-conf`。该默认会删除 `/etc/idleleo/conf/nginx` 下用户自建片段，必须先在 CLI 输出明确提示。
  - 若不愿默认删除：改为 `Install` 记录并清理上一轮受管片段（Metadata 增加 `fragments`），卸载保留目录；但这只能防“受管片段残留”，无法防用户自建片段影响重装。
  - stop 失败且服务仍 active → 返回错误、不删树。
  - 删除失败（非 ENOENT）→ 返回错误；`UninstallReport` 增加 `Errors`。
  - `deploy.Uninstall` 在完成其余清理后 `errors.Join` 返回，CLI 退出非零。
- 测试：`TestUninstallDefaultRemovesConf`、`TestUninstallKeepsConfWithFlag`、`TestUninstallAbortsWhenStopFails`、`TestUninstallReportsRemovalFailure`。

### A3 权限失效导致 worker 读不到证书

- 现象：Go 只有 `ApplyLayeredPermissions`，没有 bash 等价的 stat 断言与 `runuser` 读写验证；证书目录若是 symlink，`paths.Join` 失败被忽略，权限被静默跳过。
- 证据：[install.go L559-L634](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L559-L634)、[L578](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L578)；bash [install.sh L4984-L5042](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/install.sh#L4984-L5042)。
- 判定：静态推断；真实 root 效果待 Block 3。
- 修法：
  - 新增 `VerifyLayeredPermissions(root) error`：binary `root:root 755`；conf/html/cert `root:idleleo-nginx 750/640`；logs/temp `idleleo-nginx:idleleo-nginx 750/640`；`root=="/"` 且存在 `xray.key` 时用 `runuser` 验证可读不可写。
  - `Install` 在权限应用后、`nginx -t` 前调用；失败回滚。
  - `certDir` 解析失败时记 warning，不再静默。
- 测试：`TestInstallFailsWhenPermissionsDrift`、`TestCertDirResolutionWarning`。

### A4 symlink 阻断安装（可用性）

- 现象：conf/html/cert/logs 下存在 symlink 时，`walkFiles` 直接报错并回滚整次安装；bash 静默跳过。证书管理工具的 `live/` 目录是典型场景。
- 证据：[install.go L636-L655](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L636-L655)；bash [install.sh L4926-L4929](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/install.sh#L4926-L4929)。
- 判定：静态推断。
- 修法：`walkFiles` 遇 symlink 跳过并 warning；非普通文件仍报错；`captureFiles` 仅对 unit/metadata 保持拒绝。
- 测试：`TestInstallToleratesSymlinkInCertDir`。

### A5 回滚提前放弃，留下半应用状态

- 现象：删除/改名新树失败、快照恢复失败、`daemon-reload` 失败都会提前 `return`，跳过后续恢复与服务状态还原。
- 证据：[install.go L873-L893](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L873-L893)。
- 判定：静态推断。
- 修法：`restore` 收集 `[]error` 并用 `errors.Join`；`daemon-reload` 失败记录后继续 enable/disable/start/stop；快照逐项恢复，不因前一项失败短路。
- 测试：注入 remove/rename/daemon-reload 失败，断言所有恢复步骤都被尝试。

### A6 同 build 重复安装不修复漂移且无谓重启

- 现象：命中同 build 直接 `ensureService`；active 时 `restart`。主配置/权限被破坏时不会修复，重复执行造成断连。
- 证据：[install.go L212-L219](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L212-L219)、[L717-L723](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L717-L723)。
- 判定：已实测“跳过配置改写”；重启行为静态。
- 修法：新增 `configDrift(root, localIP)` 检查关键指令与权限；无漂移且 active 时不动作；有漂移则重写+权限+`-t`+reload。
- 测试：`TestSameBuildDoesNotRestartActiveService`、`TestSameBuildRepairsDriftedConfig`。

### A7 Xray 失败后遗留运行中的 Nginx（提示缺失）

- 现象：Nginx 在 Xray journal 之前安装并可能已启动；后续 Xray 步骤失败只回滚 Xray，用户无提示。
- 证据：[deploy.go L237-L253](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/deploy/deploy.go#L237-L253)、[L280-L291](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/deploy/deploy.go#L280-L291)。
- 判定：静态推断。
- 修法（最小）：`fail` 闭包记录 `nginxInstalled`，错误信息追加“Nginx 已安装，可运行 uninstall 清理”；修正 [L234-L236](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/deploy/deploy.go#L234-L236) 误导注释。纳入 journal 的方案成本高，另立任务。
- 测试：注入 Xray 写文件失败，断言错误信息包含 Nginx 状态。

## 2. C 类：Go 侧独立缺陷（与 bash 无关也要修）

| 编号 | 缺陷 | 证据 | 归属 |
| --- | --- | --- | --- |
| C1 | cert 目录为 symlink 时 `Join` 错误被忽略，权限静默跳过 | [install.go L578](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L578) | 已并入 A3 |
| C2 | 卸载 stop 失败后仍删树 | [install.go L391-L397](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L391-L397) | 已并入 A2 |
| C3 | 卸载删除失败降级为 warning，退出码仍成功 | [install.go L431-L433](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L431-L433) | 已并入 A2 |
| C4 | 回滚提前返回，跳过后续恢复 | [install.go L873-L893](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L873-L893) | 已并入 A5 |
| C5 | 成功路径忽略备份删除失败，累积 `.pre-install.*` | [install.go L339-L341](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L339-L341) | 随 A5 修，记 warning |
| C6 | 403 锚点未命中时静默跳过安全指令 | [install.go L117](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L117)、[L494-L506](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L494-L506) | 已并入 A1 |
| C7 | 无 metadata 时也会停用并删除现有 `/usr/local/nginx` | [install.go L382-L387](file:///Users/yunshu/Documents/GitHub/Xray_bash_onekey/internal/nginx/install.go#L382-L387) | 与 bash 同行为；建议后续加 metadata 守卫，暂登记 |

## 3. B 类：可接受，但登记为有意分叉（写入 `docs/go/DECISIONS.md` D-023）

| 项 | Go 行为 | bash 行为 | 理由 | 影响面 |
| --- | --- | --- | --- | --- |
| manifest 校验更严 | 强制 `schema_version==1`、`size_bytes>0`、精确 size、dotted build | 只校验 arch/filename/sha/build/tag | 失败关闭，当前线上 manifest 已满足 | 未来 manifest schema 升级需同步 Go |
| 解包权限固定 | 文件 0644、`sbin/nginx` 0755 | `tar --no-same-permissions`，保留 tar 模式减 umask | 当前产物仅需 0644/0755，等价 | 产物模式变化时需调整 |
| 解包无总量/条目上限 | 单条 ≤64MB，总量/条目不限 | 无显式上限 | 压缩包受 64MB + SHA256 约束 | 供应链攻击面，后续加固 |
| HTTPS 仅校验初始 URL | 默认跟随 HTTPS→HTTP 重定向 | curl 也跟随 | 产物有 SHA256，manifest 无签名 | 加固项，后续禁止降级 |
| 建用户失败即回滚 | `ensureWorker` 失败返回错误 | 回退 `nobody` | 不回退到共享弱身份，更安全 | 极少数无 useradd 环境会安装失败 |
| 多 user 行/server_tokens | 只处理首条 user、首个 `http {` | 替换全部/插入每个 `http {` | 默认配置等价；多 http 块非标准 | 自定义配置边界 |
| `modules` 未显式 chmod | 依赖 Extract 固定权限 | 显式 755/644 | 当前产物等价 | 产物变化时需补齐 |
| `nginx -t` 带 `-p` | `-t -p <prefix>/ -c` | `-t -c` | 显式 prefix 更稳 | 需 Block 3 `nginx -V` 确认无差异 |
| 不写 `nginx_build_version` | 只写 `etc/idleleo/v1/nginx.json` | 读写 Xray 配置字段 | 两套管理器元数据独立 | Go 装后 bash 更新看不到版本；F13 前登记 |
| 无 metadata 也清理 | 会停用并删除 `/usr/local/nginx` | 同样无条件删除 | 与 bash 一致 | 可能误删独立 Nginx；后续加守卫 |
| 启动等待 5 秒 | 20×250ms | 无等价等待 | 快速失败 | 慢启动主机可能误判；Block 3 验证 |

## 4. 实施顺序（已按此顺序完成）

1. **A1** 默认 IP 403（安全默认，独立可合）。✅
2. **A2** 卸载/重装闭环（默认删 conf、`--keep-nginx-conf`、stop 失败不删树、错误传播）。✅
3. **A3 + A4** 权限验证与 symlink（证书可读、安装不中断）。✅
4. **A5** 回滚健壮性（含 C5 备份清理 warning）。✅
5. **A6** 同 build 幂等与漂移修复。✅
6. **A7** 事务失败提示与注释修正。✅
7. **CFG-1～CFG-9** Xray 协作配置对齐。✅
8. **D-023** 登记 B 类分叉。✅
9. Block 3：真实 root 安装/`nginx -V`/自启/卸载/symlink/并发/失败注入。⏳

每步完成即跑 `go test ./internal/nginx/ ./internal/deploy/`，全部完成跑 `go test ./...`。

## 4.1 Xray 协作配置对照（硬约束：功能必须一致）

对照 bash `nginx_ssl_conf_add` / `nginx_conf_add` / `nginx_upstream_conf_add` / `nginx_reality_conf_add` / `nginx_reality_servers_add` / `add_sni_guard_http_include` / `modify_nginx_origin_conf` 与 Go `internal/xraycfg`、`internal/nginx`、`internal/deploy`。

### 4.1.1 实际差异与处理（全部已实施）

| 编号 | 项 | bash | Go 修复前 | 判定 | 处理 |
| --- | --- | --- | --- | --- | --- |
| CFG-1 | TLS 80 + ACME + 跳转 | `01-xray-80.conf`：ACME root `/etc/idleleo/conf`，其余 301 | 只生成 443 server | 主功能差异（HTTP 站点/证书签发） | 新增 `buildTLSRedirectNginx`，写入 `01-xray-80.conf` |
| CFG-2 | TLS 监听 | `<port> ssl reuseport` + `[::]` + `quic` + `http2 on` | 固定 `listen 443 ssl http2` | 自定义端口失效、无 QUIC/IPv6 | 改用 `spec.PublicPort`，补齐四条 listen 与 `http2 on` |
| CFG-3 | TLS 参数 | real_ip、ciphers、ecdh、session、tickets、early_data、HSTS、403 error_page | 仅证书 + TLSv1.3 | 安全/功能差异 | 按 bash 逐项补齐 `buildNginx` |
| CFG-4 | location/代理头 | ws/grpc/xhttp 的 60s/720m、buffering off、`client_max_body_size 0`、X-Real-IP/XFF/Early-Data、`location / 403` | 精简，xhttp 误用 `proxy_pass` | **xhttp 无法工作** | 三个 location 按 bash 重写；xhttp 改 `grpc_pass grpc://xray-xhttp-server` |
| CFG-5 | upstream | `02-xray-server.conf`：`xray-{ws,grpc,xhttp}-server` include `*.<t>Servers`；`127.0.0.1.<t>Servers` 内 `server 127.0.0.1:<port> weight=50 max_fails=2 fail_timeout=10;` | 无 upstream，内联端口 | 单后端可用，但缺权重/健康与文件管理兼容 | 新增 `buildTLSServerConf`/`buildTLSServerFragments`，`location` 改指向 upstream |
| CFG-6 | Reality+Nginx stream | 协议 map（deny 非 TLS1.3）、SNI map + `*.serverNames` 白名单、`default deny`、deny upstream、`*.realityServers`、日志、`listen <port> reuseport so_keepalive=on backlog=65535` | 只有 default → 127.0.0.1，任意 SNI 直转 Xray；端口硬编码 443 | **SNI Guard 失效** | 复用 `buildRealityBalanceNginx`/`buildRealityBalanceFragments`，与 RealityBalance 主节点同构 |
| CFG-6b | Reality+Nginx 后端端口 | Xray 保持模板 9443，Nginx 占 public port | `inboundPort=spec.Port`，默认与 Nginx 同为 443（`0.0.0.0:443` vs `127.0.0.1:443` 必有一方 bind 失败） | **服务起不来** | `ModeRealityNginx` 的 `inboundPort` 固定 9443，`PublicPort=spec.Port`（分享链接端口随之正确） |
| CFG-7 | Reality 的 `03-isolate.conf` | `http{}` 后插入 include；isolate/reject 分别写 9403/9404 deny 与 isolate server | 主配置无该 include；xraycfg 不写 fragment | 隔离站点不生效 | `RewriteMainConfigWithWarnings` 插入 include + install 建占位；xraycfg 写 `03-isolate.conf` |
| CFG-8 | 受管文件清理 | 重装/切模式清理旧 `*.serverNames` 等 | `writeNginxArtifacts` 只写不删 | 旧 SNI/旧 01/02 残留，切换模式后仍被 `*.conf` 引入 | 写前删除工具自有名（01/02/03 与 `*.{serverNames,realityServers,wsServers,grpcServers,xhttpServers}`），保留 operator 文件 |
| CFG-9 | 默认证书路径 | `/etc/idleleo/cert/xray.crt|key` | `<domain>.crt|key` | 与 `schedule` 证书续期脱节，站点可能起不来 | 默认改为 `xray.crt|key`，`--cert/--key` 仍可覆盖 |

### 4.1.2 确认等价（对照证据）

| 项 | 证据 |
| --- | --- |
| `http{}` 内 `*.conf` include | bash `modify_nginx_origin_conf`：删旧 include 后在末行前插入 `include .../*.conf;`；Go `RewriteMainConfigWithWarnings` 在最后 `}` 前插入同一行（单测 `TestRewriteMainConfigHTTPMode` 断言位于 `http {` 内） |
| Reality 顶层 `00-xray.conf` include | bash `printf '\ninclude %s;\n'`；Go 追加同一行且不写 glob（`TestRewriteMainConfigStreamMode`） |
| include 去重与幂等 | 两实现均先按正则删旧行再加；`TestRewriteMainConfigIsIdempotent` 断言重复改写不产生重复行 |
| `server_tokens off` / user / worker 参数 | bash sed 与 Go 行级替换等价（`sampleMainConf` 对照测试） |
| TLS `server_name` | 均为站点域名（`spec.Domain` / `serverName`）；`root /var/www/html`、`error_page 403` 一致 |
| RealityBalance 主节点 | `buildRealityBalanceNginx`/`Fragments` 与 bash 流式模板逐行同构（既有测试 `TestGenerateRealityBalancePrimary` 断言 include、deny、isolate、片段） |
| `nginx -t` 验证覆盖 fragments | `verifyNginx` 的 http 包装现在 include `frags/*.conf`，与真实主配置的 glob 一致，upstream 引用可解析 |
| 真实安装路径 include | `deploy.Install` 先写 fragments，再 `nginx.Finalize` 执行 `nginx -t`；主配置 glob 覆盖 00/01/02 |

### 4.1.3 登记的细节分叉（不影响站点可用）

- Reality+Nginx 的 Xray inbound 用 `127.0.0.1:9443`（bash 为 `0.0.0.0:9443`）：更严格，Nginx 从回环代理仍可达。
- 非 443 公网端口时，80 跳转携带 `:port`（bash 不带，会跳到错误端口）；默认 443 完全一致。
- Stream 模式即使未知 SNI 策略为 reject 也保留空的 `03-isolate.conf` 占位：空 include 无副作用，且让“先装 Nginx、后写片段”的 `nginx -t` 通过。
- TLS 的 `location /ray/` 带尾斜杠（bash `/ray`）：前缀匹配对客户端路径等价。

## 5. 本轮不做（避免范围膨胀）

- 不逐字复现 bash 的多 user 行、每个 `http {` 插 `server_tokens`、`nobody` 回退。
- 不放宽 manifest 校验去兼容未验证的旧/未来 schema。
- 不在本轮把 Nginx 纳入 Xray journal（只做失败提示）。
- 不做 `nginx -t` 行为的真实二进制断言（Block 3）。
- 不重构产物层的解包上限/重定向策略（登记为加固项）。

## 6. 已确认的决定

- [x] A2 采用方案 1：卸载默认删除 `/etc/idleleo/conf/nginx`，新增 `--keep-nginx-conf`。
- [x] A7 只做“失败提示”，不把 Nginx 纳入 Xray journal。
- [x] B 类全部按“有意分叉”登记（`docs/go/DECISIONS.md` D-023），不逐个改齐 bash。
- [x] 按第 4 节顺序实施；Block 3 排最后。
- [x] Xray 协作路径的 nginx 配置以“功能一致”为准，见 4.1。

## 7. Block 3 只能由真实 root 确认（未通过前不得宣称等价）

1. chown/useradd/systemctl 的真实权限与服务状态。
2. `nginx -V` 的 prefix/configure 与 `-p` 影响。
3. 开机自启、5 秒 `is-active` 是否足够。
4. `/etc/idleleo/cert` 为 symlink 时的真实行为。
5. 真实卸载后的 conf 保留/删除状态。
6. 跨进程并发 install/uninstall。
