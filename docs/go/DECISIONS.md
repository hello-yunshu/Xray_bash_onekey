# Go 迁移线决策记录

## 工作约定（用户授权，2026-11-07）

Go 迁移相关工作中，**不需要用户参与排版与细节决策**。技术选型、命名、目录结构、
文档排版、补丁取舍、测试组织、提交拆分、报告格式等，由执行者自行判断并当场决定，
把决策与理由记录在本文件，不因这些细节回头征询用户。

仅在以下情况暂停并征询用户：

1. 对外发布、打 tag、合并 main；
2. 需要用户提供凭据；
3. 真实设备 / 真实 VPS 的写操作或重启服务；
4. 不可逆且有数据风险的操作。

原有约束不变：不伪造结果、不跳过失败断言、未达成项如实标注。真实 VPS 不可用时，
Docker / 容器级证据即满足验证门槛，但必须标注证据等级。

## D-001 logrotate 沙箱修复方式（2026-11-07）

**决定**：保留 nginx 日志目录 `/usr/local/nginx/logs` 不变，在生成
`/etc/logrotate.d/xray_log_cleanup` 时同时写入
`/etc/systemd/system/logrotate.service.d/10-idleleo-readwrite.conf`，内容为
`ReadWritePaths=-${nginx_dir}/logs`，并执行 `systemctl daemon-reload`。

**理由**：
- 搬迁日志目录属于日志体系重构，会破坏用户已有的 nginx 配置、外部采集与权限；
- `ReadWritePaths` 是 systemd 对 `ProtectSystem=full` 的标准例外，改动最小、可逆；
- 与仓库既有 `geodata_sandbox_allows_write` 的沙箱判定思路一致；
- 前缀 `-` 让目录不存在时（纯 Xray 用户）自动忽略，不引入额外失败。

**代价**：依赖 systemd。非 systemd 主机上 `systemctl daemon-reload` 失败被忽略，
行为退回原状，不产生新的硬失败。

## D-002 xray 侧继续使用 copytruncate（2026-11-07）

**决定**：xray 日志段保留 `copytruncate`，不增加 `postrotate`；nginx 日志段保留
`create` + `postrotate` + `nginx -s reopen`。

**理由**：Xray 没有 reopen 信号（SIGHUP 不会重新打开日志），只能就地截断；
nginx 支持 `-s reopen`，用 `create` + 精确属主比 `copytruncate` 更安全。
两个段分开书写，避免 v3.2.8 那种共享块把 xray 语义强加给 nginx。

**注意**：`copytruncate` 与 `create` 在同一段中不并存，因此不存在“二者冲突”；
`copytruncate` 本就不执行 rename，`create` 只对 rename 路径有意义。

## D-003 存量用户生效条件（2026-11-07）

**决定**：不自动改写用户已有的 logrotate 配置；修复只对“重新生成配置”生效。
存量用户需要升级到包含本修复的版本，并重新执行菜单中的「自动清理日志」设置。

**理由**：该配置文件可能被用户手工调整过，静默覆盖会丢失用户意图；把它改成
“每次升级自动重写”属于扩大变更面，本次不做。

## D-004 回归测试组织（2026-11-07）

**决定**：扩展现有 `.github/test/test_log_rotation.sh`，不新建平行测试体系；
真实 `ProtectSystem=full` 场景用特权 systemd 容器中的 `systemd-run` 复现，
输出保存在 `tests/go-parity/evidence/logrotate/`，不放进默认 CI（需要特权容器）。

**理由**：仓库约束优先复用既有测试；systemd 沙箱行为无法用纯 shell 桩可靠模拟，
但错误信息与修复效果可以用真实 systemd 一次性证明并留证。

## D-005 Phase 01 多行 diff 既保留失败又修夹具（2026-11-08）

**决定**：在 `run_phase01.sh` 的 `record()` 里对 `act` 做换行/制表符折叠，保留
完整 diff 文本但不再撑裂 TSV；C12.1/C12.2 仍为 FAIL。

**理由**：多行 `git diff` 被原样写入单行 TSV，导致一行变多行、通过/失败计数虚增
（首次复跑 33/35 但 TSV 只有 34 行）。这是夹具缺陷，不是产品失败；修复只改证据
编码，不改期望、不隐去差异。

## D-006 C12.1/C12.2 保持红色，不改 pin（2026-11-08）

**决定**：`install.sh` 因 logrotate `ReadWritePaths` 修复（`2d44d98`）比已发布
v3.3.6 pin 多 26 行；Phase 01 的这两项继续 FAIL，pin 指向发布的 `0fa7052e` 不变。

**理由**：改 pin 会把“未发布的产品改动”伪装成“与发布版一致”；C12 的价值正是
暴露这种差异。等下一次正式发版后再同步 pin，届时两项会自然转绿。

**2026-11-08 复核（capability/C12 与 pin）**：

- 当前红线是 `C12.1`（`install.sh` 字节不等于 pin）与 `C12.2`
  （`git diff pin..HEAD -- install.sh scripts config` 非空），差异为
  `install.sh | 27 +++-`（26 插入 / 1 删除），唯一来源是 `2d44d98`
  （logrotate `ReadWritePaths` 修复）。
- 哈希：pin `0fa7052e` 的 `install.sh` 为
  `a8e4d850…6797358c`，当前树为 `1a2af27e…ec72b7f`。
- `C12.3`（不得覆盖 Bash 入口）与 `C12.4`（pin 仍可加载、版本 3.3.6）仍为绿。
- **转绿条件（按优先级）**：
  1. 正式发布新版本（tag + Release），其 `install.sh` 包含该修复；随后把
     `tests/go-parity/phase01/run_phase01.sh`、`parity/scripts/run_parity.py`、
     `parity/cases/feature_contracts.json`、`parity/ci/*.yml`、
     `parity/oracle/pinned-extract.sh` 的 PIN 同步到新发布 commit，并把
     `C12.4` 期望版本改为新 `shell_version`，再在干净 checkout 重跑 Phase 01。
  2. 回退 `install.sh` 的修复（不推荐：会重新引入 logrotate 沙箱失败）。
- **不可接受的做法**：把 PIN 指向一个含修复但未发布的 commit 来“变绿”；
  那只是把当前差异合法化，失去 C12 的基线守护意义。

## D-007 TCP 原生化实现边界（2026-11-08）

**决定**：
- 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf` 一个文件，只做 `bbr-fq` 一个 profile；
- journal 先写后改，pending 标记阻断半事务再次 apply；
- 只写指定 key 到 `/proc/sys`，不重放 `sysctl --system`；
- `WriteSysctl` 使用 `O_WRONLY|O_TRUNC`（与 shell `>` 一致，sandbox 可复现 procfs 语义）；
- 回退只撤销 journal 记录的 key，第三方漂移一律拒绝；
- 锁使用独立 `run/lock/idleleo-tcp.lock`，与配置更新锁分离。

**理由**：满足“安全、轻量、可回退”，把变更面压到最小；见
[TCP_NATIVE_DESIGN_AND_QA.md](TCP_NATIVE_DESIGN_AND_QA.md)。

## D-008 Docker 只做 sandbox mock apply（2026-11-08）

**决定**：容器内 apply/rollback 通过 `--root <sandbox>` 重定向到一次性目录，
伪造 `/proc/sys` 与 marker；不写 Docker VM 内核。证据标签固定为
`DOCKER_MOCK_APPLY`，不写成宿主内核验收或性能验收。

**理由**：写容器内核会污染共享 VM，且无法证明真实 VPS 行为；sandbox 能完整验证
文件/事务/回退/漂移逻辑，同时用前后哈希证明真实 `/proc/sys` 未变。

## D-009 辅助脚本迁移取舍（2026-11-08）

**决定**：本轮只把已有 Go 原语的部分标注为已迁移/部分迁移；`ssl_update.sh`、
`fail2ban_manager.sh`、`traffic_blocker.sh`、`auto_update.sh` 的 Xray/Nginx 升级器、
Rill 安装/卸载保持 Bash。TCP 的 Bash 菜单不默认接线到 Go，只提供可审计的替代入口。

**理由**：这些脚本涉及 ACME、防火墙、权限/epoch 或混合升级器，缺少真实验证环境时
强行迁移会制造“看起来迁移了”的假象；详见
[SCRIPT_NATIVE_MIGRATION_MATRIX.md](SCRIPT_NATIVE_MIGRATION_MATRIX.md)。

## D-010 部署回滚补齐属主/链接/父目录，并增加跨进程 journal/lock（2026-11-08）

**决定**：
- `internal/deploy` 的文件快照扩展为 `uid/gid/link/exists/missingDirs`，回滚恢复
  mode、属主、符号链接与父目录副作用；新装失败显式 `stop + disable`，移除 unit 后
  `daemon-reload` 并校验 `is-enabled`。
- 增加持久事务 journal `var/lib/idleleo/deploy/journal.json` 与
  `snapshot/entry-N`：安装前 fsync `PREPARED`，成功写 `COMMITTED`；
  `PREPARED/ROLLING_BACK/RECOVERY_REQUIRED` 由下一持锁进程逆序还原，失败保留
  `RECOVERY_REQUIRED` 并提供 `idleleo xray recover`。
- `Install`/`Uninstall`/`Recover` 共用 `host.AcquireUpdate` 排他锁；journal 只存
  相对路径，恢复时拒绝绝对路径与 `..` 越界。
- 验证边界：容器内真实 `kill -9`（写入中途）→ 新容器 `recover` 收敛，
  证据等级 `DOCKER_CRASH_INJECTION`；未做真实 VPS 断电/重启，不据此升格签收。

**理由**：属主/链接/父目录是已复现的真实缺陷；跨进程恢复由持久快照 + 锁 +
显式恢复入口构成，先写 journal 再改 live 状态的顺序可以由同进程失败测试与
真实 SIGKILL 注入共同验证，且不需要新框架。

## D-011 `tcp.sh` 只审计入口与风险，不承诺固定版本逐行等价（2026-11-08）

**决定**：`install.sh` 的 `bbr_boost_sh` 会优先执行本地 `scripts/tcp.sh`，否则
下载上游 Linux-NetSpeed 脚本并直接以 root 执行，无 pin、无哈希。本轮取
2026-11-08 快照（SHA-256 `0b7614e7…2ea61c0`）逐类审计内核安装/reboot、
`sysctl.conf` 改写、systemd/PAM/profile、IPv6、远程 lotServer 与内核卸载，
证据落盘 `tests/go-parity/evidence/tcp-upstream-2026-11-08.txt`。

**理由**：上游脚本不在仓库，无法证明“任意时刻下载到的内容”逐行等价；只能审计
入口与已知快照。Go 只实现 `bbr-fq` 安全子集，不移植 `wget | bash`。

## D-012 矩阵 after-fix 证据必须在真实 commit 重跑（2026-11-08）

**决定**：复检发现旧 `after-fix/environment.txt` 记录 `repo_commit=7b15c83…`，
该对象不存在于仓库。改为在真实 HEAD `ace4a16` 上用仓库修正版
`tests/go-parity/matrix/run_matrix.py`（bind-mount 覆盖缓存镜像内构建时烤入的旧
副本）重跑，状态仍为 `54/32/8/4`，替换 summary/environment；缓存镜像旧脚本的
`13/32/44/5/4` 结果明确标注不得作为证据。

**理由**：证据必须可追溯到真实提交；缓存镜像不会自动更新 `COPY` 进去的脚本，
直接运行会得到假阴性。以后矩阵复跑必须显式 bind-mount 仓库脚本或重建镜像。

## D-013 多入口用相邻端口生成，按拓扑而非单一 network 校验（2026-11-08）

**决定**：
- `--transport ws+grpc+xhttp` 在主端口建主 inbound，其余入口使用相邻端口
  （65535 附近回绕），保持产物可复现；Bash 的随机端口不复制。
- none/TLS 主入口为 ws、附加入口绑定 `127.0.0.1`；Reality 主入口为 raw、
  附加入口沿用主监听地址（对齐 Bash `reality_add_more` 的 0.0.0.0 行为）。
- 矩阵对多入口不再比较单一 `streamSettings.network`，而是要求 3 个 inbound、
  网络集合为 ws/grpc/xhttp、端口互异；这是增强校验，不是放宽断言。

**理由**：多入口天然不是单流配置；把 `network` 写成 `ws+grpc+xhttp` 会让
Xray 拒绝配置。用拓扑断言可以在不牺牲真实配置合法性的前提下覆盖原 8 个
`GAP`，并由真实 Xray `-test` 与 A2 真实 runtime 双重验证。

## D-014 主备负载均衡按 Bash 的 primary/secondary 角色建模（2026-11-08）

**决定**：
- `--mode reality-balance --role primary|secondary`；角色必须显式给出。
- primary：Xray Reality 保持模板 `9443/0.0.0.0`，Nginx stream 监听用户端口；
  `--backend host:port` 可重复，默认 `127.0.0.1:9443`，片段行固定
  `weight=50 max_fails=2 fail_timeout=10`，与 `file_manager.sh` 一致。
- secondary：Xray Reality 监听用户端口，不生成 Nginx 产物；secondary 带
  `--backend` 直接拒绝。
- 9403/9404/9443/9444 对所有 Reality 模式作为用户端口一律拒绝（Bash
  `reality_reserved_port_conflict` 语义）；`decoy` SNI 策略需要外部站点产物，
  Go 生成器明确拒绝而不是静默降级。
- Nginx stream 模板、include 路径、日志路径、isolate 站点均按安装态的
  `/etc/idleleo/conf/nginx` 与 `/usr/local/nginx/logs` 输出，保证可直接
  与 Bash 产物逐字节比较。Go 不代管 `nginx.conf` 主配置，这是已知 CORE。

**理由**：双机无法在当前环境复现，但 Bash 语义可完整抽取；把“角色 + 后端
片段 + stream 规则”作为纯产物生成，再用真实 Nginx 做 SNI/协议/默认拒绝的
容器级验证，能覆盖除宿主 Nginx 主配置接线外的全部连接语义。

## D-015 ACME 原生客户端以 Pebble 本地 CA 验收（2026-11-08）

**状态**：协议实现部分由 **D-020**（lego 库模式）取代；本条的验收环境、显式目录
URL、证据标签与“不得据此升格”约束继续有效。

**决定**：
- 新增 `internal/acme`，用 stdlib 实现 ACME v2（ES256 JWS、nonce、账户、
  订单、HTTP-01、CSR、finalize、证书下载）；新增 `idleleo xray cert
  issue|renew`，目录 URL 必须显式传入，避免隐式访问公网 CA。
- 验收环境固定为 Pebble 容器 + 自签 `pebble.minica.pem`（仅保护 ACME 服务端
  TLS），HttpPort 5002，域名用 Docker 网络别名 `acme.local`，不发布宿主端口。
- 证书链验证对象是 Pebble 管理接口 `/roots/0` 返回的**动态根**，不是
  `pebble.minica.pem`；后者只签服务端证书。
- 证据标签固定为 `ACME_LOCAL_CA`；不得据此把 F12 或 F01–F28 升格为
  `REAL_VPS_VERIFIED`。

**理由**：本地 CA 能真实执行协议状态机（账户/订单/挑战/签发/续期），比桩服务
更能暴露 JWS、nonce、CSR、链下载问题；但公网 CA、DNS-01、EAB、真实 DNS 与
Bash 的 `idleleo-nginx` 组/重启语义仍不在本次范围内，必须如实标注。

**已知差异**：Bash 用 `acme.sh` 先 staging 测试再正式签发，reloadcmd 内置
`chown root:idleleo-nginx`、`chmod 640` 与重启 nginx/xray；Go 只做协议与落盘，
权限/服务编排由调用方通过 `--reload-command` 提供。

## D-016 既有运行配置只能显式接管或显式改写（2026-11-08 收尾轮）

**决定**：
- 安装/迁移遇到已存在的 `config.json` 一律 fail-closed：要么
  `--keep-config` 原样接管，要么 `--rewrite-config` 显式替换；没有第三个默认路径。
- 新增 `idleleo xray generate --from-config <path> --out <path>`：只重排缩进，
  端口、listen、路径、UUID、flow、Reality privateKey/shortIds/serverNames、
  证书路径与自定义字段全部原样保留；`--out` 必填、已存在需 `--force`、落盘 0600。
- 接管前拒绝不可运行配置（无 inbound、端口越界、重复 tag、重复
  `listen:port`、非法 UUID、未知 security、非法 Reality key），避免把坏配置
  带进托管态。

**理由**：迁移最危险的失败不是报错，而是“看起来成功但把用户的端口/UUID/
Reality 身份换掉了”。拒绝必须发生在任何写盘之前；显式开关把决定权交回操作者。

## D-017 Nginx 必需模式没有真实前端就拒绝安装（2026-11-08 收尾轮）

**决定**：
- `tls`、`reality-nginx`、`reality-balance --role primary` 必须同时给出
  `--external-nginx-managed` 与 `--nginx-bin`，否则安装在任何落盘前返回错误。
- 生成的 `00-xray.conf` 与全部片段写入 `/etc/idleleo/conf/nginx` 后，用真实
  `nginx -t` 在临时 root 内验证；验证失败触发整体回滚。
- `ssl_reject_handshake` 只从 `http{}` 引入：它属于 `ngx_http_ssl_module`，
  Bash 的 isolate 站点就是 http 片段，绝不能塞进 `stream{}`。
- 只有 `nginx -t` + 容器 e2e 都通过时，报告才允许出现“已管理 Nginx”；
  两者都不等于生产可用，e2e 标签固定为 `REAL_NGINX_REAL_XRAY_E2E`（container）。

**理由**：只生成片段 + `xray -test` 不能证明主备可用。缺少前端时“成功”只是
幻觉；必须先拒绝，再把能验证的部分（语法、SNI 分流、故障切换）用真实进程验证。

## D-018 ACME 证书对按单事务发布（2026-11-08 收尾轮）

**决定**：
- 证书与私钥都先写临时文件并 `fsync`，证书 `rename` 成功后再 `rename` 私钥；
  私钥失败即恢复旧证书，绝不出现“新证书 + 旧私钥”。
- `--reload-command` 失败时恢复**整对**旧证书并返回错误；回滚本身失败时
  错误信息必须写明，不能宣称已恢复。
- HTTP-01 token 先按 base64url 字母表校验，再拼进 webroot 路径。
- 权限：证书 `0644`、私钥 `0600`（含账号私钥）；负面证据必须覆盖
  webroot 失效、reload 失败、只读目标、CA 拒绝。

**理由**：证书更新是典型的“部分成功最危险”操作。任何一步失败后，
磁盘上必须仍是更新前可用的那一对；只有真实负面路径能证明这一点。

## D-019 S0–S3 收口：真实根变更、门禁解耦与历史重写（2026-11-11）

**决定**：

- **真实根变更**（S2）：`change port` / `change user` 允许在真实根执行，但必须先过
  `RequireSystemWrite`（真机写入需双确认）并写审计日志；事务记录落在
  `var/lib/idleleo/transactions/phase01.json`，有界且不含配置字节/密钥；崩溃用
  `change recover` 重放，失败回滚。此前“Phase 01 只能写 sandbox 根”
  （`host.RequireSandbox` 对变更路径的约束）**由本条取代**：sandbox 仍是测试入口，
  但不再是变更的唯一入口。
- **门禁解耦**（S3）：preview qualification 与 release qualification 分离；开发产物
  走 `go-native-artifacts.yml`，固定标注 “NOT FOR RELEASE”；preview 失败不得阻断
  开发产物，但 preview 绿也不等于发布资格。
- **历史重写**（S0 延伸）：2026-11-11 一次性重写了全部分支与 tag 的历史，替换真实
  主机地址、用户名与主机路径。pin / baseline 随之更新到重写后的 v3.3.6 对象
  `3b2a5045…`（`install.sh` 字节未变）；C12 保持**已知 pin 不匹配**，不为了变绿去
  改基线。对外证据必须写明“历史已重写，此前暴露不可撤回”，不得声称彻底清除。

**理由**：真实根变更是生产可用性的必要条件，但必须用门禁、审计、事务与恢复来换取；
把 preview 与 release 绑在一起，会让开发通道被发布门禁误伤。历史隐私则只能重写 +
诚实披露，PUBLIC 仓库的服务端缓存不在本地可控范围。

**已知偏差**：审计备忘把被 S2 取代的规则记作 “D-015”，但本文件的 D-015 是
“ACME 原生客户端以 Pebble 本地 CA 验收”，仍然有效、未被取代；实际被取代的是
上文所述 sandbox-only 写入约束。详见 `CLOSEOUT_S0_S3_2026-11-11.md`。
（S5 补充：D-015 的**协议实现**已由 D-020 取代，验收与标签约束仍有效。）

## D-020 S4/S5：lego 库模式取代 stdlib ACME 协议实现（2026-11-11）

**决定**：
- 依赖采用 `github.com/go-acme/lego/v5 v5.6.0` 的**库模式**，不引入 lego 外部
  二进制，不调用 `acme.sh`；`go mod vendor` 只落实际 import 的包（9 个模块、
  13MB / 812 文件），空模块缓存 + `GOPROXY=off` 可完成 `go build` / `go test`。
  早期“lego 要求 Go 1.26、只能用外部二进制”的结论随 Go 1.27.4 升级作废。
- `internal/acme` 的协议层（账户、订单、JWS/nonce、HTTP-01、CSR、finalize、
  证书下载）改由 lego 承担；本仓库保留并继续测试：显式目录 URL、账户密钥/状态
  （0600）、webroot token 的 base64url 校验、证书对单事务发布（temp+fsync+
  rename，证书 0644 / 私钥 0600）、reload 失败整对回滚、安装失败恢复旧证书。
- 验收不变：Pebble 本地 CA，证据标签 `ACME_LOCAL_CA`，不得据此把 F12 升格；
  F12 继续 `PENDING_GO_IMPLEMENTATION`（缺公网 CA、DNS-01/EAB、真实域名）。
- 诊断字段变化：lego 不暴露订单 URL，`Result.OrderURL` 保留但为空，CLI 仅在
  非空时打印；JSON 字段名不变。
- lego 默认日志写 stdout，会污染 `--json`；本仓库在构建客户端时把 lego 日志改到
  stderr。
- `tests/go-parity/acme/run_acme_container.sh` 的 Go 镜像默认改为
  `golang:1.27.4`（旧 matrix 镜像是 Go 1.23，无法构建本仓库），并把
  `PEBBLE_AUTHZREUSE` 默认设为 0，使 webroot 失败负面用例可确定复现。

**理由**：lego 是被广泛审计的 ACME 实现，可减少自研 JWS/订单状态机的协议风险；
但证书落盘的事务、权限与回滚是本项目对用户的责任，不能外包给库。vendor 保证
离线可构建，且不引入 lego 的全部 DNS provider。

**已知边界**：本轮只完成协议层替换与本地 CA 全流程/负面验收，不等同于 F12
签收；`acme.sh` 入口与 cron 仍属 S7，未删除。
