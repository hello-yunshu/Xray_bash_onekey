# 优化计划实施状态（v2.1）

本文件记录《Xray_bash_onekey 优化计划｜审计补全版 v2.1》各阶段在本仓库中的实际实施情况。
依据为仓库当前源码，不沿用旧行号。

---

## 阶段 01｜证书恢复与安全基线

**状态：代码完成并通过本地自动化验证；实机（真实 Linux + systemd + Nginx + Xray）验证待补**

基线提交：`c6a039f`（main）
工作分支：`feat/stage1-cert-recovery-security-baseline`

### 1. 证书更新的服务状态恢复

改动文件：`scripts/ssl_update.sh`、`install.sh`

`scripts/ssl_update.sh` 重写为「先预检 → 单一恢复出口」的结构（行为等价的功能拆分，不改变签发方式）：

- **预检前置**：`install_config.json`、`host`、可执行的 `acme.sh`、证书目录、
  `idleleo-nginx` 组全部在停止 Nginx **之前** 校验；任一项缺失直接非零退出，Nginx 不受影响。
  原脚本把组检查放在 `installcert` 之后，组缺失时退出会让 Nginx 留在停止状态。
- **状态记忆与单一恢复出口**：仅当本进程确实停止了一个原本 `active` 的 Nginx 时，
  才在失败分支重新启动它；原本停止的 Nginx 在任何分支（失败或成功）都不会被启动。
  恢复后再次校验 `is-active`，恢复失败返回退出码 **2** 并打印 `systemctl start nginx` 的处理指引；
  普通失败返回 **1**。
- **并发互斥**：保留原有 `ssl_update_running` 目录锁，并额外获取与 `install.sh` /
  `auto_update.sh` / `geo_update.sh` 相同的 `/run/lock/idleleo-update.lock`，
  避免证书续签与 Nginx/Xray 升级互相重启；无 `flock` 时退化为仅目录锁。
- **不重复重启**：Xray 仅在续签前处于 `active` 时重启一次；Nginx 只 `start` 一次（且仅当被本进程停止）。
- `SIGINT`/`SIGTERM` 经 `EXIT` trap 复用同一恢复逻辑，异常中断也会尝试恢复 Nginx。
- 路径支持环境变量覆盖（`IDLELEO_DIR` / `IDLELEO_CERT_DIR` / `IDLELEO_ACME_HOME` /
  `IDLELEO_NGINX_UNIT` / `IDLELEO_XRAY_UNIT` / `XRAY_UPDATE_LOCK_FILE`），默认值与生产路径完全一致，
  仅为可测试性引入（与 `scripts/geo_update.sh` 的既有风格一致）。

`install.sh`：

- `check_cert_status()` 不再在调用前 `systemctl stop xray`，服务状态处理统一收敛到 `cert_update_manuel()`。
- `cert_update_manuel()`：域名、证书目录、worker 组、`acme.sh` 全部前置校验；记录 Xray 原有运行状态，
  任一环节（ACME 续签 / installcert / 权限 / 重启）失败都恢复原有运行状态并返回非零；
  非 TLS 模式明确返回非零。
- `--reloadcmd` 只保留证书 `chown`/`chmod`，去掉其中的 `systemctl restart nginx && systemctl restart xray`：
  该钩子会被 acme.sh 持久化并在每次自动续签时重放，与脚本自身的重启叠加会造成重复重启。

### 2. Xray 日志权限收紧

改动文件：`install.sh`（`xray_privilege_escalation()`）

- `/var/log/xray` 目录 `755 → 750`，日志文件 `644 → 640`，属主仍为该 unit 的实际服务账号（`xray` 或 `root`），
  因此服务账号可写、同组可读，其他本地用户不可读。
- 兼顾既有机制：logrotate 使用 `copytruncate` 且以 root 运行；脚本的诊断/清理以 root 运行；
  未扩大任何 `/etc/idleleo` 或私钥目录权限。

### 3. 新建无 TLS 后端默认监听

改动文件：`install.sh`

- 新增 `ws_backend_listen_default()` / `is_valid_listen_address()` / `resolve_ws_backend_listen_addr()`。
- `modify_listen_address()` 在 `tls_mode=None`（即 ws/gRPC/xHTTP ONLY）分支改为使用上述解析结果，
  默认 `127.0.0.1`；`WS_BACKEND_LISTEN_ADDR` 或向导输入可显式指定其他（可信内网）地址，非法值回退回环并告警。
- 交互向导 `menu_install_transport` 增加 `ws_listen_address_choose()`：默认回环，需显式同意才输入其他地址。
- `install_xray_ws_only()` 在生成配置前归一化该值，确保不会落回 `0.0.0.0`。
- **已有安装不被改写**：`modify_listen_address()` 只在模板重建路径（全新安装 / `standard_rebuild` / `mode_switch`）
  被调用；`install.sh -u` 升级与 keep-config 重装路径都保持 `config.json` 中已有的 `listen`。
- **不误伤安全入站**：TLS 分支仍为 `127.0.0.1`，Reality 入站与其附加后端监听逻辑未改动。
- 提示文案：`basic_information()` 在 None 模式下增加实际 `listen` 行，并明确
  「没有传输层加密（VLESS 载荷自身仍有加密）」与「仅监听本机时的外界接入说明」；
  安装菜单由「无 Nginx、无 TLS」改为「无 Nginx、无传输层加密 / 仅限可信后端」；
  `--help` 的 `-3` 说明补充「默认仅监听 127.0.0.1」。

### 国际化

- 新增 msgid 已写入 `i18n/po/en.po`（22 条英文）并重新编译
  `i18n/languages/en/LC_MESSAGES/xray_install.mo`。
- 其余语种由仓库既有的 `Update Translations` workflow 在合入 main 后自动生成，本阶段未刷新全仓翻译产物。

### 本阶段验证（已执行）

环境：macOS 开发机（bash 3.2 / jq / msgfmt / shellcheck），**未接触任何生产服务器**。

| 命令 | 结果 |
|---|---|
| `bash -n install.sh`、`bash -n scripts/ssl_update.sh` | 通过 |
| `shellcheck -S error`（install.sh、ssl_update.sh、四个测试脚本） | 无 error 级问题 |
| `bash .github/test/test_ssl_update_recovery.sh` | **28 passed / 0 failed** |
| `bash .github/test/test_cert_update_recovery.sh` | **14 passed / 0 failed** |
| `bash .github/test/test_ws_only_listen_address.sh` | **22 passed / 0 failed** |
| `bash .github/test/test_xray_service_user_permissions.sh` | 12 passed / 0 failed（含新增 3 条日志权限断言） |
| `bash .github/test/test_install_menu_profiles.sh` | 229 passed / 0 failed（更新 ONLY 模式文案与新增监听地址断言） |
| `test_redact / test_phase1_safety / test_bootstrap_dependencies / test_shell_bootstrap_ordering / test_xray_installer_metadata / test_vps_auto_update_schedule / test_version_loading / test_reinstall_preservation / test_reinstall_call_chain / test_reality_nginx_feedback / test_nginx_update_rollback / test_nginx_tar_security / test_port_validation / test_firewall_reconcile / test_input_eof / test_shell_update_metadata / test_dual_stack / test_dns_multi_record / test_release_reconciliation` | 全部 exit=0 |
| `bash scripts/ssl_update.sh`（直接执行 + 假根目录 + 失败 stub） | 退出码 1、错误上报正确、锁目录已清理 |

失败但**与本阶段无关**（在未修改的 `main` 上以完全相同方式失败，属 macOS 本地环境限制）：
`test_xray_update_transaction.sh`、`test_xray_version_pipefail.sh`、`test_log_rotation.sh`。

### 未执行 / 待实机验证

- `sudo bash .github/test/test_nginx_security.sh`、`sudo bash .github/test/test_xray_runtime_permissions.sh`、
  `sudo bash .github/test/test_install.sh <mode>`（需要 root + Linux + 真实 Xray/Nginx/systemd）。
- 真实 Linux 主机上：TLS 节点证书续签失败后 Nginx 恢复、`/var/log/xray` 权限下 Xray 正常写日志、
  全新 ws/gRPC/xHTTP ONLY 安装后 `ss -ltn` 仅见 `127.0.0.1`。
- 上述项目在 CI（ubuntu-latest）会随既有 `Test Install` workflow 执行；未运行前不得视为通过。

### 风险与遗留

1. 真实 Linux 运行时行为（systemd、logrotate、acme.sh 真实续签）尚未实机验证。
2. 新建 None 模式默认仅监听回环后，若用户需要公网可达需显式指定地址（向导或 `WS_BACKEND_LISTEN_ADDR`）；
   分享链接仍按公网地址生成，仅监听回环时会不可直连——已在安装完成信息中明确提示。
3. `--reloadcmd` 去掉服务重启后，若用户只依赖 acme.sh 自身定时任务（未使用本项目的
   `ssl_update.sh` cron）续签，服务不会自动重启；本项目的 TLS 安装始终会写入 `ssl_update.sh` cron。
4. 纯中转角色（阶段 02）尚未实现，证书路径对纯中转的跳过逻辑留待阶段 02 处理。

### 本阶段提交

`ac63aa7`（本地提交，位于分支 `feat/stage1-cert-recovery-security-baseline`；未推送、未合并、未发布）。

### 下一阶段准入

可以进入阶段 02（代码与本地自动化验证已完成）；阶段 02 完成后应连同本阶段一起补一次真实 Linux 冒烟验证。

---

## 阶段 02｜取消 XTLS ONLY 与中转节点

**状态：代码完成并通过本地自动化验证 + 真实 Nginx 二进制 Stream 实测；真实落地站端到端 REALITY 联通待实机验证**

基线提交：`d7c4e50`（阶段 01 之后）
工作分支：`feat/stage1-cert-recovery-security-baseline`（阶段 02 在同一分支上独立提交）

### 1. 取消 XTLS ONLY（精确作用域）

| 对象 | 处理 |
|---|---|
| `config/vless_xtls.json` | 删除（`git rm`） |
| `install_xray_xtls_only()` / `install_config_xtls_only()` | 删除 |
| `xtls_only` 安装档位 | `apply_install_profile` / `install_wizard_preset` 分支删除 |
| CLI `-4` / `--install-xtls` | 从帮助与分发中移除；保留一个显式拒绝分支，输出「旧版 XTLS 模式 (已取消)」并返回 1（不再落入主菜单） |
| 安装菜单第 3 项 | 改为「中转节点 (Nginx Stream TCP 转发)」→ `menu_install_relay` |
| XTLS 专属分支 | `modify_listen_address` / `modify_inbound_port` / `xray_conf_add` / `generate_vless_link` / `install_link_image` / `basic_information` / `show_user` / `add_user` / `remove_user` / `reset_port` / `old_config_input` / `nginx_update` / `check_program` / `check_xray_local_connect` 等全部 XTLS 专属判断删除 |
| 文档 / i18n | `README.md` 与 5 个语种 README 的模式列表改为「中转节点」；`i18n/po/*.po` 与 `xray_install.pot` 删除「下载 Xray XTLS 配置」条目；`en.po` 新增 73 条阶段 02 文案并重编译 `en.mo` |

**未误删通用能力**：`xtls-rprx-vision`（VLESS Vision 流控）、Reality（`realitySettings`、`nginx_reality_conf_add`、
`install_xray_reality`、SNI Guard）全部保留，由 `test_relay_node.sh` 的 A2 组断言守住。

**旧用户不被破坏**：更新脚本不删除任何旧 XTLS 安装正在运行的文件/服务；`tls_mode == "XTLS"` 时置
`legacy_xtls_only="on"`，`old_config_exist_check()` 遇到旧 XTLS 安装**拒绝重装**并提示该模式已取消
（不做迁移向导、不自动改写用户配置）。

### 2. 新增「中转节点」独立服务器角色

只用项目自发布 Nginx（其编译参数已实测包含 `--with-stream`）做**单目标 TCP 透明转发**：

```
stream {
    server {
        listen <监听地址>:<监听端口>;
        proxy_pass <落地地址>:<落地端口>;
        proxy_connect_timeout 10s;
        proxy_timeout 720m;
        proxy_socket_keepalive on;
    }
}
```

- **不装 Xray**：`install_nginx_relay()` 全链路不调用 `install_xray_*` / `UUID_set` / 不写 `config.json`；
  `test_relay_node.sh` 对 `relay_*` 整个函数族做静态扫描，确保没有任何 Xray 安装或 UUID 生成调用。
- **不终止 TLS/Reality**：片段内无 `ssl_*`、无 `reality`、无 `proxy_protocol`（不默认 PROXY Protocol）。
- **不收集落地凭据**：向导只问落地地址、落地端口、本机监听端口，监听地址（IPv4/IPv6）为可选高级项；
  不询问私钥、不询问 SSH。
- **单目标**：无多落地、无 UDP/QUIC、无智能分流、无同机混装（超出第一版范围的一律不做）。

### 3. 角色持久化与生命周期分支

`/etc/idleleo/conf/install_config.json` 新增：`role`、`relay_backend_host`、`relay_backend_port`、
`relay_listen_port`、`relay_listen_addr`、`relay_enabled`、`nginx_build_version`；
**纯中转配置中不写入 `xray_version`、`tls` 为 `None`、无 `id`（UUID）**。

- `judge_mode()`：读取 `role`；为 `relay` 时走 `_relay_state_load`（把 `port` 同步为监听端口以便共享健康检查）
  并**提前 return**，不进入 Xray 模式判定。
- 角色分支：`nginx_update` → `nginx_update_relay`；`uninstall_all` → `relay_uninstall`；`menu` → `menu_relay_main`；
  `basic_information` → `relay_basic_information`；`check_program` / `check_xray_local_connect` / `install_link_image` 跳过；
  `dependency_install` / `collect_new_managed_ports` / `enable_process_systemd` / `disable_process_systemd` /
  `stop_service_all` / `service_restart|start|stop` 均按角色最小分支。
- **无 `judge_mode` 的离线路径**（`--service-restart`、`--purge` 等）由 `relay_bootstrap_role()` 直接从配置恢复角色，
  不会回落到 Xray 代码路径。
- 纯中转菜单不出现 Rill / Xray 用户/UUID/链进入口（由 `test_relay_node.sh` 断言）。
- `show` / `status` 输出中转入口、落地、转发方式、启用状态，并明确「客户端只改地址和端口，
  REALITY 公钥/SNI/ShortId 不变」「TCP 可达 ≠ REALITY 握手成功」「本机不装 Xray、不终止 TLS、不保存落地私钥」。

### 4. Nginx 配置存活

- **独立受管片段**：`${nginx_conf_dir}/relay-stream.conf`，由 `relay_render_stream_conf()` 纯函数生成。
  该文件**故意不加入 `managed_nginx_files`**：节点重装不会静默删除它，改由 `relay_preflight()` 明确拒绝。
- **唯一 `stream` 上下文**：只在主配置**顶层**追加 `include <片段>;`（`nginx_relay_main_conf_prepare`）；
  若主配置已存在用户自己的顶层 `stream {` 块，直接拒绝并在提示中要求手工处理，绝不重复定义。
  绝不放“普通受管站点”目录逻辑里——那里被 `http {}` 包含。
- **拒绝混装**：`relay_preflight()` 拒绝普通节点安装（存在 `config.json` / 受管站点 / 非 relay 的 `install_config.json`）
  和已有 Xray 配置；自身重配置（`role=relay`）放行。
- **事务化写入**：`nginx_relay_apply_config()` = 备份旧片段 + 记录 Nginx 运行状态 → 写片段 → 挂 include →
  `nginx -t` → 通过后才 `reload`/`start`；校验或启动失败调用 `_relay_apply_rollback()` 恢复旧转发
  （首次安装失败则删除片段与 include）。
- **Nginx 更新/恢复不丢配置**：`nginx_update_relay()` 在替换二进制后依次
  `relay_stream_conf_write_current` → `nginx_relay_main_conf_prepare` → `nginx -t` → `activate_nginx_update`，
  任一步失败走 `recover_failed_nginx_update` 回滚到旧版本。
- include 的剥离改用 `awk`（`nginx_relay_main_conf_strip`）而非 GNU-only 的 `sed` 备用分隔符，
  生产与开发主机行为一致，且原地写回保留文件属主与权限。
- 落地地址校验 `relay_is_valid_host()`：IPv4/IPv6 字面量或 DNS 名；拒绝空值、超长（>253）、
  含空格/`;`/`{}`/引号/换行的注入串、`a..b`、`-bad-`、以及纯数字（避免 `proxy_pass 443:443` 的歧义）。

### 本阶段验证（已执行）

环境：macOS 开发机（bash 3.2 / jq / shellcheck / Docker for arm64），**未接触任何生产服务器**。

| 命令 | 结果 |
|---|---|
| `bash -n install.sh`、`bash -n .github/test/test_install.sh`、`bash -n .github/test/test_relay_node.sh` | 通过 |
| `shellcheck -S error`（install.sh 与 4 个改动测试脚本） | 无 error 级问题 |
| `bash .github/test/test_relay_node.sh`（新增） | **112 passed / 0 failed** |
| `bash .github/test/test_install_menu_profiles.sh` | **221 passed / 0 failed**（8 档位、`menu_action 6` 改为中转语义、`menu_install` 第 3 项 rc 透传） |
| `bash .github/test/test_reinstall_call_chain.sh` | **160 passed / 0 failed**（S17 由 4 条链改 3 条、S20 去掉 XTLS 链） |
| `test_redact / test_ws_only_listen_address / test_firewall_reconcile / test_phase1_safety / test_nginx_health_production_defaults / test_ssl_update_recovery / test_cert_update_recovery / test_dual_stack(_runtime) / test_firewall_family_transition / test_xray_service_user_permissions` | 全部 exit=0 |
| 全量批量运行 48 个可本地运行的测试脚本 | 仅 6 个失败，且**在未修改的 `main` 工作树上以完全相同方式失败**（`flock` 缺失 / 需要 sudo 终端 / 需要参数），与本阶段无关 |

**真实 Nginx 二进制实测（Docker，arm64 Debian）**：

1. 下载仓库自发布产物 `xray-nginx-custom-arm.tar.gz`（Release `v2026.07.15.6961`，即 API 的
   `nginx_build_tested_version`），`nginx -V` 确认包含 `--with-stream`（含 `stream_ssl`、
   `stream_ssl_preread`、`stream_realip`）——中转方案的前提成立。
2. 用**真实函数** `relay_render_stream_conf 0.0.0.0 15001 127.0.0.1 15002` 生成片段，
   在主配置**顶层** `include`，本地起一个 HTTP 后端：
   - `nginx -t`：`syntax is ok / test is successful`
   - 通过 `127.0.0.1:15001` 取到后端内容：`http_code=200 body='RELAY-OK'`
   - 裸 TCP 首行：`b'HTTP/1.0 200 OK'`（即字节级透传，非 HTTP 反代）
3. IPv6 片段（`listen [::]:15003; proxy_pass [::1]:15002;`）同样 `nginx -t` 通过。
4. 反证：把 `stream {}` 写进 `http {}` 内，`nginx -t` 报
   `"stream" directive is not allowed here` —— 证明「必须顶层 include」的设计约束成立。

### 未执行 / 待实机验证

- `sudo bash .github/test/test_install.sh relay`（需要 root + Linux + systemd + 真实下载 Nginx 发布包）：
  已在 CI 矩阵中用 `relay` 取代 `xtls_only`，未运行前不得视为通过。
- **真实落地站端到端联通待验证**：本阶段只证明了「本机 Nginx Stream 能把 TCP 字节转发到本地后端」，
  没有、也无法在开发机验证「经中转节点连到真实落地 VPS 后 REALITY 握手成功」。
- 真实 Linux 主机上：Nginx 更新（换二进制）后中转配置与 include 是否仍在、`recover_failed_nginx_update`
  回滚是否保留旧转发、卸载中转后 `uninstall_nginx` 与主配置残留状态。

### 风险与遗留

1. 中转为单目标透明转发：落地更换需在菜单里改目标（`relay_modify_target`），不支持多落地/分流/UDP。
2. 落地地址若为域名，Nginx 在启动时解析并在解析失败时启动失败；域名 IP 变更后需重启 Nginx 才生效。
3. `proxy_timeout 720m` 与 `proxy_socket_keepalive on` 只解决长连接空闲；不解决落地侧限速/审计。
4. 如果用户手工在主配置写了自己的顶层 `stream {}`，中转安装会被拒绝（设计如此），需要人工合并。
5. 中转节点与普通节点不允许同机混装；`relay_preflight` 只做“拒绝”，不提供自动迁移。
6. 阶段 01 遗留的第 4 条（纯中转跳过证书路径）随本阶段落地：中转安装全程不触碰证书目录。

### 本阶段提交

独立提交（本地，位于分支 `feat/stage1-cert-recovery-security-baseline`；未推送、未合并、未发布）。

### 下一阶段准入

阶段 02 代码与本地自动化验证已完成，可进入阶段 03；进入前建议先在真实 Linux 上跑一次
`test_install.sh relay` 与一次「中转 → 真实落地 REALITY 客户端连测」，把上面两条待验证项补齐。
