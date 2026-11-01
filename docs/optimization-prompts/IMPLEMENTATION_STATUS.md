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

**整机安装 / 生命周期实测（Docker，arm64 Debian 12 + `docker/fake-systemctl`）**

在容器内以 root 跑完整 Linux 安装链路（真实 apt、真实 Nginx 发布包下载与 SHA256 校验、
真实服务启停），不是函数级模拟：

| 场景 | 命令 | 结果 |
|---|---|---|
| 中转节点完整安装 | `bash .github/test/test_install.sh relay` | **29 passed / 0 failed**（Nginx v2026.10.15.7679 下载→校验→安装→启动，入口端口监听，`curl` 经中转取到后端内容；无 Xray 二进制/服务/配置/UUID，`nginx -t` 通过，分层权限校验通过） |
| 中转全生命周期 + 混装守卫 | `bash .github/test/test_relay_container.sh all` | **80 passed / 0 failed** |
| Reality（Vision）回归 | `bash .github/test/test_install.sh reality` | **26 passed / 0 failed**（Xray v26.10.31 安装、Reality 配置生成、服务启动、端口监听，证明取消 XTLS ONLY 未伤及 Vision/Reality） |
| 容器内函数级套件 | `test_relay_node / test_install_menu_profiles / test_offline_commands / test_redact` | 112 / 221 / 39 / 40，全部 0 failed |

`test_relay_container.sh` 覆盖的端到端行为：

- 真实向导输入：非法落地地址后重问、默认监听地址 `0.0.0.0`、向导只问落地地址/端口/本机监听端口，
  函数体内不含 `UUID_set`/`email_set`/`domain_check`/`ssl_judge_and_install`/`keys_set` 等 Xray 参数
- 角色持久化：清空内存变量后 `relay_bootstrap_role` 仍能从 `install_config.json` 恢复 `role=relay` 与目标/端口
- 信息输出：`xray_info_file` 含落地目标、含「REALITY 公钥/SNI/ShortId 不变」与「TCP 可达 ≠ REALITY 握手」提示、不含 UUID、权限 600
- 改落地目标：入口端口不变，流量从后端 A 切到后端 B，`proxy_pass` 与配置文件同步，`nginx -t` 通过
- 改监听端口：新端口监听、旧端口关闭、流量继续可用
- 停止 / 启动：入口端口随之关闭 / 恢复，转发内容不变
- 非法输入拒绝：`127.0.0.1; rm -rf /`、`evil$(id).example.com`、`-bad.example.com`、`bad..example.com`、
  空地址、端口 `0` / `70000` / `abc`、非法监听地址
- 端口冲突：占用中的端口被拒，`relay_listen_port` 回滚，转发不受影响
- **`nginx -t` 失败回滚**：向主配置注入非法指令后改目标，`relay_apply_change` 返回非 0，
  `relay-stream.conf` 与备份逐字节一致，日志出现「已恢复原转发配置」，恢复主配置后转发仍正常
- **Nginx 更新**：把记录的版本改成旧值触发真实下载；成功则检查 include/片段/`nginx -t`/转发，
  下载中断则要求「已成功回滚到之前的 Nginx 版本」——两种结果都不允许丢中转配置
- 卸载：片段删除、主配置 include 摘除、Nginx 卸载、入口端口关闭、`role` 从配置中清除、全程未装 Xray
- 混装守卫：已有 Xray 配置 / 已有受管站点时 `relay_preflight` 拒绝且**不修改**原文件；
  旧 `tls=XTLS` 配置下 `old_config_exist_check` 拒绝重装并提示「该模式已取消」「现有配置与服务不会被改动」

### 未执行 / 待实机验证

- **真实落地站 REALITY 端到端联通仍待验证**：容器里只证明「本机 Nginx Stream 把 TCP 字节转发到本地
  后端」，没有验证「经中转节点连到真实落地 VPS 后 REALITY 握手成功」。这一项必须在有真实落地机的
  环境完成，不能由容器替代。
- 真实公网主机上的防火墙落盘（`iptables-persistent`/`firewalld`）与 NAT 前置场景未在容器内覆盖
  （容器无 `NET_ADMIN`，`relay_firewall_sync` 走空实现）。


### 风险与遗留

1. 中转为单目标透明转发：落地更换需在菜单里改目标（`relay_modify_target`），不支持多落地/分流/UDP。
2. 落地地址若为域名，Nginx 在启动时解析并在解析失败时启动失败；域名 IP 变更后需重启 Nginx 才生效。
3. `proxy_timeout 720m` 与 `proxy_socket_keepalive on` 只解决长连接空闲；不解决落地侧限速/审计。
4. 如果用户手工在主配置写了自己的顶层 `stream {}`，中转安装会被拒绝（设计如此），需要人工合并。
5. 中转节点与普通节点不允许同机混装；`relay_preflight` 只做“拒绝”，不提供自动迁移。
6. 阶段 01 遗留的第 4 条（纯中转跳过证书路径）随本阶段落地：中转安装全程不触碰证书目录。

### 本阶段提交

`eba8daf`（功能）+ `84c3a63`（状态文档）+ 容器验证补强提交（`test_relay_container.sh`、CI guard job、
本文档更新）。均位于分支 `feat/stage1-cert-recovery-security-baseline`；未推送、未合并、未发布。

### 下一阶段准入

阶段 02 代码、本地自动化验证与容器整机实测已完成，可进入阶段 03；进入前唯一剩下的硬性待验证项是
**「中转节点 → 真实落地 VPS → REALITY 客户端」的端到端连测**，需要在有真实落地主机的环境完成。

---

## 阶段 03｜GeoData 原生热更新

**状态：代码完成，本地单测 + 容器整机（真实 Xray 二进制、真实 cron、真实下载）已验证；实机（真实 VPS）验证待补**

基线提交：`4fa2a53`（阶段 02 收尾）
工作分支：`feat/stage1-cert-recovery-security-baseline`

### 1. 用 Xray 原生 geodata 取代外部定时任务

改动文件：`install.sh`（`geodata_*` 一组函数，插入 `xray_install()` 之前）

- 普通节点不再依赖 `geo_update.sh` + crontab：安装/重装/换模式后，向 `config.json` 写入

  ```json
  "geodata": {
    "cron": "0 3 * * 1",
    "assets": [
      {"url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",   "file": "geoip.dat"},
      {"url": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat", "file": "geosite.dat"}
    ]
  }
  ```

  由 Xray 进程内按 cron 下载并**热重载**，不重启服务、不中断连接。
- 更新节奏与数据源刻意与旧方案保持一致（每周一 03:00、Loyalsoldier `latest/download`），
  因此**路由语义不变**；`.dat` 只是换了搬运者。
- 原生 `assets` 强制 HTTPS（`geodata_managed_json` 是唯一定义处），不引入可被降级为明文的地址。
- **幂等**：`geodata_state` 返回 `absent|managed|custom|invalid`。`custom`（用户自己写的 geodata 对象）
  只提示「保留原样」、绝不覆盖；`managed` 重跑只重新断言权限。
- **资产目录必须真实可读**：`geodata_prepare_layout` 要求 `geoip.dat`/`geosite.dat` 是资源目录下的
  普通文件（非符号链接），且 `XRAY_LOCATION_ASSET` 解析出的路径与 `/etc/idleleo/share/xray` 一致。
  任何一条不满足就跳过原生配置并给出提示——原生下载只会替换「本来就解析得到」的文件，
  缺文件时不写入 `geodata`，避免路由规则静默变化。

### 2. 写入事务与失败回滚

- 写前先判定「现有配置是否本来就有效」：`xray run -test` 不通过时**跳过**而不是修复，
  不把一个能用的安装改坏。
- 写入流程：`mktemp` 备份 → `update_json_config`（原子写，复用阶段 01 的既有实现）→
  `xray run -test -config` 复测 → 失败则 `cp -p` 备份**逐字节还原**并返回非零 → 成功才落地权限。
- 权限设置失败同样返回非零（原生更新会静默失效，不能当成功）。
- 安装链钩子（三处，均为 `standard_rebuild` / 全新安装 / 模式切换）：

  ```bash
  harden_config_permissions || return 1
  geodata_native_enable || return 1      # 写配置 + 测配置 + 落权限
  ...
  service_restart || return 1
  geodata_legacy_cron_disable || true    # 服务健康后才移除重复任务
  setup_auto_clean_logs || return 1
  ```

  顺序刻意如此：先让原生计划生效、服务确认健康，再动 crontab；移除失败只告警（`|| true`），
  不影响安装结果。

### 3. 服务账号写权限与 systemd 沙箱

- 只打开资源目录与两个 `.dat`：目录 `root:<svc-group>` `0770`，文件 `<svc-user>:<svc-group>` `0660`；
  `config.json`、私钥、证书的属主与 mode 一律不动（服务账号除了它必须替换的数据文件外没有新权限）。
- `root` 作为服务账号时退化为 `0755`/`0644`。
- **mode 位不等于有写权限**：`geodata_service_can_write` 在 `runuser`/`su` 可用时以服务账号实际探测
  `test -w`，失败只告警不致命（ACL、只读挂载都能让 0660 失效）。
- **沙箱**：`ProtectSystem=strict` 而没有对应 `ReadWritePaths` 时，原生下载必然失败。
  `geodata_sandbox_allows_write` 读取 unit 及其 `.d/*.conf` drop-in（按 systemd 语义后写覆盖先写、
  `ReadWritePaths` 累加），缺少可写路径则跳过原生配置并提示，不写一个注定失败的 `geodata`。
- 权限注释记录了实测结论：**长期成立的是「属主 + 目录可写」，不是精确 mode**——
  首次原生下载后 Xray 自己写回文件，实测变为 `0644`（属主仍是服务账号）。

### 4. 纯中转角色为 no-op

- `geodata_native_enable` / `geodata_legacy_cron_disable` 首行 `is_relay_role && return 0`。
- 中转节点不装 Xray、不生成 asset 目录、不写 `geodata`，安装后 `config.json` 不存在也无副作用。
- 阶段 02 的 relay 断言补了一条：relay 安装后**不存在** asset 目录。

### 5. traffic_blocker 菜单区分原生/旧模式

改动文件：`scripts/traffic_blocker.sh`（`1.6.2 → 1.7.0`）

- 新增只读探针：`tb_geo_native_cron`（读 `.geodata.cron`）、`tb_geo_native_assets_ok`（要求 `https://`
  且 `file` 为字符串）、`tb_geo_legacy_cron_lines`（只匹配指向本项目 `geo_update.sh` 的行）、
  `tb_geo_native_file_state`（`missing/recent/pending/stale`，7 天 / 30 天阈值）。
- `tb_display_geo_summary` 分流：原生已启用 → 显示真实 cron、两个文件的真实 mtime 状态；
  **不读 `geo_version.json`**（原生路径不写它，读了就是在编造历史）。
- 诚实性：明确打印「这里只反映配置与文件现状, 不代表某次定时任务已成功」——
  Xray 不落成功记录，菜单不能声称「上次更新成功」。
- `tb_geo_auto_update`：原生已启用时**拒绝安装第二套自动化**（否则外部 cron 会自己重启 Xray，
  且与原生任务重复），只报告并允许移除重复的 `geo_update.sh` 条目；移除按路径精确匹配，
  用户自建条目不动。旧模式保留原逻辑，并提示「重装为普通节点后会被自动移除」。
- 手动下载沿用 `geo_update.sh`（保留为救援工具），并提示手动更新会重启 Xray（与原生热更新不同）。

### 6. 国际化

- 新增 32 条 msgid 写入 `i18n/po/en.po` 与 `i18n/po/xray_install.pot`，`msgfmt --check` 通过，
  重建 `i18n/languages/en/LC_MESSAGES/xray_install.mo`。其余语种仍由 `Update Translations` workflow 生成。

### 本阶段验证（已执行）

环境：macOS 开发机（bash 3.2 / jq / msgfmt / shellcheck）+ 本地 Docker（`xray-relay-test:base`，
Debian 12 / arm64，`docker/fake-systemctl`），**未接触任何生产服务器**。

| 验证 | 命令 | 结果 |
| --- | --- | --- |
| 原生 geodata 单测（新增） | `bash .github/test/test_geodata_native.sh` | **93 passed, 0 failed, 1 skipped** |
| 普通节点整机安装（容器） | `docker run ... test_install.sh reality` | **31 / 31**（含新增 5 条 Native GeoData 断言） |
| 中转节点整机安装（容器） | `docker run ... test_install.sh relay` | **30 / 30** |
| 真实 Xray 热更新（容器，真实二进制 + 真实下载 + 1 分钟 cron） | `docker logs geo-live` | **15 / 15** |
| 本地可执行回归（30 个脚本） | `/tmp/run_all2.sh` | 与基线一致，无新增失败 |
| 语法 / 翻译 | `bash -n`、`msgfmt --check` | 通过 |

`test_geodata_native.sh` 覆盖：配置生成与幂等、自定义 `geodata` 不被覆盖、无法解析的配置被跳过、
`xray run -test` 前校验与写后复测、**逐字节回滚**（桩故意让第二次 `run -test` 失败）、
relay no-op、cron 去重且保留用户自建行、安装链顺序（`sed -n '/service_restart/,+5p'` 断言）、
权限 mode 与 `runuser` DAC 探测。

真实热更新的证据（`geo-live` 容器）：

```
app/geodata: downloading geodata asset from https://.../geosite.dat to /usr/local/share/xray/geosite.dat
common/geodata: reloading GeoIP data for 2 IP matcher(s) → reloaded
common/geodata: reloading GeoSite data for 1 domain matcher(s) → reloaded
-rw-r--r-- 1 nobody nogroup 16549678 geoip.dat     # 下载后由 Xray 自己写回，mode 0644
```

同一容器内还有「热更新后路由规则仍生效」「无残留临时文件」「确实读到了新文件」三项断言，均通过。

### 未执行 / 待实机验证

- **真实低内存设备的峰值内存**未测：`geodata_low_memory_notice` 只在 `MemTotal < 1 GiB` 时提示，
  但「下载 + 重载」的实际瞬时内存占用需要在 512 MB / 1 GB 的机器上观测。
- **长期 cron 行为**只在容器内用 1 分钟周期验证过一次；跨周（DST、时区、失败重试、GitHub 限流）
  的长期表现需要在真实机器上跑一段时间。
- 真实公网主机的防火墙/NAT 未在本阶段范围内（阶段 02 遗留），本阶段未新增防火墙改动。
- 未在真实 VPS 上执行完整 `install.sh` 安装（本阶段所有整机验证都在容器内完成）。

### 风险与遗留

1. **失败不可见**：原生路径不写更新结果，Xray 只在日志里留痕；菜单只能报告文件 mtime，
   无法回答「上次更新成功了吗」。要靠 `journalctl -u <unit>` 查 `app/geodata` 日志。
2. **低内存峰值**：下载 + 解析 `.dat` 的瞬时内存高于旧脚本（旧脚本是外部进程），
   小内存机器仍需观察。
3. **数据源单点**：仍为 GitHub `latest/download`，被限流或不可达时原生下载静默失败（下个周期重试）。
4. **`geodata` 是配置级设置**：用户若手工改 `config.json` 的 `geodata`（例如换 CDN），
   本脚本识别为 `custom` 并永不覆盖——这是刻意的，但也意味着脚本不再为它兜底。
5. **`geo_update.sh` 保留双路径**：作为手动救援工具共存；若用户手动把它的 cron 加回来，
   会与原生任务重复（菜单会检测并提示移除，但不主动删除用户自建条目）。
6. 沙箱判定依赖文本解析 unit/drop-in；若用户用 `systemd-analyze` 之外的方式（如容器内直接改挂载）
   放宽限制，判定可能与实际不一致——此时只跳过原生配置，不产生错误配置。

### 本阶段提交

`a2f512d`（功能 + 测试 + i18n）+ 状态文档提交。均位于分支
`feat/stage1-cert-recovery-security-baseline`；未推送、未合并、未发布。

### 下一阶段准入

阶段 03 代码与本地/容器验证完成，**可以进入阶段 04**；进入前的硬性待验证项是
「真实 VPS 上的原生热更新 + `ProtectSystem` 沙箱组合」，以及低内存设备的内存峰值观测。
两项都不阻塞阶段 04 的代码工作，但应在合并前补测。
