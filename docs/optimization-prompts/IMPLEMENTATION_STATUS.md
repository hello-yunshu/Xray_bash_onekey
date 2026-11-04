# 优化计划实施状态（v2.1）

本文件记录《Xray_bash_onekey 优化计划｜审计补全版 v2.1》各阶段在本仓库中的实际实施情况。
依据为仓库当前源码，不沿用旧行号。

---

## 3.3.0 发布与总体验收（2026-11-02）

**状态：已发布；发布流水线与 API 资格验证均通过。**

| 项 | 结果 |
| --- | --- |
| Shell 版本 | `install.sh` 唯一锚点 `shell_version="3.3.0"` |
| 合并 | 主仓库 PR #126（`3b129f9`）；API 模式发现 PR #32（`f7568ef`）、资格策略/元数据 PR #34（`1ed7f00`）、矩阵修复 PR #35（`b3d712f`） |
| Git tag / Release | `v3.3.0`（commit `3b129f9f1f04c47689ce39e8bbd186a84dec0b78`） |
| Release 资产 | `install.sh`（sha256 `0730ad91…`）、`rill-xray-agent-xray-bundle.tar.gz`、`SHA256SUMS`、`release-manifest.json`；`sha256sum -c` 通过 |
| 发布工作流 | `Release Xray` run `41409994118`：成功；candidate、5 个 Install 模式、security-regression、minimal bootstrap、Rill、release 全部 success |
| API 元数据 | `shell_online_version=3.3.0`、`shell_tested_version=3.3.0`、`shell_release_sha256=0730ad91…`；v3.3.0 基线已记录 |
| 正式资格验证 | run `41414537541`（main，workflow_dispatch）：**30 / 30 success，0 failed** |
| 资格矩阵 | 由 3.3.0 的 `test_install.sh` 解析出 `relay / ws_grpc_xhttp / reality / reality_nginx / tls`；证据 job success |

### 最低直接升级来源

`compatibility-baselines.json` 设置 `minimumDirectUpgradeVersion=3.3.0`：

- 3.2.9 / 3.2.10 / 3.2.11：只真实执行 `shell-first` 与 `reinstall`，均 **success**。
- 3.3.0：真实执行 `direct`、`shell-first`、`reinstall`、`failure-recovery`、
  `restart-recovery`、`fallback`，均 **success**。
- 新装 3.3.0：由 Release Xray 的 5 个 full-install 模式覆盖，均 **success**。
- **3.2.12 → 3.3.0 直更未执行**：仓库从未发布过 3.2.12，无法构造该来源版本；
  最低支持直更来源实际为 3.3.0（后续 3.3.x）。该项标记为 NOT_RUN，不伪称通过。
- 未使用 expected-incompatible 豁免；旧版本的 auto-update 会因 3.2→3.3 跨次版本
  主动拒绝，门禁改用真实用户路径：交互式 `-u` 确认后升级 Shell，再更新 Xray。

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

#### 迁移入口（旧 `geo_update.sh` 安装）

迁移到原生 geodata 有且只有两条入口：

1. **下次启动脚本**：`install.sh` 启动钩子调用 `geodata_migrate_legacy`，覆盖普通启动、
   `-u`、菜单等所有可变启动路径。成功后摘除本项目自建的 `geo_update.sh` cron；失败保留
   旧 cron、恢复原配置并写入 `geodata_migration.failed` 供菜单显示原因。
2. **进入 GeoData 菜单**：`traffic_blocker.sh` 在首次进入 GeoData 菜单时，仅当
   「没有 `.geodata.cron` + 存在本项目 `geo_update.sh` cron」才尝试迁移；已是原生、
   `custom` 配置、配置无法解析、没有旧 cron 都直接跳过。失败同样保留旧 cron 和原配置，
   不会重启一个未运行的 Xray。

`-u` **故意不在当次迁移**：旧进程替换 `install.sh` 后不 re-exec 新脚本，避免递归、
退出码透传和服务重启新风险；下一次启动新版脚本时由入口 1 完成迁移。更新日志会提示用户
“GeoData 迁移将在下次启动脚本或进入 GeoData 菜单时执行”。

#### 备份恢复时自愈（旧归档也可恢复到新主机）

- **新备份**包含 `/usr/local/share/xray -> /etc/idleleo/share/xray` 软链；**旧归档**没有该条目
  （或只有真实目录），恢复后会出现「`.dat` 在 `/etc/idleleo/share/xray`、Xray 却读
  `/usr/local/share/xray`」的错位。恢复路径现在做三态自愈：
  1. 软链已正确指向托管目录 → 不动（重复恢复幂等）；
  2. 路径不存在、托管目录已有 `geoip.dat`/`geosite.dat` → 直接建软链；
  3. 路径是真实目录且含两个 `.dat` → 合并进托管目录，**目标已有同名文件优先保留**，
     原目录先移动到 `<path>.restore-backup.<timestamp>` 作为可回退副本，再替换为软链。
- **重复恢复旧归档**：覆盖前先把归档里的真实目录移出 overlay，避免 `cp -a` 对现有软链报错
  或把旧文件写穿软链；随后只补托管目录缺失的文件，不产生第二个回退副本。
- 自愈后用恢复的二进制执行真实 `XRAY_LOCATION_ASSET=<软链路径> xray run -test`；失败时
  删除新建软链、把回退副本移回原位、删除本次复制进托管目录的文件并还原配置快照，
  明确报错，不留下半成品。没有可执行 Xray 时只跳过自检并告警，布局仍按上述规则修复。
- **旧归档可直接恢复到全新主机，无需重装**；备份侧行为不变（新备份仍带软链）。
- 备份/恢复影响面：`config.json` 里的 `.geodata` 随 `/etc/idleleo` 备份；root crontab spool
  也在备份清单里（旧 cron 会一并恢复，之后由启动钩子或菜单迁移摘除）；`geo_update.sh`
  若存在会随 `/etc/idleleo/scripts` 备份。卸载路径未新增清理项，仍清理软链、托管目录、
  脚本和本项目 cron。
- 测试：`.github/test/test_restore_geodata_selfheal.sh`（旧归档 fixture：真实目录 / 无条目的
  托管数据 / 目标已有 geodata / 重复恢复 / 失败回滚），本地与 Linux 容器均为 0 failed；
  真实 Xray `run -test`、`chroot` 默认路径探测、负向坏数据探测都在容器内执行。

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
- 诚实性：明确打印「这里只反映配置与文件现状, 不代表某次自动刷新已成功」——
  Xray 不落成功记录，菜单不能声称「上次刷新成功」。
- `tb_geo_auto_update`：原生已启用时**拒绝安装第二套自动化**（否则外部 cron 会自己重启 Xray，
  且与原生任务重复），只报告并允许移除重复的 `geo_update.sh` 条目；移除按路径精确匹配，
  用户自建条目不动。旧模式保留原逻辑，并提示「重装为普通节点后会被自动移除」。
- 手动下载沿用 `geo_update.sh`（保留为**手动刷新**工具），并提示手动刷新会重启 Xray（与原生热更新不同）。
- 进入 GeoData 菜单和执行手动刷新前都先打印 `自动刷新状态` 头：原生已开启时显示 cron 与含义
  （如 `0 3 * * 1` → 每周一 03:00）并说明无需手动操作；未开启、旧脚本 cron、custom、配置不可解析、
  上次开启失败各自有独立文案。手动刷新结束再报成功/失败、写入位置和是否需要重启。
- 术语统一为 **自动刷新 / 手动刷新**；不再出现「救援」「自动更新与救援」等混用文案。

#### `geo_update.sh` 手动刷新入口审计

| 审计项 | 实际行为 |
| --- | --- |
| 菜单脚本来源 | `tb_geo_ensure_updater` 优先用 `geo_remote_url`（`https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/v<shell_version>/scripts/geo_update.sh`），缺失时按同一路径回退；仅在本地文件不存在时下载 |
| 脚本完整性 | **不走 `release-manifest.json`，也没有 SHA256/签名校验**；只依赖 HTTPS、版本化 tag（v3.3.2）和下载后的 `bash -n` 语法检查 |
| 脚本权限 | `download_script_file` 写入临时文件后 `mv` 到 `/etc/idleleo/scripts/geo_update.sh` 并 `chmod +x`；不强制 0600/root:root（与 `xray_stats.sh` 的校验方式不同） |
| GeoData 数据来源 | `geo_update.sh` 先解析 `Loyalsoldier/v2ray-rules-dat` 的 `releases/latest` 不可变 tag，再下载 `geoip.dat`/`geosite.dat` 及上游 `.sha256sum`；逐文件校验 SHA256，下载上限 100 MB，使用 `/run/lock/idleleo-update.lock` |
| 是否改 `config.json` | **不改**；只写两个 `.dat` 与 `geo_version.json`（元数据）。脚本先构造校验配置并跑真实 `xray run -test`，通过后才提交文件 |
| 是否重启 Xray | 仅当 `systemctl is-active xray` 为真时重启并做健康检查；未运行的服务不会被启动或重启。菜单包装层只查询状态，不主动重启 |
| 失败残留 | 提交前失败不改线上文件；提交阶段失败回滚上一代 `.dat`/元数据并恢复原服务状态；回滚失败时保留 `stage` 并写 `RECOVERY REQUIRED`。日志在 `/etc/idleleo/logs/geo_update.log` |
| 菜单项 1：立即启用 | 触发条件：无原生 `.geodata.cron`、存在本项目自建 `geo_update.sh` cron、`geodata_state` 非 `custom`/`invalid`。输出：已是自动刷新 / 未检测到旧 cron / custom 跳过 / 配置不可解析 / 切换中 / 切换成功或失败原因 |
| 菜单项 2：手动刷新 | 始终可用；脚本缺失时先下载。先打印当前自动刷新状态，再执行；成功报写入位置与运行中/未运行的重启结论，失败报 rc、日志位置和「config 未改、未建 cron」 |
| 菜单项 3：移除旧 cron | 仅删除包含本项目 `geo_update.sh` 路径的行；不重启、不改配置；没有匹配行时提示「没有找到」；手写 cron 永远保留 |
| 定时任务副作用 | 三个手动刷新/维护动作都**不新建 cron**；测试断言 crontab 保持为空、未运行服务不被重启、失败时配置逐字节不变 |

#### 分版本退役方案

| 阶段 | 菜单行为 | 进入下一阶段的条件 |
| --- | --- | --- |
| 当前版本（3.3.2） | 保留「自动刷新与手动刷新」子菜单；手动刷新仅作为显式操作，不安装 cron | —（本版本基线） |
| 下一版本 | 菜单项默认隐藏，仅在**故障态**显示：存在 `geodata_migration.failed`，或仍有本项目 `geo_update.sh` cron，或 `.dat` 缺失/超过 30 天未刷新；其余情况需用户显式输入确认词才显示 | 本版本发布后，至少 1 台真实 VPS（非容器）连续 **2 个完整周期**（`0 3 * * 1`）原生刷新成功：Xray 日志有下载+reload 记录、两个 `.dat` mtime 前进、无旧 cron、无失败标记 |
| 再下一版本 | 菜单不再提供下载/运行入口；只保留文档中的手动命令（用户自行下载脚本、校验、运行） | 3 台不同发行版的真实 VPS（Debian/Ubuntu/CentOS）各自连续 2 个周期成功，且菜单手动刷新入口在这 2 个周期内未被使用（以脚本 mtime/日志为准）；无相关回归 issue |

> 判定口径刻意要求「真实主机 + 连续两个周期」，容器内 1 分钟 cron 的验证不算数。

本轮验证（2026-11-05）：

| 验证 | 环境 | 结果 |
| --- | --- | --- |
| 旧归档恢复自愈 | macOS + 真实 Xray 26.10.31 | **39 passed, 0 failed, 1 skipped**（chroot 需 root/Linux） |
| 旧归档恢复自愈 | CentOS Stream 10 / Ubuntu 24.04 容器 + 真实 Xray | **40 passed, 0 failed, 0 skipped**（含 chroot 默认路径探测） |
| GeoData 菜单/迁移 | macOS | **208 passed, 0 failed, 1 skipped** |
| `-u` 下次启动迁移 | Debian 12 容器 | **27 passed, 0 failed** |
| 颜色全仓扫描 | macOS | **67 passed, 0 failed** |
| 翻译完整性 | `validate_po.py` | en/fa/ru/ko/fr 全部 complete |

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
5. **`geo_update.sh` 保留双路径**：作为手动刷新工具共存；若用户手动把它的 cron 加回来，
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

---

## 阶段 04｜自动更新可靠性、协议兼容与总收口

**状态：已完成；3.3.0 已发布，正式资格验证 30/30 通过（见本文件顶部 3.3.0 章节）。**

基线提交：`77ad84a`（阶段 03 收尾）
工作分支：`feat/stage1-cert-recovery-security-baseline`

### 1. 自动更新失败记录（`scripts/auto_update.sh` 1.1.6 → 1.2.0）

原实现用 `update_failed.mark.xray` / `.nginx` 两个**空标记文件**表达"上次失败"：
一旦生成就永久阻挡该组件的所有未来版本，只能人工 `rm`。改为结构化记录：

```json
{"xray":  {"version": "26.10.31", "failed_at": "2026-11-02T01:00:00Z"},
 "nginx": {"version": "2026.10.15.7679", "failed_at": "..."}}
```

- **重试判定看版本，不看"是否曾失败"**（`component_should_attempt`）：
  记录的失败目标版本与本次目标相同 → 跳过并打印失败时间；目标版本变化 → 重新尝试。
  这也顺带修掉了"新版出来后仍被旧标记挡住"的长期问题。
- **旧标记不再阻断**：`legacy_marker_migrate` 在启动时删除 `.xray` / `.nginx`（旧标记不含版本，
  无法参与判定），并在日志里写明"旧标记曾阻挡所有后续版本，现已不再参考"。
- **日志自解释**：每次跳过都打印组件、失败版本、失败时间、手动重试命令
  （`jq 'del(.xray)' /etc/idleleo/logs/update_failed.json`）以及"元数据出现新版本会自动重试"。
- 成功即清除对应记录；记录文件 `0640`，写入走 `mktemp` + `mv` 原子替换，损坏的旧文件被整体重建。
- 共享锁（`/run/lock/idleleo-update.lock`）、`running` 目录锁、备份与回滚全部保持原样；
  另补 `flock` 缺失时的降级日志（仅影响无 util-linux 的开发机，生产行为不变）。

### 2. 版本元数据源回退

- 顺序：jsDelivr → GitHub Raw，各自都必须"单对象 JSON + 本次要用的字段齐全且形如版本号"才被接受；
  缺字段/非 JSON/网络失败的源被整体拒绝并尝试下一个（`fetch_versions` + `versions_fields_ok`）。
- **不再半信半疑地用脏数据**：原实现拿到任意非空字符串就当版本；现在 `nginx_build_online_version: "latest"`
  这类值会被拒（有测试）。
- 只做"取版本号"，不绕过任何既有校验：脚本更新仍走 `install.sh -u`（Release 版本/`shell_release_sha256`）、
  Nginx 走 `-n`（manifest/SHA256SUMS）、Xray 走 `-x`（installer ref/sha256），三者都在原处校验。
- 两个源都不可用时 **exit 0 跳过**（cron 不刷失败），日志写明原因。

### 3. 纯中转节点只更新主脚本与 Nginx

- 读 `install_config.json` 的 `role`；`relay` 时：
  - 元数据只要求 `shell_online_version` / `nginx_build_online_version`，缺 `xray_online_version` 不算失败；
  - 永不调用 `install.sh -x`，日志写"Relay node: Xray is not installed by design"；
  - 不会写出 Xray 的失败记录（有测试断言）。
- 顺带把"Nginx 未安装 / 版本未知"两种情况分开报告，避免中转（无 Xray）与 ws ONLY（无 Nginx）
  互相误导。

### 4. REALITY 客户端版本下限（2026-03 后唯一必须适配的上游变更）

**证据**：Xray 26.7.11 起，`realitySettings.minClientVer` 未显式设置时按 `26.3.27` 处理，
仍在报旧版本号的客户端（Mihomo/Clash 固定上报 1.8.2）直接握手失败。上游 issue
[XTLS/Xray-core#6482](https://github.com/XTLS/Xray-core/issues/6482) 的结论就是显式写 `minClientVer`。
本脚本钉定 `26.10.31`，而模板里没有该字段 → **所有 Reality 新装机都会复现**。

- `config/vless_reality.json` 模板加 `"minClientVer": "1.0.0"`。
- 新增 `reality_min_client_ver_repair()`（`install.sh`）：只给**缺失**该字段的 reality 入站补值，
  用户自己设的值永不覆盖；写前备份、写后 `xray run -test`，失败逐字节还原；relay 与无 reality 入站的配置不动。
- 调用点两处：`install_xray_reality()`（新装 / 重装 / Reality+Nginx 都经过）与 `xray_update()`（核心更新、
  重启前，因此本次重启即生效）。这也覆盖了"已经升到 26.10.31 但配置没字段"的存量机器。

**2026-03 之后上游变化对照（本阶段结论）**

| 变更 | 判断 | 依据 / 处理 |
| --- | --- | --- |
| REALITY `minClientVer` 默认值 26.3.27（26.7.11+） | **必须适配（已做）** | 上游 issue #6482；不写字段则旧客户端全部握手失败 |
| `allowInsecure` 2026-06-01 强制下线 | 不适用 | 脚本与服务端配置从未使用该字段；服务端只用真实证书 / REALITY |
| XHTTP 客户端 `maxConnections` 默认 6 → 3（26.7.28） | 可选 | 只影响客户端默认值；服务端 `xhttpSettings` 仅 `path`/`mode: auto` |
| 26.10.31 默认关闭 MPTCP（安全修复） | 无需处理 | 二进制行为，配置无对应开关；钉定版本已包含 |
| MASQUE / XDRIVE 等新传输 | 暂不做 | 会引入新协议菜单，超出"最小兼容收口"范围 |
| Vision CloseNotify / FinalMask 等行为修正 | 无需处理 | 无配置面影响，配置测试与真实握手均通过 |

### 5. CLI / 帮助 / i18n / README / 卸载 / 状态显示核对

- `--help` 已含 `--install-relay`；无 `XTLS ONLY` 残留入口（阶段 02 已清）。
- `basic_information` / `check_program` 有 relay 分支（显示 Nginx 状态、Xray "不适用"），阶段 02 已落地。
- `uninstall_all` 有 relay 分支，并清理 `auto_update.sh` / `geo_update.sh` / `ssl_update.sh` 三类 cron。
- README 无 `geo_update.sh` 定时任务的过时描述；中转节点在支持模式表里。
- i18n：本阶段新增 3 条 msgid 写入 `.pot` / `en.po`，`msgfmt --check` 通过并重建 en `.mo`。
- 未发现需要在本阶段修复的 CLI/状态显示不一致。

### 6. 并行版本修复核验（只核验，未改动）

任务要求核对三项，结论如下（第一项已在本仓库补充提交中解决，第三项仍是发布阻塞）：

| 项 | 结论 | 证据 |
| --- | --- | --- |
| a. 不能因"版本不相等"自动降级到更旧版本 | **已满足（本仓库补充提交）** | 初始核验时 `install.sh` 只有 `!=` 比较；补充提交 `fd48c42` 增加 `version_compare` 数字序比较与更新前守卫，`auto_update.sh` 1.2.1 同步拒绝降级；`test_version_downgrade_guard.sh` 29/29、`test_auto_update_failure_records.sh` H 段覆盖。仓库内不存在可独立核对的"并行版本修复"分支，故只记录本仓库结果，不代第三方宣称 |
| b. 恢复旧测试版不得误报"安全更新成功" | **已满足（2026-11-02 复跑）** | `install.sh` 的 `xray_update` 在任何回滚成功后仍 `return 1`，注释明确"服务恢复成功 ≠ 本次更新成功"；`test_xray_update_transaction.sh` **53 passed, 0 failed**（auto/manual 两种模式都断言回滚成功返回非零） |
| c. API/installer 候选、资格验证、晋级链路可靠 | **未满足，发布阻塞（已缩小到上游兼容问题）** | 最新 `Qualify candidate API release (read only)` 运行 [41356005715](https://github.com/hello-yunshu/Xray_bash_onekey_api/actions/runs/41356005715)（2026-11-01T22:13Z）failure：3.2.9 的 `fresh/reinstall/direct/fallback/restart-recovery` 失败，3.2.10/3.2.11 的 `restart-recovery` 失败，`evidence`/`request-publication` 被跳过。日志证据：3.2.9 fresh 为 `permission denied observed` + `Xray service inactive`（基线安装阶段即失败）；三个 restart-recovery 均为 `Original binary was not restored; observed Xray version: 25.12.8` + `permission denied observed`（候选安装器切换服务账号后，注入启动失败使 Layer 1 恢复无法启动，落到 Layer 2 tested_version）。这是 installer `04e6f3b` 硬编码 `User=xray` 与旧 Shell 归属顺序的兼容问题，不是测试预期错误。API 侧已推送 `fix/qualify-install-modes-relay`（`75d6ae7`）：资格矩阵改为只读解析已发布 Shell 的真实安装模式（3.2.11→`xtls_only`，含 relay 的 3.2.12 Shell→`relay`），证据收集/校验同步支持 `--modes`；**未新增 expected-incompatible 豁免，门禁未放宽**。新流水线运行 `41403268854` 用于验证矩阵发现链路 |

其它观察（不是本阶段可改的）：线上元数据（2026-11-02 读取）为 `shell_online_version=3.2.11`、
`xray_online_version=26.10.31`、`xray_tested_version=25.12.8`、`shell_tested_version=2.8.3`、
`xray_installer_ref=e741a4f`；资格基线明显落后于线上版本，`xray_online_version` 已钉定为
含 MPTCP 安全修复的版本。


### 7. 本阶段验证（已执行）

| 验证 | 命令 | 结果 |
| --- | --- | --- |
| 自动更新定向测试（新增） | `bash .github/test/test_auto_update_failure_records.sh` | 初次 **28 passed**；2026-11-02 复核 **46 passed, 0 failed** |
| REALITY minClientVer 测试（新增） | `bash .github/test/test_reality_min_client_ver.sh` | **12 passed, 0 failed** |
| 普通 Reality 整机（容器） | `test_install.sh reality` | **32 / 32**（新增 minClientVer 断言） |
| Reality+Nginx 整机（容器） | `test_install.sh reality_nginx` | **51 / 51**（2026-11-01）；2026-11-02 复跑因 Xray 下载网络中断未通过，见复核表 |
| ws/gRPC/xHTTP 整机（容器） | `test_install.sh ws_grpc_xhttp` | **33 / 33** |
| TLS 整机（容器） | `test_install.sh tls` | **31 / 31** |
| 中转整机（容器） | `test_install.sh relay` | **30 / 30** |
| 受影响单测 | `test_version_loading` / `test_vps_auto_update_schedule` / `test_install_menu_profiles` / `test_reinstall_call_chain` / `test_geodata_native` / `test_relay_node` / `test_reality_nginx_feedback` / `test_ws_only_listen_address` / `test_shell_update_metadata` / `test_offline_commands` | 全部通过 |
| 本地可执行回归（全部脚本） | `/tmp/run_all3.sh` | 失败项与基线 `4fa2a53` 完全一致（`test_fail2ban`、`test_log_rotation`、`test_installer_candidate_smoke`、`test_relay_container`、`rill_*`、`test_xray_update_transaction`、`test_xray_version_pipefail` 均为 macOS/需 root/需参数的环境限制，已在基线 worktree 逐项复现） |
| 语法/格式 | `bash -n`、`msgfmt --check`、`jq -e config/vless_reality.json` | 通过 |

**阶段 04 复核（2026-11-02，macOS 开发机，未接触生产服务器）**

| 命令 | 结果 |
| --- | --- |
| `bash .github/test/test_auto_update_failure_records.sh` | **46 passed, 0 failed**（原 36；新增 Nginx 失败记录、成功重试清除记录、失败后立即可见人工重试提示、Xray/Nginx 互不阻塞的断言） |
| `bash .github/test/test_reality_min_client_ver.sh` | **12 passed, 0 failed** |
| `bash .github/test/test_version_downgrade_guard.sh` | **29 passed, 0 failed** |
| `bash .github/test/test_xray_update_transaction.sh` | **53 passed, 0 failed**（复核 b：回滚成功仍返回非零） |
| `bash .github/test/test_install_menu_profiles.sh` / `test_reinstall_call_chain.sh` / `test_geodata_native.sh` / `test_relay_node.sh` | 221 / 160 / 93(+1 skipped) / 112，全部 0 failed |
| `bash .github/test/test_nginx_update_rollback.sh` / `test_nginx_health_production_defaults.sh` / `test_log_rotation.sh` | 28 / 6 / 10，全部 0 failed |
| `bash .github/test/test_version_loading.sh` / `test_vps_auto_update_schedule.sh` / `test_shell_update_metadata.sh` / `test_offline_commands.sh` / `test_reality_nginx_feedback.sh` / `test_ws_only_listen_address.sh` / `test_redact.sh` / `test_phase1_safety.sh` / `test_xray_installer_metadata.sh` / `test_release_reconciliation.sh` | 全部 exit=0 |
| `bash -n install.sh scripts/auto_update.sh`、`shellcheck -S error`（改动文件） | 通过 / 无 error 级问题 |
| `msgfmt --check i18n/po/en.po`、`msgfmt --check i18n/po/xray_install.pot` | 通过（pot 仅有既有 header 占位警告） |
| `bash .github/test/test_xray_version_pipefail.sh` | macOS 直跑仍 **FAIL（rc=1，无输出）**；在 Debian 12 容器（bash 5）内 **PASS**（"version health check consumes complete output under pipefail"），属 macOS/bash 3.2 环境限制，已在 Linux 等价环境补齐 |
| 容器整机 `test_install.sh reality`（真实下载 + 真实二进制） | **32 / 32** |
| 容器整机 `test_install.sh relay`（真实 Nginx 下载与 SHA256 校验） | **30 / 30** |
| 容器整机 `test_install.sh reality_nginx` | **51 / 51（2026-11-02 复跑通过）**：前两次在本机网络下 Xray 下载被 `curl: (18)` 中断（41/51，失败项全部是二进制缺失）；改用仅强制 HTTP/1.1 的测试镜像后完成真实下载并全量通过 |
| 容器整机 `test_install.sh ws_grpc_xhttp` | **33 / 33**（HTTP/1.1 测试镜像，真实 Xray 下载） |
| 容器整机 `test_install.sh tls` | **31 / 31**：本机网络连续两次在 Xray/Nginx 大文件下载中断；用官方发布产物（Xray zip sha256 `1811c8f1…`、Nginx tar sha256 与 manifest `dc78117f…` 一致）放入测试镜像的本地缓存后，安装链、SHA/manifest 校验、服务与端口断言全部通过 |

**Reality 真实握手（容器内，真实 26.10.31 客户端 + 服务端）**：
客户端 `proxy/vless/outbound: tunneling request to tcp:127.0.0.1:18080 via 127.0.0.1:14431`，
服务端 `accepted tcp:127.0.0.1:18080 [VLESS-Reality-in -> direct]` → REALITY 认证通过、VLESS 请求被接受。
错误 shortId 的对照连接被拒绝。**但完整 HTTP 载荷回程在容器内超时（多次重试）**，
因此只把"REALITY 握手 + VLESS 请求接受"记为已验证，"端到端数据面"记为待实机验证。

### 8. 未执行 / 待实机验证

- **Reality/TLS 的完整外网握手**：容器内只验证到握手与请求接受，载荷回程超时未定位；
  TLS 模式需要真实域名 + 证书，未在容器内做。
- **中转 → 真实落地 VPS 的完整协议连接**（阶段 02 遗留）：仍未做。
- **GeoData 真实热更**：阶段 03 已用真实二进制 + 真实下载 + 短 cron 验证（15/15），本阶段未重跑。
- **真实低内存设备的峰值内存**（阶段 03 遗留）。
- 真实 VPS 上的 `ProtectSystem` + 原生热更新组合（阶段 03 遗留）。

### 9. 风险与遗留

1. `xray_update` 的降级判定缺失（阻塞 a）会把"元数据回退"变成自动降级，需并行任务补齐后再发布。
2. 资格验证流水线当前红灯（阻塞 c），且其安装矩阵仍包含已删除的 `xtls_only`。
3. 失败记录按"目标版本"抑制：若同一版本被上游重发修复，需要按日志提示手动清一次记录。
4. `minClientVer="1.0.0"` 是兼容优先的取舍：放宽了 REALITY 的客户端版本门槛（上游默认在收紧）；
   需要更严格时可自行改成更高版本，脚本不会覆盖用户设置。
5. 自动更新只在"目标版本变化"时重试，同一版本的瞬时网络故障不会被当天重试（由下一个版本或手动重试覆盖）。

### 10. 本阶段提交

`acd4568`（自动更新失败记录 + 元数据回退 + REALITY minClientVer + 两个新测试 + i18n）、
`fd48c42`（版本降级保护 + 测试）、`c0c37ac` / `b5edc40`（状态文档）、
`58c5095`（失败日志即时重试提示 + 测试 36→46 断言 + 复核文档）。
上述提交均位于分支 `feat/stage1-cert-recovery-security-baseline`，已于 2026-11-02 推送到
`origin/feat/stage1-cert-recovery-security-baseline`；未合并、未发布。

### 11. 阶段 01—04 汇总

| 阶段 | 提交 | 范围 |
| --- | --- | --- |
| 01 证书恢复与安全基线 | `ac63aa7`、`d7c4e50` | `scripts/ssl_update.sh`、`install.sh`（日志权限、无 TLS 后端默认回环） |
| 02 取消 XTLS ONLY 与中转节点 | `eba8daf`、`84c3a63`、`4fa2a53` | `install.sh`、`config/*`、`test_relay_container.sh`、CI |
| 03 GeoData 原生热更新 | `a2f512d`、`77ad84a` | `install.sh`、`scripts/traffic_blocker.sh`、`test_geodata_native.sh`、i18n |
| 04 自动更新与总收口 | `acd4568`、`c0c37ac` | `scripts/auto_update.sh`、`install.sh`、`config/vless_reality.json`、两个新测试、i18n |
| 04 补充·版本降级保护 | `fd48c42`、文档提交 | `install.sh`（`version_compare`）、`scripts/auto_update.sh` 1.2.1、`test_version_downgrade_guard.sh` |

**仍未验证的实机项**：真实 VPS 上的证书续签失败恢复、中转→真实落地端到端、低内存峰值、
`ProtectSystem` 与原生热更新组合、Reality/TLS 外网完整数据面。

**发布阻塞项（合并/发布前必须解决）**：
1. ~~`xray_update` 缺版本序比较，元数据回退会导致自动降级。~~ **已解决**（见「阶段 04 补充」，
   `version_compare` 数字序比较 + 更新前守卫，`auto_update.sh` 1.2.1 同步；2026-11-02 复跑 29/29）。
2. ~~候选资格流水线红灯~~ **已解决**：
   3.2.9–3.2.11 改为只验证真实支持的 `shell-first` + `reinstall`；3.3.0 验证
   `direct`/`shell-first`/`reinstall`/`failure-recovery`/`restart-recovery`/`fallback`；
   新装由 Release Xray 的 full-install 矩阵覆盖。正式资格运行 `41414537541`
   **30/30 success**，矩阵由 3.3.0 解析出 `relay`；未使用 expected-incompatible 豁免。
   旧 Shell 的 `-u auto_update` 会主动拒绝 3.2→3.3 跨次版本，门禁改用真实交互式
   `-u` 路径，并在 3.2.9/3.2.10/3.2.11 上真实通过。

### 12. 下一阶段准入

阶段 04 与 3.3.0 发布已完成：代码、Release 资产、API 元数据、旧版本支持路径与
正式资格验证均通过。剩余仅实机项（真实 VPS 证书恢复、中转→真实落地、外网完整数据面、
低内存与 `ProtectSystem` 组合）需在有真实主机的环境补测；未发现新的发布阻塞项。


---

## 阶段 04 补充｜版本降级保护（阻塞项 1 已解决）

**状态：已修复并通过定向验证；阻塞项 2 已定位到根因，但修复跨仓库且有策略取舍，未擅自改动。**

### 1. 问题

`xray_update` 与 `scripts/auto_update.sh` 都用 `[[ a != b ]]` 判断"要不要更新"。版本**不同**被当成
"有更新"，于是下列任一情况都会把一台能用的主机降级：

- API `xray_shell_versions.json` 回退到更旧版本（发布回滚、人工改错）；
- jsDelivr/GitHub Raw 返回过期副本（阶段 04 引入的双源回退放大了这个可能）；
- 用户手工改了元数据。

字符串比较还有第二种错法：`26.10.4` 与 `26.10.31` 按字典序是"前者更大"，实际是更旧。所以不能只加
一个方向判断，必须换成按数字分段的比较。

### 2. 改动

`install.sh`（新增 `version_is_numeric` / `version_compare` / `version_gt` / `version_lt`）：

- 按 `.` 分段逐段数字比较（`10#` 前缀，`026` 不会被当成八进制），缺段补 0（`26.10 == 26.10.0`），
  忽略 `v` 前缀。不引入 `sort -V` 外部依赖。
- 任一侧不是"点分数字版本"时返回 `2`（不可比），`version_gt`/`version_lt` 对不可比输入都返回假——
  畸形元数据既不会触发更新，也不会被误判成降级。
- `xray_update` 在任何备份/停服/安装动作之前先判断：本机版本高于清单版本 → 打印两边的版本、
  提示"如确需降级请手动指定版本或先卸载"，直接 `return 0`（不写 `update_failed`、不动服务）。
  真正的新版本与同版本重装（`!=` 分支后的 countdown 重装）都保持原行为。
- `xray_install` 仍按清单钉定版本收敛（这是安装语义），但本机版本更高时会显式告警
  "本机版本高于清单钉定版本, 将按清单重新安装"，不再静默降级。

`scripts/auto_update.sh`（1.2.0 → 1.2.1）：

- 新增同样的比较函数（脚本独立运行，不能 source `install.sh`）。
- Xray 与 Nginx 两处更新判定都改为：相同 → 已是最新；目标更旧 → 跳过并记录
  `Installed ... is newer than the metadata target ...; refusing to downgrade`；
  目标更新 → 走原更新路径。
- 跳过的降级**不写失败记录**（否则下次元数据恢复正常时会被"同版本已失败"再挡一次）。

### 3. 验证

| 验证 | 命令 | 结果 |
| --- | --- | --- |
| 新增 `test_version_downgrade_guard.sh` | `bash .github/test/test_version_downgrade_guard.sh` | **29 passed, 0 failed** |
| `test_auto_update_failure_records.sh`（新增 H 段） | 同上 | **36 passed, 0 failed**（原 28 + 8） |
| 普通节点整机（容器） | `test_install.sh reality` | **32 / 32** |
| 中转节点整机（容器） | `test_install.sh relay` | **30 / 30** |
| 版本/更新相关定向回归 | `test_version_loading`、`test_reality_min_client_ver`、`test_xray_installer_metadata`、`test_shell_update_metadata`、`test_install_menu_profiles`、`test_reinstall_call_chain`、`test_relay_node`、`test_offline_commands`、`test_vps_auto_update_schedule`、`test_geodata_native` | 全部通过 |

`test_version_downgrade_guard.sh` 覆盖：数字序（`26.10.4 < 26.10.31`）、缺段补零、`v` 前缀、前导零、
四段版本、畸形输入返回 `2` 且两个方向都为假、`xray_update` 拒绝降级时**没有**触发备份
（`backup_xray_binary` 未被调用）、拒绝信息包含两侧版本、目标更新时备份仍然发生、
以及"守卫必须先于首次安装/备份调用"的顺序断言。

### 4. 阻塞项 2（候选资格流水线）——根因已定位，未修改

**根因**：上游 `XTLS/Xray-install` 在 `04e6f3b`（2026-10-31）把服务身份从"读现有 unit 的 `User=`"
改成硬编码 `User=xray`，并把 `/var/log/xray` 建成 `xray:xray 0700`
（旧版 `e741a4f` 用 `User=$INSTALL_USER`，且日志归 `INSTALL_USER_UID`）。
本仓库 3.2.11+ 通过 `xray_service_user` 读 unit 的 `User=` 再 `chown`，因此**能**适配；
但基线 `3.2.9` 把配置 `chown nobody:nogroup`，unit 却是 `User=xray` → 服务读不到 `config.json`，
于是出现资格日志里的 `permission denied` + `Xray service inactive`。

对着失败运行逐项核对后的结论：

- `3.2.9` 的 `fresh/direct/reinstall/fallback/restart-recovery` 全部因此失败
  （`failure-recovery` 在下载校验阶段就终止、`shell-first` 先升级 Shell，所以这两项通过）；
- `3.2.10/3.2.11` 只有 `restart-recovery` 失败，与上述无关，尚未单独归因。

**为什么没有直接改**：

1. API 仓库的 `qualify-legacy-upgrade.yml` 其实已经把这组组合当"已知不兼容"处理，但只在
   `pull_request` + caller 为 `Qualify legacy shell upgrades (evidence only)` 时生效，生产
   `workflow_dispatch` 走严格路径。把生产路径也改成"预期失败"等于**降低发布门禁**，
   属于策略决定（后果：3.2.9 机器上直接 `-x` 更新会坏，只有先 `-u` 升级 Shell 才安全）。
2. 真要让证据链接受"已知不兼容、无二进制证据"，还要同步改
   `collect_qualification_evidence.py`（`MODES` 硬编码、要求每个 baseline×scenario 都有
   `xray-binary.json`）与 `verify_qualification_run.py` 及其测试——这是发布证据校验链路，
   不适合在没有 CI 迭代的情况下顺手改。
3. `full-install` 矩阵里的 `xtls_only` 现在还能跑（`shell_commit` 指向 3.2.11），
   但**发布 3.2.12 后会必然失败**：该 profile 已删除，同时新增 `relay`。
   矩阵、`MODES` 常量、证据测试必须一起改（`xtls_only` → `relay`），
   且只能与 3.2.12 的 `shell_online_version` 同时上线，否则当前资格验证会因 `relay` 不存在而红。

**建议的收口顺序**（需仓库所有者确认）：

1. 先按原计划发布 3.2.12（本仓库已具备适配 `User=xray` 的能力），在同一批改动里把 API 的
   `xtls_only` 换成 `relay`（矩阵 + `MODES` + 测试）。
2. 3.2.9 直更不兼容这件事，二选一：
   - **接受**：把生产路径也按"已知不兼容"分类（必须仍以 `permission denied` 为判据，
     并在发布说明里写明"3.2.9 请先升级 Shell"），同时给证据链加"无二进制证据"的表达；
   - **不接受**：保持门禁红灯，改为给元数据加"旧 Shell 专用 installer 引脚"
     （旧 Shell 永远读旧 installer），这是一次真正的发布协议变更。
