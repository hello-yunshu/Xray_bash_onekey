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
