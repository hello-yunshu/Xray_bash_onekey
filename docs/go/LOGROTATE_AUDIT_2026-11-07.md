# logrotate 缺陷复核与修复（2026-11-07）

复核对象：软路由侧对一台 Ubuntu、`install.sh` 为 release-managed v3.2.8 的真实部署机
的只读诊断结论。以下判定均以仓库源码、可执行探针与真实 systemd 行为为准。

- 结论：**疑似缺陷 A 成立**（master / 3.3.6 仍成立）；**疑似缺陷 B 成立**
  （v3.2.8 / v3.2.9 成立，master 已修且完整）。
- 修复：`develop/go-native` 新增 logrotate 的 systemd drop-in，单独提交；
  未合并 main、未发布 Release。
- 证据：[tests/go-parity/evidence/logrotate/](../../tests/go-parity/evidence/logrotate/)。

## 1. 疑似缺陷 A：`/usr` 只读导致轮转 EROFS

**判定：成立（当前 master / v3.3.6 仍成立）。**

证据链：

1. [install.sh](../../install.sh#L298) `local_bin="/usr/local"`，
   [install.sh](../../install.sh#L332) `nginx_dir="${local_bin}/nginx"`
   → nginx 日志目录固定为 `/usr/local/nginx/logs`。
2. [install.sh](../../install.sh#L8901-L8907) 生成的
   `/etc/logrotate.d/xray_log_cleanup` 以 `${nginx_dir}/logs/*.log` 为轮转目标，
   并在此目录执行 `create 640 <worker>`。
3. Ubuntu 24.04 自带的 `logrotate.service` 含 `ProtectSystem=full`
   （见 [ubuntu-logrotate-unit.log](../../tests/go-parity/evidence/logrotate/ubuntu-logrotate-unit.log)），
   `/usr` 在单元命名空间内只读，且没有针对 `/usr/local/nginx/logs` 的
   `ReadWritePaths`。
4. 真实 systemd 探针（[protect-system-full.log](../../tests/go-parity/evidence/logrotate/protect-system-full.log)）：
   - 无 drop-in：`mv` 失败，journal 为
     `mv: cannot move '/usr/local/nginx/logs/access.log' …: Read-only file system`；
   - 用真实 `logrotate -f` 复现了同一条外部报错：
     `error renaming /usr/local/nginx/logs/access.log.3.gz to /usr/local/nginx/logs/access.log.4.gz: Read-only file system`。

### 为什么 `logrotate --debug` 抓不到

[install.sh](../../install.sh#L8921) 在安装前跑 `logrotate --debug`。`--debug`
只打印“将要做什么”，不执行 rename / truncate / compress，进程也不在
`logrotate.service` 的 `ProtectSystem=full` 命名空间里。探针第 6 项显示：
同一个配置在 `ProtectSystem=full` 下 `--debug` 退出 0，而真实轮转退出 1。
因此这条自检只能验证语法与路径存在性，不能验证沙箱可写性。

### 纯 Xray 用户是否中招

不中招（探针第 5 项）：未安装 nginx 时该 glob 无匹配，配合 `missingok`
logrotate 直接成功退出，不会对缺失路径做 rename。风险只存在于
`/usr/local/nginx/logs` 里确实有日志的主机（本报告中的部署机即属此类），
包括“曾装过 nginx 但已停用、日志目录与文件仍在”的机器。

## 2. 疑似缺陷 B：v3.2.8 的 xray 段轮转无效

**判定：成立（v3.2.8 / v3.2.9）；master 已修复且修复完整。**

v3.2.8 证据（`git show v3.2.8:install.sh`）：

```text
7626    echo "/var/log/xray/*.log ${nginx_dir}/logs/*.log {" > "$logrotate_config"
7627        weekly
7628        rotate 3
7629        compress
7630        missingok
7631        notifempty
7632        # create 640 nobody <nobody-group>
7635    echo "}" >> "$logrotate_config"
```

- 单段共享块，xray 与 nginx 用同一套策略；
- 没有 `copytruncate`，也没有 `postrotate`：logrotate 执行 rename，
  而 xray 进程仍持有旧 inode；
- `create 640 nobody <group>` 让新建的 `access.log` 属主变成 nobody，
  xray 用户（`User=xray`）即便拿到新路径也写不进去。

真实复现（[v328-no-copytruncate.log](../../tests/go-parity/evidence/logrotate/v328-no-copytruncate.log)）：
用持久的 fd 3 模拟 xray 打开日志，轮转后

```text
-rw-r----- 1 nobody nogroup  0 access.log        # 新文件，0 字节
-rw-r----- 1 nobody nogroup 32 access.log.1.gz   # 旧 inode 被压缩
new access.log bytes=0
```

即：xray 继续写旧 inode，新文件不再增长；压缩后旧 inode 的数据最终不可见。

### master 是否修好、是否完整

修复提交 `4cb86a8`（`fix: repair log rotation and bump shell 3.2.10`），
首次随 **v3.2.10** 发布。当前模板（[install.sh](../../install.sh#L8893-L8914)）：

- xray 段：`copytruncate`；
- nginx 段独立：`create 640 ${nginx_user} ${nginx_group}` +
  `sharedscripts` + `postrotate` 调 `${nginx_dir}/sbin/nginx -s reopen`；
- nginx 的 worker 用户/组由 `get_nginx_worker_user` /
  `get_nginx_worker_group`（[install.sh](../../install.sh#L4507)）解析，带回退。

完整性判断：

- `copytruncate` 与 `create` 不会“冲突”：`copytruncate` 段中没有 `create`；
  `create` 只在 rename 语义下有意义，而 `copytruncate` 不 rename。
- `postrotate` 只覆盖 nginx 是**有意为之**：Xray 没有 reopen 信号，
  `SIGHUP` 不会重新打开日志文件，只能用 `copytruncate`；
  nginx 支持 `-s reopen`，用 `create` + 精确属主更安全。
- 因此 master 的修复对两侧都有效，不需要再给 xray 加 `postrotate`。

### 3.2.x 存量用户的实际影响

- v3.2.8 / v3.2.9 的机器上，磁盘上的旧配置不会因为升级而自动改变：
  `setup_auto_clean_logs` 是菜单里的交互动作，自动更新不会重写它。
- 因此这些机器会持续“轮转后新日志不增长”，直到用户在 ≥ v3.2.10 上
  **重新执行一次「自动清理日志」设置**（或手工替换配置）。
- 若用户曾手工修改过该文件，重跑设置会覆盖其修改；这是本次选择
  “不自动改写”的代价（见 [DECISIONS.md](DECISIONS.md) D-003）。

## 3. 同类审计：写 `/usr` 或依赖沙箱可写路径的生成物

| # | 生成物 | 路径 / 依赖 | 风险 | 说明 |
|---|---|---|---|---|
| 1 | logrotate nginx 段 | `/usr/local/nginx/logs`，`logrotate.service` 的 `ProtectSystem=full` | **高（已修）** | 本次缺陷 A；drop-in 放行 |
| 2 | logrotate xray 段 | `/var/log/xray` | 低 | `/var` 在 `ProtectSystem=full` 下可写 |
| 3 | logrotate `postrotate` | 调 `/usr/local/nginx/sbin/nginx -s reopen` | 低 | 只读 pid/配置；失败时 error log 也落在 #1 目录，已被 drop-in 覆盖 |
| 4 | nginx.service | [install.sh](../../install.sh#L9966-L9983) 生成，`PIDFile`/日志均在 `/usr/local/nginx/logs` | 中 | 本仓库未加 `ProtectSystem`，当前可用；若用户/发行版加固为 `ProtectSystem=full` 会重现 A |
| 5 | xray.service | 上游 `xray-install` 生成，`XRAY_LOCATION_ASSET=/usr/local/share/xray`（只读） | 低 | 运行时不写 `/usr`；日志在 `/var/log/xray` |
| 6 | idleleo-schedule.service | [internal/schedule/schedule.go](../../internal/schedule/schedule.go#L240-L248) 生成，无 `ProtectSystem` | 低 | 写 `/etc/idleleo/share/xray` 与 `/var/lib/idleleo`，不受限 |
| 7 | Rill agent 单元 | `systemd/*.service`，`ProtectSystem=strict` + 精确 `ReadWritePaths` | 低 | 已审计路径均在 `/var`、`/run`、`/etc`，`/opt` 为只读 |
| 8 | cron（auto_update/ssl_update/geo_update/xray_stats） | 写 `/usr/local/bin/xray`、`/usr/local/nginx` | 低 | cron 无沙箱；属特权但运行期可写 |
| 9 | 安装期 `/usr/local/share/xray`、`/usr/local/etc/xray` 符号链接 | 只读入口 | 低 | 仅安装/卸载时由 root CLI 写，不在 systemd 沙箱内 |
| 10 | 证书目录 | `/etc/idleleo/cert` | 低 | `/etc` 在 `ProtectSystem=full` 下只读，但写证书的进程不跑在该沙箱内 |

## 4. 修复内容

**代码**（[install.sh](../../install.sh#L8930-L8948)）：

生成配置后写入
`/etc/systemd/system/logrotate.service.d/10-idleleo-readwrite.conf`：

```ini
[Service]
ReadWritePaths=-${nginx_dir}/logs
```

- `-` 前缀：目录不存在时忽略（纯 Xray 用户不计失败）；
- 随后 `systemctl daemon-reload`（失败忽略，非 systemd 主机退回原行为）；
- 卸载路径同步删除该 drop-in（[install.sh](../../install.sh#L10979-L10984)）；
- 路径可用 `LOGROTATE_DROPIN_DIR` 覆盖，供测试隔离。

**回归测试**（[.github/test/test_log_rotation.sh](../../.github/test/test_log_rotation.sh)）
扩展现有套件，新增两项断言：

1. drop-in 存在且含 `[Service]` 与 `ReadWritePaths=-${nginx_dir}/logs`；
2. 写入后有 `systemctl daemon-reload` 调用。

**真实沙箱验证**：特权 Ubuntu 24.04 systemd 容器内用 `systemd-run`
比较「无 drop-in / 有 drop-in」，并跑真实 `logrotate -f`。

## 5. 回归结果

| 检查 | 结果 | 证据 |
|---|---|---|
| 修复前跑新测试 | **10 passed, 2 failed**（两条 drop-in 断言失败） | regression-test.log |
| 修复后跑新测试 | **12 passed, 0 failed** | regression-test.log |
| `bash -n install.sh` | exit 0 | 本次会话 |
| 真实 `logrotate -f`，无 drop-in | exit 1，`Read-only file system` | protect-system-full.log |
| 真实 `logrotate -f`，有 drop-in | exit 0，生成 `access.log.1.gz` 与新 `access.log` | protect-system-full.log |
| `logrotate --debug`，`ProtectSystem=full` | exit 0（证明自检抓不到） | protect-system-full.log |
| 纯 Xray 配置（无 nginx 目录） | exit 0，无错误 | protect-system-full.log |
| Phase 01（修复提交后复跑） | **33/35**：C12.1/C12.2 红，C12.3/C12.4 绿 | phase01-after-fix.log |

最后一行是预期的门禁反应：C12 校验 `install.sh` 与已发布 pin（v3.3.6）零差异，
而本修复按设计改动了 `install.sh`（+27 行）。门禁没有误报，只有发版并推进 pin
后才会重新变绿；在此之前如实保留红色。

## 6. 2026-11-08 独立复核（A–D 轮次追加）

为回应“独立复核外部报告”的要求，本轮不采信上文结论，重新从仓库取证：

| 复核项 | 方法 | 结果 |
|---|---|---|
| A：`/usr` 只读 | 读 [install.sh](../../install.sh#L298) `local_bin="/usr/local"`、[install.sh](../../install.sh#L332) `nginx_dir`；读当前模板 [install.sh](../../install.sh#L8901-L8914)；核对 Ubuntu 24.04 单元 `ProtectSystem=full` | **成立**；`/usr/local/nginx/logs` 不在任何 `ReadWritePaths` 中 |
| A：修复 | 读 [install.sh](../../install.sh#L8930-L8949) 的 drop-in 生成与 `daemon-reload`；读卸载清理 [install.sh](../../install.sh#L10979-L10984) | 已修复，`ReadWritePaths=-${nginx_dir}/logs` 与实际路径一致 |
| B：v3.2.8 轮转无效 | `git show v3.2.8:install.sh`（7626–7635 行）确认共享段、无 `copytruncate`、无 `postrotate`、`create 640 nobody` | **成立**；v3.2.10+ 已修 |
| B：master 是否完整 | 读当前模板：xray 段 `copytruncate`，nginx 段独立 `create` + `sharedscripts` + `postrotate` + `nginx -s reopen` | 完整；两侧语义分别正确 |
| 回归 | 本轮真实执行 `bash .github/test/test_log_rotation.sh` | **12 passed, 0 failed** |
| 语法 | `bash -n install.sh` 与 `scripts/*.sh` | 全部 exit 0 |
| 修复归属 | `git merge-base --is-ancestor 2d44d98 develop/go-native` | 成立：修复已在 `develop/go-native` 与远端 |

**判定不变**：A 成立（当前 master / v3.3.6 仍成立）；B 成立（仅 v3.2.8 / v3.2.9）；
修复已在 `develop/go-native`，无需重复提交。上文第 3 节同类审计的 10 项清单本轮复核
未发现新增 `/usr` 可写依赖。

## 7. 是否需要发版才对存量用户生效

**需要发版。**

- 缺陷 A 的修复在 `install.sh` 里，只有用户拿到包含该修复的新版本并重新执行
  「自动清理日志」设置，才会写入 drop-in；已在运行的主机不会自动获得修复。
- 缺陷 B 对 v3.2.8 / v3.2.9 用户仍是坏的；他们需要先升级到 ≥ v3.2.10
  （该版本已含 B 的修复），再重跑一次设置。
- 本次只提交到 `develop/go-native`，不合并 main、不打 tag、不发 Release；
  发版按用户授权另行执行。
- 一旦发版，仍需在 Release 说明中写明“升级后需重跑「自动清理日志」”，
  否则存量用户会误以为升级即自动修复。
