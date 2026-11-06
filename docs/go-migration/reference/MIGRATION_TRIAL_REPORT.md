# 已执行的 Bash → Go 隔离迁移试验：证据与边界

## 1. 为什么要做这个试验

用户要求“真正意义上的做迁移尝试”，因此本次不仅写计划，还用 Go 标准库编译了可运行 `bridge-probe`，读取**符合真实旧仓库字段和文件结构**的模拟 VPS 文件树，准备新管理配置，调用操作系统的原子重命名真实切换测试沙盒中的 `usr/bin/idleleo`，再注入进程中断并执行独立恢复。

**此试验只测试“旧管理数据识别和管理入口切换”的最小闭环，不是生产迁移。** 不执行真实 Xray/Nginx、systemd、GitHub 下载、真实证书、Rill 或远端 VPS。

## 2. 输入从哪里来

- 旧元数据字段来自 [`install_config_reality()`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/install.sh#L9101-L9154)、`install_config_ws_only()` 和 `relay_bootstrap_role()` 的实际字段：`role`、`tls`、`shell_mode`、`id`、`privateKey`、`shortIds`、`relay_backend_host`、`relay_listen_port` 等。
- 原生 Xray JSON 结构来自 [`config/vless_reality.json`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/config/vless_reality.json) 与 [`config/vless_tls.json`](https://github.com/hello-yunshu/Xray_bash_onekey/blob/4752f77/config/vless_tls.json) 的 `inbounds/settings.clients/streamSettings`、`outbounds/routing/dns`。
- 实际路径来自 `install.sh:300–342` 和 `README.md`：`/etc/idleleo/conf/install_config.json`、`/etc/idleleo/conf/xray/config.json`、`/etc/idleleo/conf/nginx/relay-stream.conf`、`/usr/bin/idleleo`。
- 生成脚本 `probe/testdata/make_sandbox.py` 使用**合成 UUID、合成密钥、RFC 5737/3849 保留的文档 IP**；它不是任何真实用户数据，也不是从远端 VPS 导出的匿名化真实备份。

## 3. 实际执行环境

- 宿主：Linux x86-64 沙盒；Go `go1.23.2`；Go 标准库，不依赖第三方 Go 包。
- 脚本：`probe/run_migration_trial.sh`；原型源码：`probe/bridge/bridge.go`、`probe/main.go`；Go tests：`probe/bridge/bridge_test.go`。
- 执行：`go test -v ./...`、`go test -race ./...`、`go test -cover ./...`、`go vet ./...`、`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build`、真实编译的 amd64 ELF 作为“候选入口”用于切换。
- Go tests：**16/16 通过**；`bridge` 包语句覆盖率 **75.0%**，顶层 `main` 包 0%（未写 main 的 Go 单测，CLI 另做真实子进程演示）。这不代表生产 Bridge 的覆盖率。
- 构建：amd64 程序在本地运行；arm64 目标**仅交叉编译**，未在 arm64 上运行。

## 4. 已实际跑过的操作与结果

| 试验项 | 真实操作 | 结果 | 证明了什么 |
|---|---|---|---|
| Reality 节点识别 | Go 解析旧 install_config 与当前 Xray JSON；核对 primary UUID 与 REALITY privateKey | 通过 | 可以将现有结构识别成有限的 Go 意图对象 |
| 独立 relay 识别 | Go 读取 relay install_config 与 Nginx stream 文件 | 通过 | 不需要安装 Xray 才能识别 relay |
| Secret 不复制 | manager.json 只保留路径、角色、hash，无旧私钥、公钥占位符和 UUID | 通过 | 最小意图模型不需要重复保存敏感材料 |
| 自定义路由保留 | 哈希比对迁移前后 Xray JSON，包含额外 inbound client/custom outbounds、DNS/routing | 通过 | **本原型未修改原生运行配置** |
| 旧模式阻断 | 使用 `XTLS ONLY` 合成样本调用 Go `plan` | 按预期拒绝 | 不会未知地把旧不可管理状态激活为 Go |
| 混装与缺陷输入 | Relay 混入 Xray、JSON 损坏、密钥冲突、准备后源文件漂移 | 按预期拒绝 | 已覆盖少量高风险失败类别 |
| 真实替换沙盒入口 | 使用 `os.Symlink` + `os.Rename` 将 `usr/bin/idleleo` 切至实际编译 Go 程序 | 通过 | 已真正执行文件系统上的入口交接操作 |
| 独立进程中断注入 | `-fault after-swap` 在原子入口替换后 `os.Exit(86)`，另起进程读取 journal | 通过 | `ACTIVATING` 状态在进程退出后仍在磁盘上 |
| 独立恢复 | 另一个进程执行 `recover` 恢复 `/etc/idleleo/install.sh` 旧 symlink | 通过 | 在这一截断点可以恢复旧管理入口 |
| 迁移前后哈希 | sha256sum 比对 Legacy 与 Reality/relay 原始运行配置 | 完全相同 | 该测试范围内旧运行数据未改 |
| Go 管理入口自检 | clean path 进入 `COMMITTED`，直接调用切换后的编译二进制 `-mode status` | 通过 | 一条真实的文件级候选激活路径可用 |
| 缺少沙盒标记、预先存在 manager、软链逃逸 | 通过 Go 测试拒绝 | 通过 | 原型不允许直接误用真实根路径/覆盖目标 |

**演示流程摘要（机器输出保存在 `evidence/migration-trial.log`）：**

```text
Reality plan → PREPARED → ACTIVATE (injected exit=86)
→ journal ACTIVATING → recover → ROLLED_BACK
→ legacy symlink original + runtime SHA256 unchanged

Relay plan → PREPARED → ACTIVATE (injected exit=86)
→ ACTIVATING → recover → ROLLED_BACK
→ legacy symlink original + relay fragment SHA256 unchanged

XTLS ONLY → REJECTED, no new manager config

Reality clean path → PREPARED → COMMITTED
→ execute actual Go binary via switched sandbox entrypoint
→ {"role":"node","transactionStatus":"COMMITTED","runtimeUntouched":true}
```

## 5. 原型有效性及重要的发现

1. **并不需要首次迁移时重写 Xray 配置。** 先让 Go 存“运行文件路径、角色、意图与摘要”，Xray JSON 完全不动，能减少大量未知字段破坏风险。Go 未来正常变更需另做受控增量编辑器。
2. 不能简单读取一个 `install_config.json` 就激活 Go：旧元数据和实际 Xray JSON 的 REALITY/UUID 必须做基本一致性检查，否则将有风险状态误判为成功。
3. 必须把程序入口的切换视作有状态操作：原子 rename 只解决**单个目录项**的可见性，不解决配置+cron+服务多对象的全局原子性。`ACTIVATING` 的持久化 journal 和**独立恢复执行器**是必要的。
4. 用户拒绝或配置不支持时，应该**在写入新正式管理配置前**终止，保持旧 Bash。
5. 在这份原型里，已 `COMMITTED` 的状态不会接受普通 `recover` 无确认回退。正式版还必须处理 Go 接管后产生的新配置变更。

## 6. 明确没做、下一阶段必须做的内容

| 尚未验证 | 原因与对应阶段 |
|---|---|
| 完整生产 `install_config.json` 各年代变体、真实用户配置 | 本次样本是依据公开源码的合成文件；Phase 00 收集匿名化/合成的实际版本案例并做覆盖 |
| Xray `run -test`、Nginx `-t`、真实服务 active/enabled | 本沙盒没有用户的运行服务和二进制；Phase 01/02/03 完成 |
| Bash 更新时用户真实 TTY 手动确认及 Go 包下载门禁 | 原型不是旧 Bash 更新器；Phase 03 集成 |
| 证书、ACME/cron、防火墙、Rill 状态转移与恢复 | 需统一资源所有权及跨服务恢复计划；Phase 03 完成 |
| 正式 Bridge 下载链 SHA/身份信任 | 原型不访问网络；Phase 00 设计，Phase 03 集成 |
| 断电、系统重启后独立恢复 | 原型测试了真实进程提前退出，并不等价于 fsync 在真实断电场景的持久保证；Phase 03 VM 断电/重启注入 |
| ARM64、Docker、Debian/Ubuntu/CentOS 实机安装 | ARM64 仅编译，未运行；Phase 04 覆盖 |
| 生产用 Go Xray 业务核心 | 本代码只做 Bridge 最小机制证明，不具备真实安装/证书/统计等功能；Phase 01/02 需另行开发 |

## 7. 复现方式

```bash
cd probe
go test -v ./...
go test -race ./...
go test -cover ./...
go vet ./...
./run_migration_trial.sh
```

**警告：** `run_migration_trial.sh` 会清空其自己的 `../evidence/demo` 文件夹以便重建合成场景；不要将整个 `probe/` 当生产安装器运行。`bridge-probe` 需要沙盒标记 `I_ACCEPT_DISPOSABLE_SANDBOX`，不允许拿它替换真实 `/usr/bin/idleleo`。

## 8. 可复核证据文件

- `evidence/go-test.txt`：16 个 Go tests 全部通过。
- `evidence/build-validation.txt`：Go 版本、覆盖率、race、vet、amd64/arm64 文件格式与 SHA256。
- `evidence/migration-trial.log`：两种角色故障注入后的状态、恢复与哈希检查、XTLS 拒绝和 clean commit。

这份实测结果**支持 Phase 03 的架构决策**，但绝不能替代 Phase 03/04 的完整迁移验收。生产 Bridge 不应直接复用演示中的简化 Journal（原型将旧入口字节作为 JSON base64 保存，仅为测试方便；正式版需控制备份大小、权限、来源和保留周期）。
