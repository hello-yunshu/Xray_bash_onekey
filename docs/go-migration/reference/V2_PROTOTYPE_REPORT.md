# Go Bridge 原型 v2：实际执行与验证记录

## 定位

这是对 v4 附带原型进行**重新编写与增量加固**的沙盒级证明程序；不是完整的 Go 管理器，不负责 Xray/Nginx systemd 和定时任务，也不提供正式 Bash→Go 发布入口。

## v2 的可核验实现

- 纯读取 `Inspect`：识别旧 Bash 的 Reality/TLS/None 与 relay 最小字段，保留原 Xray/Nginx JSON 文件，独立拒绝旧 XTLS ONLY 和角色矛盾。
- 准备阶段从受信操作参数取得候选 SHA256 pin，先实际运行候选 `--bridge-self-check` 协议响应，检查 Schema、GOOS、GOARCH，再写入阶段日志。
- `PREPARING` 在写入 manager 前先落盘、每步同目录临时文件 + rename + file/dir `fsync`；避免仅因两次文件写入间进程退出而无日志。
- 原正式入口是符号链接或普通文件：将其类型、相对目标或 SHA/权限记录在 Journal，普通入口字节保存在**独立 0600 备份**，不嵌入 Journal。
- `PREPARED → ACTIVATING → COMMITTED`，并支持在准备前半、写候选 manager 后、设置 ACTIVATING 后、入口实际切换后四类注入中断。
- 激活前验证旧配置/运行文件哈希、旧入口身份、候选二进制 SHA/selfcheck、manager hash、入口备份 hash；不匹配拒绝替换。
- 恢复先判断当前入口确实是旧入口或本次交易切出的候选；若出现第三方入口或 manager 内容漂移，则 `RECOVERY_REQUIRED` **拒绝覆盖**。
- Linux `flock` 防止两个原型事务同时进入，Recovery/Activate 独立进程运行。已提交状态不被隐式回滚。
- 状态查看仅依赖 Journal 的事实，不因回滚后 manager 不存在而报错。

## 本轮执行结果

| 测试 | 状态 | 证据 |
|---|---|---|
| `go test -count=1 -race -v ./...` | **23/23 通过** | `evidence/v2-go-test-race.txt` |
| `go vet ./...` | 通过 | `evidence/QA.txt` |
| Go Linux amd64 静态交付编译 | 通过并本机执行 | `evidence/build-info.txt` |
| Go Linux arm64 静态交付编译 | 通过，未在 ARM 运行 | `evidence/build-info.txt` |
| Reality + TLS + relay，进程异常退出后独立恢复 | 三种场景通过 | `evidence/v2-migration-trial.txt` |
| 旧 XTLS ONLY 只读扫描阻断 | 通过 | `evidence/v2-migration-trial.txt` |
| 正常切换入口后直接调用新 Go 二进制 | 通过 | `evidence/v2-migration-trial.txt` |
| 恢复后运行原 Bash 入口 | 通过（合成 Bash，可执行的相对软链） | `evidence/v2-migration-trial.txt` |

注意：v4 附带的旧 Bash 入口在沙盒里是指向宿主 `/etc/idleleo/install.sh` 的绝对软链；v2 将此测试软链改成指向同一沙盒内 `../../etc/idleleo/install.sh` 的等价形式，因此可以实际执行旧脚本作为交接验证。

## 与正式版本仍存在的边界

1. **可信 pin 来源未实现**：测试命令的 SHA256 是从本地编译得到；生产必须从可信、固定版本的 Release 元数据或经过独立签名的产物清单获得，单纯 pin 并不能认证发布者。
2. **候选 self-check 仅验证协议**，没有验证候选是否真正完成 Go 业务功能、配置解析/证书/服务运行。正式 Bridge 应额外运行只读的 `status` / 配置一致性与服务健康检查。
3. **原型事务只覆盖入口文件与 manager.json**，不覆盖 cron、systemd、Go 二进制部署、证书、GeoData、Rill，因此**无法验证生产迁移时这些资源的原状态恢复**。
4. **完全模拟的合成配置**，只使用仓库真实字段与模板形状，不代表实际 3.3.4 及更老版本全部历史配置；某些有效安装模式仍会被“能力未知”拒绝，正确行为是等正式版本明确支持再迁移。
5. 运行时无真实 systemd、Xray `-test` 或 Nginx `-t`；未验证端口、客户端真实握手、更新触发、卸载或重配置。
6. 所有沙盒保护依赖用户提供的 `.idleleo-probe-sandbox` 标记。该标记是防误操作限制，不等于安全沙盒或可信权限边界。禁止安装到生产 VPS。
7. `flock` 仅是本原型自己的锁，生产还必须与旧 Bash `/run/lock/idleleo-update.lock`、ACME/更新/GeoData 的互斥协调；处理跨设备路径、损坏 Journal 和 root 所有权。
8. 没有模拟真实断电对磁盘写入顺序、内核缓存与文件系统的全部影响；原型 `fsync` 对普通文件和目录提供了较好的测试基础，但并非跨资源全原子事务。

**结论：** v2 相比 v4 确实关闭了已复现的三个高风险逻辑缺口，并提供更好的崩溃后恢复样板；仍需 Phase 00–04 的完整生产实现及真实运行验收。
