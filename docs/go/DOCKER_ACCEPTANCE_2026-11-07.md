# Docker Desktop 验收与修复报告（2026-11-07）

> 范围：`develop/go-native`，Bash → Go 迁移的真实功能验证、迁移演练与安全缺陷修复。
> 真实 VPS 不可用是既定前提；本报告只声明 Docker / 容器级证据，**不代表生产签收**。
> 证据目录：[tests/go-parity/evidence/docker-current/](../../tests/go-parity/evidence/docker-current/)。

## 1. 环境

| 项 | 值 |
|---|---|
| 分支 / HEAD | `develop/go-native` / `e859724`（本报告提交前） |
| main | `81e10ac`（未修改） |
| Bash pin | `0fa7052e51b9bd7e6ffb46bc86befb006034da3c`（v3.3.6） |
| 固定 Bash `install.sh` | `a8e4d850da40295303785d17bc3ee629574932b56aef9ae3905baf4e6797358c` |
| Docker | OrbStack 29.8.2 / arm64 / 10 CPU / 16 GB |
| Kernel | `7.2.12-orbstack-00394-gbecdd6130068` |
| Go | `go1.24.0 darwin/arm64`（`/tmp/gotoolchain/go/bin/go`） |
| 真实 Xray | 26.10.31（`a4a3dff`，`linux/arm64`），sha256 `5939649960de…5328` |

镜像 digest 见 [env.txt](../../tests/go-parity/evidence/docker-current/env.txt)。

### 运行方式说明（环境限制，不是产品缺陷）

macOS 上仓库的 `.git/objects` 中部分 loose object 带 `com.apple.macl` 扩展属性。
把工作区直接 bind-mount 进 Linux 容器时，读取这些对象会返回
`error: unable to open loose object …: Operation not permitted`，导致 Phase 01 的
C12.2/C12.4 假失败。处理方式是使用不含该属性的干净副本运行阶段脚本：

```bash
git clone --no-hardlinks --branch develop/go-native <repo> /tmp/xray-acceptance-repo
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase01/run_phase01_container.sh
```

副本 HEAD 与被测 HEAD 相同，未修改任何被测文件。该问题已记录为
`HOST_NOT_VERIFIED`（宿主文件共享限制），不通过跳过断言绕过。

## 2. 真实运行结果

| 阶段 | 命令 | 结果 | 证据等级 |
|---|---|---|---|
| Phase 01 L0→C12 | `tests/go-parity/phase01/run_phase01_container.sh` | **35 / 35 passed, 0 failed** | DOCKER_VERIFIED |
| Phase 02 | `tests/go-parity/phase02/run_phase02_container.sh` | **36 passed, 0 failed** | DOCKER_VERIFIED |
| Phase 03（Bridge + systemd） | `tests/go-parity/phase03/run_phase03_container.sh` | **219 passed, 0 failed** | DOCKER_VERIFIED |
| Phase 04 | `tests/go-parity/phase04/run_phase04_container.sh` | **pass=42 fail=0** | DOCKER_VERIFIED |
| L0 差分（Linux 容器） | `run_parity.py --require-live --require-native-l0 …` | **83 / 83 MATCH**，`release_certified=False` | DOCKER_VERIFIED |
| Bridge CLI 契约 | `run_bridge_fixture_suite.sh`（容器内） | **39 / 39**，`production_migration_certified=False` | DOCKER_VERIFIED |
| Stage gate | `run_stage_gate.py --bash-repo legacy`（容器内） | **STAGE GATE PASS** | DOCKER_VERIFIED |
| 精简发行版 smoke | Debian 12 / Debian trixie / CentOS Stream 10 | 三镜像 `version` + `--help` 均 `SMOKE_OK` | DOCKER_VERIFIED |
| 反向发布门禁（默认账本） | `check_release_gate.py` | `exit=2`，`RELEASE BLOCKED: pending 28; missing executable feature tests 28` | DOCKER_VERIFIED |
| 反向发布门禁（伪造全绿） | 全 `VERIFIED_GO_PARITY` + 空测试，无 CI runner | `exit=3`，`only a checked CI runner may issue …` | DOCKER_VERIFIED |
| Go 单元/契约测试 | `go test -count=1 ./...` | **exit 0**（10 个包 `ok`） | HOST_VERIFIED |
| Go 静态检查 | `go vet ./...` | **exit 0**（无输出） | HOST_VERIFIED |

一次 Phase 02 复跑出现过 `35 passed, 1 failed`：`reality tunnel data path`
因容器内 DoH（dns.google / cloudflare-dns.com）超时失败；同一命令立即复跑
`36 / 0`。该失败与产品无关，原始日志保留为
[phase02-attempt1-network-flake.log](../../tests/go-parity/evidence/docker-current/phase02-attempt1-network-flake.log)，
未删除、未改写。

### Phase 01 C12（Bash 基线零差异）

修前 `C12.1/C12.2` 失败来自真实漂移：develop 的 `install.sh` 仍是 3.3.5，
与 v3.3.6 pin 只差 `shell_version` 与一行注释（`install.sh | 5 ++---`）。
已直接采用 main 中已发布文件（sha256 `a8e4d850…`），随后 Phase 01 为 35/35；
C12.3/C12.4 均通过（发布 pin 仍可 source 出 `3.3.6`）。

### 后续变更：logrotate 修复使 C12 再次变红（预期）

D 包提交后又在同一分支提交了 `2d44d98`（logrotate `ReadWritePaths` 修复，
见 [LOGROTATE_AUDIT_2026-11-07.md](LOGROTATE_AUDIT_2026-11-07.md)）。该提交
按设计修改了 `install.sh`（+27 行），而 C12 的 pin 仍指向已发布的 v3.3.6，
因此在当前 HEAD 上复跑 Phase 01 的真实结果是：

```text
PHASE01: 33/35 passed, 2 failed
C12.1 install.sh bytes match pin            FAIL (1a2af27… != a8e4d850…)
C12.2 product code diff empty               FAIL (install.sh | 27 ++…)
C12.3/C12.4                                 PASS
```

这是门禁在正确工作（产品代码相对已发布版本发生了变更），不是回归。
只有把修复发布为新的 Bash 版本（如 v3.3.7）并推进 pin 后，C12 才能重新变绿；
发版需要用户授权，本次未做。证据：
[phase01-after-fix.log](../../tests/go-parity/evidence/logrotate/phase01-after-fix.log)、
[phase01-after-fix-c12.tsv](../../tests/go-parity/evidence/logrotate/phase01-after-fix-c12.tsv)。
上文 35/35 的结论对应提交 `a829b08`。

## 3. 代码修改清单

| 工作包 | 提交 | 内容 |
|---|---|---|
| A | `91dcc45` | 新增 `tests/go-parity/lib/docker_common.sh`（Docker 架构检测、`sha256` 跨平台、ELF 架构校验、Xray 资产解析、cgroup 挂载条件化）；Phase02–04 启动器改用该库；三个 CI workflow 的 Bash pin 统一到 `0fa7052e`；`.gitignore` 增加 `.cache/` |
| B | `48485f7` | `internal/legacybridge`：写入门禁复用 `host.RequireSystemWrite`；Prepare 在候选拷贝/快照/计划写入前完成 journal 与未完成状态检查（零覆盖）；Activate 校验入口快照；Recover 拒绝覆盖第三方入口 → `RECOVERY_REQUIRED`。`internal/deploy`：新增 config/binary/unit/metadata 与 systemd 状态快照，失败即回滚，回滚失败显式报告。`internal/release`：manifest/资产强制 HTTPS 且同源（loopback 例外）、拒绝 userinfo；health check 或 state 落盘失败恢复旧二进制，恢复失败标记 `recovery-required`。三组回归测试 |
| C | `35b7ee9` | `phase03/run_phase03.sh`：M14 改为反向断言（`-u` 有 TTY 也必须是 0 请求、入口仍为 Bash）；在 cron 自审计前用显式 `--internal-bridge-offer` + TTY 建立真实 COMMITTED 迁移。`run_bridge_contract.py`：候选二进制改为原子替换，规避 Linux `ETXTBSY` |
| D 前置 | `e859724` | `install.sh` 对齐到 main 发布的 v3.3.6（仅版本号 + 注释），使 C12.1/C12.2 反映真实基线 |
| D | 本提交 | 本报告、`FUNCTION_PARITY.md` 状态更新、`tests/go-parity/evidence/docker-current/` |

## 4. F01–F28 覆盖情况（如实标注）

判定口径：**PASS** = 在固定 digest 容器内真实执行且覆盖该功能核心路径；
**FAIL** = Go 只覆盖子集/未实现；**BLOCKED** = 环境或授权原因无法验证。
以下是**本轮验收覆盖**结论，不改变 `FUNCTION_PARITY.md` 中「正式签收 0 / 28」。

| ID | 覆盖 | 判定 | 依据（本轮） |
|---|---|---|---|
| F01 | Reality 安装 / 加 Nginx | PASS | 容器内 fresh install：systemd `active/enabled`、`User=xray`、`xray -test`、Reality 客户端隧道取回 HTTP |
| F02 | TLS ws/gRPC/xHTTP | PASS | 容器内生成三协议配置并通过真实 `xray -test` |
| F03 | none + ws | PASS | 生成配置通过 `xray -test`；非回环无确认 exit 2 且零落盘 |
| F04 | Reality 主/备负载均衡 | FAIL | 无双节点真实验收 |
| F05 | relay 独立中转 | PASS | Nginx `stream` 片段 + `nginx -t` + 容器网络 PING 回显 |
| F06 | 用户增删 / UUID | FAIL | 事务/回滚已实测，但 **UUIDv5 未实现** |
| F07 | shortId / spiderX / 映射 | FAIL | 可追加 shortId、URI 带 `sid/spx`；完整映射管理缺失 |
| F08 | 端口/target/serverNames | FAIL | 原语与校验已有；**SNI Guard 未实现** |
| F09 | `--add-upstream` | FAIL | 仅允许改写项目片段，未迁移 |
| F10 | `--tls` 版本变更 | FAIL | 仍为 `sed -i` + 重启 |
| F11 | 服务状态/启停/日志 | PASS | `service status/start/stop/restart/reload/logs` 实测；非法 unit exit 2 |
| F12 | 证书签发/续期/清理 | BLOCKED | 无公网域名/CA；仅到期监控与外部续约契约 |
| F13 | 更新事务 | FAIL | Go release 通道自身可升级；Xray/Nginx 更新未迁移 |
| F14 | 自动更新 / cron | FAIL | 原生 schedule 接管 GeoData/统计；Xray/Nginx 自动更新执行器缺失 |
| F15 | Stats / JSON / watch / reset | FAIL | 真实 statsquery、`--json`、非 root 5、API down 8；**watch/reset 未实现** |
| F16 | GeoData 热更新 | FAIL | 双文件下载→校验→原子替换→重启已实测；旧布局迁移缺失 |
| F17 | 双栈 / DNS / 防火墙 | FAIL | iptables 直写未纳入事务 |
| F18 | 分享链接 / 二维码 / Clash | FAIL | URI 派生已实测；二维码未实现 |
| F19 | 备份/恢复/保留重装 | FAIL | 保留配置重装实测；`backup/restore` CLI 未实现 |
| F20 | Fail2ban | FAIL | 批准的安全差异：不得删除第三方 jail |
| F21 | 流量阻断 / 自定义路由 | FAIL | 规则生成未完整迁移 |
| F22 | Rill 观察/诊断/授权/卸载 | FAIL | 只读 `rill status` 与迁移状态投影；安装/诊断/授权/两阶段卸载缺失 |
| F23 | 六语言 | FAIL | zh/en 完整，其余回退英文；未逐条差分 |
| F24 | Docker 交付 | FAIL | 不能假设宿主 systemd DBus |
| F25 | TCP 优化 / 测速 | BLOCKED | 批准的安全差异：不执行浮动远程脚本 |
| F26 | XTLS ONLY 旧模式 | PASS | audit 识别 `legacy-xtls-removed`、prepare exit 3、入口/cron 不变、无 journal |
| F27 | backup/restore/purge/service-* | FAIL | service 子命令与 uninstall 已实测；`backup/restore/purge` CLI 缺失 |
| F28 | 运行态 / 分享展示 | FAIL | `status/show/stats` 只读路径实测；输出契约未逐字段差分 |

汇总：**PASS 6**（F01/F02/F03/F05/F11/F26）；**BLOCKED 2**（F12/F25）；
**FAIL 20**；正式签收 **0 / 28**（迁移未完成，未把容器级子集写成完成）。

## 5. 遗留问题与阻断原因

1. **真实 VPS 未验证**：所有结论仅到 `CONTAINER_VERIFIED`，`HOST_NOT_VERIFIED`。
2. **C12 环境限制**：macOS `com.apple.macl` 导致容器读 git 对象 EPERM；已用干净 clone
   运行并保留日志，未跳过断言。
3. **Phase 02 外部 DNS 抖动**：一次 DoH 超时导致 1 项失败，复跑通过；两次日志都在证据目录。
4. **发布门禁仍为红**：28 项 feature contract 全部 pending、28 个可执行 feature test 缺失；
   反向测试证明伪造全绿与 JSON 状态都无法解锁发布。
5. **未做真实 VPS 操作、未改 main、未发 Release。**

## 6. 复现命令

```bash
# 干净副本（规避宿主 xattr 导致容器读 .git 对象 EPERM）
git clone --no-hardlinks --branch develop/go-native <repo> /tmp/xray-acceptance-repo

# Phase 01–04
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase01/run_phase01_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase02/run_phase02_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase03/run_phase03_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase04/run_phase04_container.sh

# L0（Linux 容器，固定 Bash pin + 干净 Go checkout）
docker run --rm --network=none -v /tmp/xray-bash-clone:/bash:ro \
  -v /tmp/native-src-final:/native:ro -w /native idleleo-phase01-test:1.24 bash -c \
  'export PATH=/usr/local/go/bin:$PATH HOME=/tmp; PYTHONPATH=/native/tests/go-parity/parity/scripts \
   python3 /native/tests/go-parity/parity/scripts/run_parity.py --bash-repo /bash --require-live \
   --native-go-dir /native --native-package ./cmd/parity-adapter \
   --require-package github.com/hello-yunshu/Xray_bash_onekey/internal/compat \
   --require-native-l0 --evidence /tmp/l0'

# Stage gate（含 Bridge 39 项与 fail-closed 单测）
docker run --rm -v /tmp/xray-bash-clone:/legacy:ro -v /tmp/xray-acceptance-repo:/current \
  -w /current idleleo-phase01-test:1.24 bash -c \
  'export PATH=/usr/local/go/bin:$PATH HOME=/tmp; PYTHONPATH=/current/tests/go-parity/parity/scripts \
   python3 /current/tests/go-parity/parity/scripts/run_stage_gate.py --bash-repo /legacy'

# 反向发布门禁
cd tests/go-parity/parity && PYTHONPATH=scripts python3 scripts/check_release_gate.py

# Go 测试与静态检查
PATH=/tmp/gotoolchain/go/bin:$PATH go test -count=1 ./...
PATH=/tmp/gotoolchain/go/bin:$PATH go vet ./...
```
