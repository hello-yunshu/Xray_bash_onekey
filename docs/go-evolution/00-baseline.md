# S0 基线审计（2026-11-18）

## 结论

- 基线分支 `develop/go-native` 的受跟踪文件是干净的；工作区只有 110 个本地证据副本（文件名带 ` 1`/` 2` 后缀），已原样保留，未删除、未纳入提交。
- Go 主代码可构建、可测试：`gofmt`、`go vet`、`go test ./...` 在 Go 1.27.4 下全部通过。
- 两条 CI 红项在本地复现并修复：Go parity stage 的 evidence hygiene（5 处）与 Bash 安装安全回归的 GeoData cron 断言。
- `P0-01` 已复现并修复：`/` 根写入审计曾把完整 argv（含 `--private-key`）落盘，现改为结构化脱敏事件，并新增 `--private-key-file`。
- 发布资格保持红：28 个生产 Go 契约未实现，`check_release_gate.py` 返回 `BLOCKED`，符合预期。

## 环境矩阵

| 项目 | 值 |
| --- | --- |
| 主机 | macOS，arm64 |
| 工作目录 | `<repo>` |
| Go | `golang:1.27.4` 容器（主机未安装 Go；不使用其他 Go 版本） |
| 容器 | Docker 29.8.2，linux/arm64，native overlayfs |
| 受测镜像 | `idleleo-reality-e2e:local`（Xray 26.10.31, go1.27.3 linux/arm64） |
| 矩阵入口 | `xray-bash-go-matrix:local` |
| 磁盘 | 约 3.7 TiB 可用；CPU 10 核 |

## 代码基线

| 引用 | 值 |
| --- | --- |
| `develop/go-native` | `d4858a1150d3f83202e95aa9dfea2244832c8b3e` |
| `main` | `bad1bdeffc6626652adfe414a4a5528cde54d52d` |
| 工作分支 | `work/go-evolution-audit-20261118`（从 `develop/go-native` 创建） |
| Bash 对照固定版 | `3b2a5045fec4535e189a0b25ca27dc534945bab5`（release/3.3.6） |

未提交任何发布分支，未合并 `main`，未发布正式版本。

## 构建与测试

| 检查 | 结果 |
| --- | --- |
| `gofmt -l cmd internal` | 初始 2 个文件不合规（`internal/deploy/edit.go`、`internal/legacybridge/rill_test.go`），已修复 |
| `go vet ./...` | 通过 |
| `go test ./...` | 全部包通过 |
| `go build ./...` | 通过 |

## CI 红项复现与处置

### 1. Go parity stage：evidence hygiene

- 复现：`python3 tests/go-parity/parity/scripts/check_evidence_hygiene.py tests/go-parity/evidence tests/go-parity/parity/evidence docs` → `5 finding(s)`。
  - `docs/plans/p2/behavior-diff.md`：个人绝对路径。
  - `docs/plans/p2/specs/finalize-release/spec.md`：GitHub API 地址与 Clash fake-IP 地址。
- 处置：
  - 报告中的个人路径改为仓库相对引用。
  - `198.18.0.0/15` 按 RFC 2544 归类为非公网（fake-IP），不是主机地址。
  - `140.82.113.3` 作为环境探测记录的 GitHub API 地址加入 allowlist，附理由。
  - 4 份历史 `run.log` 中的本机路径改为 `<repo>`。
- 复验：`0 finding(s)`。

### 2. Bash Test Install：GeoData cron 断言

- 复现：`bash .github/test/test_geodata_native.sh` → `213 passed, 1 failed`，失败项为
  `cron cleanup runs only after a successful restart`。
- 根因：断言用 `sed -n '/service_restart || return 1/,+5p'` 限定 5 行窗口；`install_xray_ws_tls` 在重启与清理之间插入了证书处理块，安全顺序没有改变，但距离超过 5 行。
- 处置：改为在同一函数体内比较 `service_restart || return 1` 与 `geodata_legacy_cron_disable` 的行号先后，保留“重启成功后才停 cron”的语义，不削弱断言。
- 复验：`214 passed, 0 failed`。

### 3. Privacy Guard

- 复现：全仓扫描 `7 finding(s)`：`internal/netcfg/classify_test.go` 的文档占位 IPv4（3 处）与 4 份历史运行日志中的本机路径。
- 处置：测试夹具改用 RFC 5737 文档地址 `192.0.2.99`；日志路径脱敏。
- 复验：`0 finding(s)`。

### 4. Go parity stage 全链路复验

在干净克隆上（Go 1.27.4 + Python 3 + git + jq 的本地验证镜像）重跑：

| 步骤 | 结果 |
| --- | --- |
| `gofmt` / `go vet` / `go test ./...` | 通过 |
| A2 真实运行时对比自检 | 通过 |
| Native L0 parity | 83/83 PASS |
| Bridge 切换/中断/恢复 | 39/39 PASS，`production_migration_certified=False` |
| Stage 3 fail-closed 单测 | 7/7 PASS |
| Stage gate 汇总 | `STAGE GATE PASS`（非生产发布结论） |

说明：宿主 macOS 上 `.git` 的松散对象在容器 bind mount 下会触发 `EPERM`，导致测试内嵌 `go build` 的 VCS stamping 失败；本地验证统一加 `-buildvcs=false`（仅影响本地测试环境，不改变仓库或 CI 配置）。

### 5. 发布资格

- `check_release_gate.py` 依旧 `BLOCKED`；`FEATURE_CONTRACTS` 为 `0/28 IMPLEMENTED`。这是预期红灯，不作为阶段放行条件。

## P0 安全项

### P0-01 根写入审计泄漏材料

- 证据：`internal/host/gate.go` 原实现把 `os.Args` 原样写入 `var/log/idleleo/system-writes.log`，`--private-key` 等值会持久化。
- 修复：
  - 审计事件改为 `time/mode/operation/uid/pid/plan/flags`。
  - 仅保留少量无秘密参数值；未知参数默认脱敏；计划指纹为 argv 的单向 SHA-256 前缀。
  - 新增 `--private-key-file`，并保持 `--private-key` 兼容；两者互斥，文件大小上限 4096 字节。
  - 回归测试使用唯一 canary 扫描审计文件，并覆盖未知参数默认保护。
- 未改变：根写入的门禁条件与审计不可写即拒绝写入的行为。

## Docker 实机能力

- `idleleo-reality-e2e:local` 可用：Xray 26.10.31 + Pebble + Python 3.12 + jq 1.7 + Bash 5.2。
- `xray-bash-go-matrix:local` 为矩阵入口，当前需通过 `run_matrix.py` 调用，不能直接执行 `sh -c`。
- 宿主机为 macOS，真实根路径迁移用例按设计只能在 Linux 容器内模拟；容器内的“真实根”写入需显式 `--container` 与 `IDLELEO_ALLOW_SYSTEM_WRITES`，S0 未放宽该门禁。

## 未验证项

- 今日已有的 P2 全矩阵证据为 `tests/e2e-diff/evidence/20261118-0605-full`（M1–M10、E1–E8、OPS-32），第一阶段正在以 `goevo-s0-20261118` 重跑。
- 真实 VPS 上的 systemd/防火墙/ACME 行为不在 macOS 容器范围内，只保留为人工验证项。

## 阶段入口条件

- 基线提交：`96bc4edd`（CI 门禁修复）、`a3277875`（清理误跟踪副本）、`2a930874`（P0 审计修复）。
- 后续阶段每次提交前必须重跑：`gofmt`、`go vet`、`go test ./...`、相关 Bash 定向测试、Docker 实机用例。
- 任何测试证据写入 `tests/go-evolution/evidence/`，不得包含主机路径、公网地址或用户标识。
