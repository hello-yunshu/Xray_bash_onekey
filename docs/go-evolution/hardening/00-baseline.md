# S0 基线核实（2026-11-19）

本文件记录本轮修复任务的真实起点。所有结论均来自本轮实际执行，不继承上一轮报告的“已通过”字样。

## 1. 仓库与 SHA

| 项 | 值 | 核实方式 |
|---|---|---|
| 仓库 | `https://github.com/hello-yunshu/Xray_bash_onekey` | `git remote -v` |
| 工作源分支 | `develop/go-native` | `git branch -vv` |
| `develop/go-native` HEAD | `9b965843dccc955eee8b91903749500f082271f7` | `git rev-parse develop/go-native` |
| `origin/develop/go-native` | `9b965843dccc955eee8b91903749500f082271f7` | `git rev-parse origin/develop/go-native` |
| `main` HEAD | `bad1bdef` | `git rev-parse main` |
| 固定 Bash Oracle | `3b2a5045fec4535e189a0b25ca27dc534945bab5` | 任务书指定 + `git show --stat` 可解析 |
| 修复分支 | `work/go-hardening-parity-20261119`（自 `9b965843` 创建，0 个领先提交） | `git rev-list --count 9b965843..HEAD` = 0 |
| 工作区 | 干净（仅未跟踪的本地 `idleleo` 构建产物） | `git status --short` |

`git fetch --all --prune` 已执行，无新提交。

## 2. 工具链与构建

| 项 | 值 |
|---|---|
| `go.mod` | `go 1.27.4`，`module github.com/hello-yunshu/Xray_bash_onekey` |
| 依赖 | vendored（`vendor/` 存在，`-mod=vendor`） |
| 本机 Go | 未安装于宿主 PATH；使用固定镜像 `golang:1.27.4`（Docker/OrbStack） |
| 构建命令 | `go build -trimpath -o idleleo ./cmd/idleleo` |
| 产物 | `idleleo 0.2.0-phase04 (go)`，`linux/arm64` |

宿主 `go` 不存在（`command not found`），因此所有 Go 命令在容器内执行：

```bash
docker run --rm -v "$PWD":/src -w /src \
  -e GOFLAGS=-mod=vendor -e CGO_ENABLED=0 -e GOCACHE=/tmp/gocache \
  golang:1.27.4 bash -c 'export PATH=$PATH:/usr/local/go/bin; ...'
```

## 3. 基线执行结果（真实命令与退出码）

| 检查 | 命令 | 退出码 | 结果 |
|---|---|---|---|
| gofmt | `gofmt -l ./cmd ./internal` | 0 | 无输出（CLEAN） |
| go vet | `go vet ./...` | 0 | 无告警 |
| go test | `go test ./...` | 0 | 全部包 `ok`（含 backup/change/cli/deploy/doctor/host/repair） |
| go build | `go build -o /tmp/idleleo ./cmd/idleleo` | 0 | 成功，`idleleo version` 输出 `idleleo 0.2.0-phase04 (go)` |

## 4. CI 现状（`develop/go-native` @ `9b965843`，push run 组 2026-11-18T23:56:17Z）

| 工作流 | run id | 结果 |
|---|---|---|
| Go production parity release qualification | 44424910845 | success（28/28 fixtures，功能资格） |
| Go real-root change acceptance (container) | 44424910875 | success（10/10） |
| Privacy Guard | 44424910919 | success |
| Go native artifacts | 44424910944 | success |
| **Go parity stage gate** | **44424910844** | **failure** |
| **Go preview qualification** | **44424910823** | **failure** |
| **Test Install** | **44424910819** | **failure** |

三条红灯的源码级根因（本轮重新确认）：

1. `tests/go-parity/parity/tests/test_fail_closed.py::test_unverified_release_must_fail`
   固定断言真实账本“全部 PENDING 且 rc=2”。账本已于 `9b965843` 签收（26 VERIFIED_GO_PARITY + 2 APPROVED_SAFE_DIVERGENCE），
   `check_release_gate.py` 在没有 `--bash-repo/--native-go-dir/--require-package` 时返回 3。测试语义与账本状态脱节。
2. `tests/go-parity/parity/scripts/check_preview_gate.py::check_gate_and_ledger`
   强制要求 `feature_contracts.json` 恰好 28 项且全部 `PENDING_GO_IMPLEMENTATION`。签收后的 develop 分支每次 push 必然触发该“故意失败”的 Preview。
3. `Test Install`：ANSI 扫描覆盖被 Git 跟踪的历史原始日志（约 32k 文件），且 7 处 fixture 标记缺失。需区分生产输出、测试 fixture 与历史归档，而不是全局忽略 `.log`。

## 5. 历史证据适用性

- `tests/go-parity/parity/cases/feature_contracts.json` 的 F01–F28 证据绑定在 `9b965843` 及更早提交上；本轮新提交不得复用旧 SHA 的证据。
- `tests/e2e-diff/matrix.json` 共 34 行；仅 OPS-09/19/21/31/32 为双端实测，其余约 29 行为 Go 单边/映射，不能作为 `DUAL_SIDE_PASS`。
- `tests/e2e-diff/drivers/bash_install.sh` 的 M8 分支预装 Go 并调用 `idleleo schedule install`，属于 `HYBRID_BASH_GO`，不是纯 Bash 基线。
- `docs/go-evolution/*.md` 中的 PASS 字样只作问题索引，不构成签收。

## 6. 本轮已确认的 P0/P1 代码缺陷（静态审计）

| ID | 位置 | 现象 |
|---|---|---|
| B-01 | `internal/backup/backup.go::Verify` | 只校验 manifest 声明的条目存在/哈希，不拒绝 tar 内额外未声明条目；不校验 mode；manifest 无大小上限；`io.ReadAll` 可被压缩炸弹打爆 |
| B-02 | `internal/backup/backup.go::Create` | 直接写最终路径（崩溃留半成品）；不拒绝归档写入受管树内部；不校验受管目录祖先符号链接 |
| B-03 | `internal/backup/backup.go::Restore` | 无锁、无持久化 journal；`_ = os.Remove(dst+".restore-old")` 无条件删除既有文件；SIGKILL 后无法收敛；不重建服务状态 |
| B-04 | `internal/repair/repair.go` | `os.Stat`/`os.Chmod`/`os.Chown`/`os.ReadFile` 跟随符号链接；dry-run 无写但正式运行无共享锁 |
| B-05 | `internal/backup/backup.go::extract` | 恢复暂存目录同样使用 `filepath.Join`，父级符号链接可越界 |

## 7. 本轮验收等级用语

仅使用：`DUAL_SIDE_PASS`、`GO_ONLY_PASS`、`APPROVED_SAFE_DIVERGENCE`、`FAIL`、`NOT_RUN`、`BLOCKED`、`LOCAL_RUN`、`CI_RUN`、`STATIC_ONLY`。
`exit 0`、配置 JSON 匹配、Go 单边运行都不等于双端数据面 PASS。

## 8. 复现命令（干净克隆）

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
git checkout 9b965843
docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-mod=vendor -e CGO_ENABLED=0 \
  golang:1.27.4 bash -c 'export PATH=$PATH:/usr/local/go/bin; gofmt -l ./cmd ./internal; go vet ./...; go test ./...; go build -o /tmp/idleleo ./cmd/idleleo'
```
