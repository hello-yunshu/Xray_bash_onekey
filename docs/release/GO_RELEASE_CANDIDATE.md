# Phase 04 — Go 发布候选与准入门禁

> 状态：**候选，未发布**。未合并 `main`、未打 tag、未发 Release。
> 证据等级：`CONTAINER_VERIFIED`（固定 digest 容器内真实执行）。
> 这**不是** `REAL_VPS_VERIFIED`，也不是发布授权。

## 1. 候选身份

| 项 | 值 |
|---|---|
| 分支 | `develop/go-native` |
| 源码提交（产物 `sourceCommit`） | `a1e00850fc6940934df3add83b18c5ec7a95f5c9` |
| 版本 | `0.2.0-phase04`（由 `-ldflags -X ...cli.Version` 写入） |
| 通道 | `channel=go`，`schemaVersion=1` |
| 构建 Go | `go1.24.0 darwin/arm64`（`CGO_ENABLED=0`，目标 Linux） |
| 构建脚本 | [`packaging/build-go-release.sh`](../../packaging/build-go-release.sh) |
| 构建参数 | `-trimpath -buildvcs=false -ldflags "-s -w -X ...cli.Version=$VERSION"` |

> 产物只在 `a1e0085` 上构建一次；本文件与同批文档提交只改文档，不改二进制，
> 因此 `sourceCommit` 与资产哈希保持对应关系。

## 2. 双架构产物

构建命令（真实执行）：

```text
VERSION=0.2.0-phase04 OUT_DIR=/tmp/phase04-release bash packaging/build-go-release.sh
release-dir=/tmp/phase04-release
version=0.2.0-phase04 commit=a1e00850fc6940934df3add83b18c5ec7a95f5c9 go=go1.24.0
9f7a5ab3f607eda6de1e55d87fff10ae927f4ce649ea578358d5db906a81d89e  idleleo-linux-amd64
0177eed4cc4879e3b1ed12cc39792755f3f1965305b5966456c125d334d43053  idleleo-linux-arm64
```

| 架构 | 资产 | SHA-256 | Size (bytes) |
|---|---|---|---|
| linux/amd64 | `idleleo-linux-amd64` | `9f7a5ab3f607eda6de1e55d87fff10ae927f4ce649ea578358d5db906a81d89e` | 6959288 |
| linux/arm64 | `idleleo-linux-arm64` | `0177eed4cc4879e3b1ed12cc39792755f3f1965305b5966456c125d334d43053` | 6488248 |

`SHA256SUMS` 与 `manifest.json` 已复制到 [`assets/go/`](../../assets/go/)。
仓库内 `assets/go/manifest.json` 的 `sourceCommit`、两个哈希与 size 与上表逐字段一致。

## 3. 真实执行证据（不是“仅编译成功”）

两个产物分别在各自架构的固定 digest 容器内执行：

```text
== amd64 ==
idleleo 0.2.0-phase04 (go)
exit=0
== arm64 ==
idleleo 0.2.0-phase04 (go)
exit=0
--- host sha256 ---
9f7a5ab3f607eda6de1e55d87fff10ae927f4ce649ea578358d5db906a81d89e  /tmp/phase04-release/idleleo-linux-amd64
0177eed4cc4879e3b1ed12cc39792755f3f1965305b5966456c125d334d43053  /tmp/phase04-release/idleleo-linux-arm64
```

容器：`ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`，
`--platform linux/amd64` / `linux/arm64`。

## 4. Manifest 真实下载与校验

在 arm64 容器内用仓库内 `assets/go/` 作为固定 origin（`manifest.json` 与两个资产
原样提供），真实执行 `update check`：

```text
state=available platform=linux-arm64 current= latest=0.2.0-phase04 verified=true
asset=idleleo-linux-arm64 size=6488248 sha256=0177eed4cc4879e3b1ed12cc39792755f3f1965305b5966456c125d334d43053
detail=no applied Go release recorded; the channel can install this version
check-exit=0
idleleo 0.2.0-phase04 (go)
```

origin 访问日志：

```text
127.0.0.1 - - [07/Nov/2026 01:38:22] "GET /manifest.json HTTP/1.1" 200 -
127.0.0.1 - - [07/Nov/2026 01:38:22] "GET /idleleo-linux-arm64 HTTP/1.1" 200 -
```

这说明：manifest schema、平台选择、size 与 SHA-256 校验、真实 HTTP 下载路径均走通。

## 5. 代码质量门禁

```text
go test ./...  → test-exit=0
go vet ./...   → vet-exit=0
go version     → go version go1.24.0 darwin/arm64
```

全部包通过或 `[no test files]`；无第三方依赖，无 `go.sum` 外部模块。

## 6. 发布准入门禁（仍为红灯）

`check_release_gate.py` 真实执行：

```text
gate-exit=2
RELEASE BLOCKED: pending 28; missing executable feature tests 28; JSON statuses alone never grant success
PENDING: F01,F02,F03,F04,F05,F06,F07,F08,F09,F10,F11,F12,F13,F14,F15,F16,F17,F18,F19,F20,F21,F22,F23,F24,F25,F26,F27,F28
MISSING TESTS: F01,F02,F03,F04,F05,F06,F07,F08,F09,F10,F11,F12,F13,F14,F15,F16,F17,F18,F19,F20,F21,F22,F23,F24,F25,F26,F27,F28
```

- `tests/go-parity/parity/cases/feature_contracts.json` 仍为 28×`PENDING_GO_IMPLEMENTATION`，
  **本轮没有、也不允许**通过改 JSON 状态获得发布授权。
- `tests/go-parity/parity/features/F01_test.py` … `F28_test.py` 均不存在。
- [`.github/workflows/go-release-qualification.yml`](../../.github/workflows/go-release-qualification.yml)
  的检出路径（`current/go`）与 `REQUIRED_PRODUCTION_PACKAGE` 与本仓库根模块布局不一致，
  即使状态全部完成也不能直接执行；本轮未修改该工作流。
- 因此 **Go Release 不得发布**，`assets/go/manifest.json` 只作为候选记录，
  不构成“已发布资产”。

## 7. 当前 Ubuntu Stats CI 红灯定位

| 项 | 事实 |
|---|---|
| 失败 run | `42048259341` |
| 失败 job | `Stats Readout (ubuntu:24.04)` |
| run head | `4752f77c58028ac169c429fe7674c20060b30c9e` |
| 失败簇 | `FAIL query rc!=0` → `table missing fields` → `zero-traffic empty-state missing` → `repeat query differs` |

根因与修复提交的 ancestry 事实（真实执行）：

```text
95c4cff NOT-ANCESTOR
160f01c NOT-ANCESTOR
c75d11f NOT-ANCESTOR
a1e0085 NOT-ANCESTOR
4752f77 Merge pull request #175 from hello-yunshu/i18n/auto-translations
```

结论：失败 run 使用旧的 readiness 检查（`statsquery` 丢弃输出），慢 runner 上
listener 已存在但 Stats API 尚未就绪；`95c4cff`（打印 stderr）、`160f01c`
（readiness 改为 `statssys | grep Uptime`）与 `c75d11f` 都不在失败 run 的 ancestry 内。

当前代码在 amd64 + 真实 tmux 环境完整复现（固定 digest 容器、`XRAY_BIN` 在 PATH）：

```text
Summary: PASS=47 FAIL=0
repro-exit=0
```

即：**原失败簇当前已不能复现**；但候选分支尚未在 GitHub Actions 上得到绿色 run
（该工作流只对 `main` push / PR / dispatch 触发，本轮未创建 PR），
所以“CI 绿灯”这一项仍未满足，发布继续阻断。

## 8. 候选结论

| 项 | 结论 |
|---|---|
| 双架构构建 | 通过（真实执行 exit 0） |
| manifest 校验 | 通过（真实下载 + SHA 匹配） |
| 单元/静态检查 | 通过（`go test` / `go vet` exit 0） |
| F01–F28 发布授权 | **未通过**（28 pending + 28 missing tests） |
| 候选 CI run | **未获得**（无绿色 Actions run） |
| 是否可发布 | **否** |
