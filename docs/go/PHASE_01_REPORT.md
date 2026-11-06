# Phase 01 收尾报告（Go 最小核心）

- 日期：2026-11-06
- 分支：`develop/go-native`（未合并 `main`，未打 tag，未发 Release）
- 源码提交：`6fc78b63cb723e2debaef80f3adbdb236a0d27af`
- Bash 基线：`install.sh` v3.3.4，SHA-256 `0af8e8f222f26f02904f80bfd0e3cf5cd119b24bbde462019f0b582e1b79cfa6`
- 行为 pin：`4752f77c58028ac169c429fe7674c20060b30c9e`

## 0. “第一阶段”的口径

`docs/go-migration/phases/` 以 `00_阶段0...`、`01_Go最小核心.md` 编号。本报告把“第一阶段”理解为
**Phase 01（Go 最小核心）**：Phase 00 已在 `8b31d3f` 关闭（契约、所有权表、F01–F28 矩阵、夹具、L0 差分）。
本报告只验收 Phase 01 的出口门槛，不进入 Phase 02 的完整安装/业务迁移。

## 1. 结论

**Phase 01 出口：PASS（容器级证据）。** 可以进入 Phase 02；但**不具备生产发布资格**，
F01–F28 中没有一项 Go 状态为“已验证”。

- Go 质量门禁：`gofmt`/`go vet`/`go test`/`go test -race` 全绿。
- 容器 E2E：C01–C12 **35/35**（含真实 `xray -test` 校验器）。
- native L0：**83/83**，`native_l0_only=true`，`release_certified=false`。
- Stage gate：Phase 00/01 门禁 **PASS**（重跑确认无回归）。

## 2. 环境与镜像

| 项 | 值 |
|---|---|
| 宿主 | macOS，Docker Desktop LinuxKit，`linux/arm64` |
| 内核 | `7.2.12-orbstack-00394-gbecdd6130068` |
| 测试镜像 | `idleleo-phase01-test:1.24`，image ID `sha256:8af4eaa68338d882c32104e30d347f575f5c23730c6249fb82b78bebd3bab6c5` |
| 基础镜像 | `golang:1.24@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804` |
| 网络 | `--network=none`（全部 Phase 01 用例零网络） |
| 特权 | 无 `--privileged`、无 `/sbin/init` |
| 真实校验器 | Xray 25.9.11，`sha256:21cfc33fa0d74fd3b2abbed158219d4b70b5a948602ea52d59b4bc6ad8600908`（只读挂载） |

证据等级：本轮全部为 `CONTAINER_VERIFIED`，**不是** `REAL_VPS_VERIFIED`。

## 3. 改动文件

| 文件 | 内容 |
|---|---|
| `go.mod`、`cmd/idleleo`、`cmd/parity-adapter`、`internal/{compat,host,store,runtime,change,app,cli,i18n}` | Phase 01 Go 最小核心与 native L0 adapter |
| `internal/*/*_test.go` | 单元/回归测试（含锁冲突零写入、候选后缀） |
| `tests/go-parity/phase01/Dockerfile` | 固定 digest 的测试镜像 |
| `tests/go-parity/phase01/run_phase01.sh` | C01–C12 + 旧样本解析 + 真实 Xray 校验器用例 |
| `tests/go-parity/phase01/run_phase01_container.sh` | 零网络容器执行与镜像/校验器挂载 |
| `tests/go-parity/phase01/evidence/c01_c12.{md,tsv}` | 本轮 35 条证据 |
| `tests/go-parity/parity/evidence/phase01-native-l0/` | native L0 83/83 证据 |
| `tests/go-parity/parity/evidence/{functional_parity.json,bridge_*,README.md}` | 门禁重跑刷新 |
| `docs/go/DOCKER_VERIFICATION_AUDIT.md` | 审计结论与完整 digest、实测事实 |
| `docs/go/FUNCTION_PARITY.md` | F01–F28 的 Go 状态与 L0 双阶段口径 |
| `.github/workflows/go-parity-stage.yml` | 增加 gofmt/vet/test/build 与 native L0 |

## 4. 验证记录（实际命令与结果）

### 4.1 Go 质量门禁

```bash
/tmp/gotoolchain/go/bin/gofmt -l cmd internal          # 无输出
/tmp/gotoolchain/go/bin/go vet ./...                   # PASS
/tmp/gotoolchain/go/bin/go test ./...                  # PASS
/tmp/gotoolchain/go/bin/go test -race ./...            # PASS
```

### 4.2 容器 E2E C01–C12

```bash
IDLELEO_XRAY_BIN=/tmp/xray-bin/xray bash tests/go-parity/phase01/run_phase01_container.sh
```

镜像 `idleleo-phase01-test:1.24`，`--network=none`，结果：

```text
Result: 35/35 passed, 0 failed
```

关键条目：C01 零写入只读、C03 四类损坏/高版本/旧模式、C05 漂移拒绝、C06 校验失败零落盘、
C09 锁冲突零写入、C10 非 root 只读/拒绝变更、C11 双架构构建、C12 Bash 字节不变与旧入口未被覆盖、
C04 三个 Phase 00 旧样本可解析、C06.real 真实 Xray 校验器事务提交。

本轮真实执行暴露并修复的 3 个问题：

1. **C09**：锁冲突时仍写事务 journal，与持锁进程并发写同一 journal。修复为锁冲突不落任何文件。
2. **C10.1**：`mktemp` 父目录 `0700` 使 `nobody` 无法遍历，且夹具缺 metadata。修复测试夹具与目录权限。
3. **C12.3**：用例把 `version` 输出误当“旧入口被写”。修复为只检查 `/etc/idleleo/install.sh` 是否存在。

真实校验器还暴露一个实现缺陷：

4. **候选文件后缀丢失**：临时文件无 `.json`，`xray -test` 无法识别格式而拒绝合法配置。
   修复为候选文件保留目标扩展名；否则“校验器返回非零即拒绝提交”会在真实环境误杀所有变更。

### 4.3 真实 Xray 校验器

```bash
Xray 25.9.11 -test -config reality-direct|xray-config.json   # Configuration OK.
Xray 25.9.11 -test -config tls-multi|xray-config.json       # Configuration OK.
Xray 25.9.11 -test -config custom-dns-routing|xray-config.json # Configuration OK.
```

另在 `C06.real` 中完成一次完整事务：旧样本 → 端口 8443 → 候选校验 → 原子替换 → 服务空操作 →
最终配置再次 `xray -test` = 0。结论：`CONTAINER_VERIFIED`（真实二进制、容器网络）。

### 4.4 native L0（生产源码，固定 Bash 基线）

干净 clone `HEAD=6fc78b6`，独立 `cwd/home/tmp`：

```bash
python3 tests/go-parity/parity/scripts/run_parity.py \
  --bash-repo /legacy --native-go-dir /src \
  --native-package ./cmd/parity-adapter \
  --require-package github.com/hello-yunshu/Xray_bash_onekey/internal/compat \
  --require-native-l0 --evidence /out
```

结果：

```text
LIVE_PINNED_CLEAN: 83/83 MATCH; SOURCE_BUILT_NATIVE_GO_L0; release_certified=False
source_commit=6fc78b6 binary_sha256=70b73e39... native_l0_only=true
```

### 4.5 Stage gate 重跑

```bash
python3 tests/go-parity/parity/scripts/run_stage_gate.py --bash-repo /legacy
```

结果：`83/83 MATCH`、Bridge `39 / 39`、fail-closed 单测 7/7、`STAGE GATE PASS`。

### 4.6 Docker 能力审计实测

- `nginx:1.27`：包装 `events {}` + `include` 后 relay stream 片段 `syntax is ok`。
- `idleleo-systemd-probe:24.04`：`--privileged --cgroupns=host` 下 `systemctl is-system-running` = `running`。
- `debian:12`/`centos:stream10` 基础镜像无 `/sbin/init`，不能直接当 systemd 宿主。

## 5. F01–F28 Go 状态（按实际证据）

| 状态 | 功能 | 依据 |
|---|---|---|
| 部分实现（容器级） | F08 端口 | 仅 `set-inbound-port` + 真实 `xray -test`；target/serverNames/SNI Guard 未实现 |
| 部分实现（容器级） | F11 服务 | 只读探测；启停/日志未实现 |
| 部分实现（容器级） | F23 六语言 | zh/en 完整，fr/fa/ru/ko 回退英文；未逐条差分 |
| 部分实现（容器级） | F27 运维 | 只有 `status/config inspect/show`；backup/restore/purge/service-* 未实现 |
| 部分实现（容器级） | F28 展示 | `show/status` 可解析旧样本；输出契约未与 Bash 逐字段差分 |
| 未实现 | 其余 23 项（F01–F07、F09、F10、F12–F22、F24–F26） | 无生产 Go 代码 |
| 未验证 | F25 | 无自动化；已批准“不执行浮动远程脚本”，仍不能闭环 |

F25、真实 ACME（F12）、真实公网 VPS 均保持**未验证**；容器/SIMULATED 证据不得升格。

## 6. 未解决项与阻断原因

| 项 | 状态 | 阻断原因 |
|---|---|---|
| 真实 ACME 签发/续期 | 未验证 | 需公网域名 + CA；容器无真实 DNS/HTTP-01 条件 |
| 真实公网 VPS 网络/防火墙 | 未验证 | 未触碰真实 VPS（约束）；容器网络不等价 |
| systemd 宿主差异 | 容器级 | 仅验证容器 systemd，未证明宿主 init/权限/单元冲突 |
| GeoData 原生刷新两个完整周期 | 未执行 | 属 Phase 03 范围；本轮未实现 |
| amd64 实际执行 | 仅构建 | C11 只交叉编译；未在 amd64 容器执行 |
| 真实 TCP/Relay 转发 | 未验证 | 只做 Nginx 语法与容器级服务语义 |
| E2E 纳入 CI | 未接入 | 依赖 Docker + 固定 Xray 二进制；CI 当前只跑 vet/test/native L0/stage gate |
| F25 自动化 | 无 | 基线与 Go 均无自动化测试 |

## 7. 是否具备进入下一阶段

具备，条件如下：

- Phase 02 必须从“完整安装/业务能力”继续，不能把本轮容器证据当作生产验收。
- 任何 F 项要升级为“已验证”，必须有 Bash 行为差分或批准的安全修正测试，并在真实或明确等级的环境复跑。
- 发布门禁继续保持红色，直到 F01–F28 的 Go 实现与证据齐备。
