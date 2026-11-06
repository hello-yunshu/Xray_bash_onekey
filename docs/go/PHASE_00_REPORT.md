# Phase 00 阶段报告（Go 原生重构）

> 范围：只执行 Phase 00，未进入 Phase 01；未合并 `main`、未发布版本、未改真实 VPS、
> 未执行真实迁移、未开发 Web/sing-box/插件。
> 日期：2026-11-06。

## 1. 当前基线

| 项 | 值 |
|---|---|
| 仓库 | `hello-yunshu/Xray_bash_onekey`（真实工作目录） |
| 开发分支 | `develop/go-native` |
| 分支基点 | `origin/main@59a87c6`（`Merge pull request #176`） |
| Bash 行为 pin | `4752f77c58028ac169c429fe7674c20060b30c9e` |
| `install.sh` SHA-256 | `0af8e8f222f26f02904f80bfd0e3cf5cd119b24bbde462019f0b582e1b79cfa6` |
| 版本 | `shell_version=3.3.4` |
| 基线漂移 | `4752f77→59a87c6` 只有 CI 测试/工作流 4 个提交；`install.sh`/`scripts`/`config` 无差异 |

初始工作树中的未跟踪文件 `.workbuddy/`、`docs/plans/` 未被覆盖；未使用用户既有的
`~/.cache/xray-audit/recheck-174` qualification worktree。

## 2. 实际修改的文件

### 新增：Phase 00 契约与文档

- `docs/go/BASELINE_AND_CI.md`
- `docs/go/FUNCTION_PARITY.md`
- `docs/go/RESOURCE_OWNERSHIP.md`
- `docs/go/CONFIG_BRIDGE_CONTRACT.md`
- `docs/go/RELEASE_MIGRATION.md`
- `docs/go/PHASE_00_REPORT.md`
- `docs/go-migration/phases/00_基线与契约.md`（以及 01–04 阶段计划）
- `docs/go-migration/reference/*`（TRACEABILITY、RELEASE_MIGRATION_CONTRACT、AUDIT_REPORT 等）
- `docs/go-migration/reference/PHASE00_L0_EVIDENCE.md`

### 新增：差分与门禁基础设施

- `tests/go-parity/parity/`（脚本、83 条 cases、oracle、参考 Go 探针、fail-closed 单测、evidence）
- `tests/go-parity/prototype/`（参考原型，**仅作对照，不是生产实现**）
- `.github/workflows/go-parity-stage.yml`（PR / 手动）
- `.github/workflows/go-release-qualification.yml`（`workflow_call` / 手动，按设计可红）
- `tests/fixtures/legacy/`：`generate.sh`、`README.md`、`SHA256SUMS`、6 个合成样本

### 修改

- `tests/go-parity/parity/scripts/run_parity.py`：新增 Bash oracle 环境前置检查。
  在 macOS 默认 bash 3.2 / 缺少 `/etc/os-release` 时 **BLOCKED**（退出 3），
  不再输出误导性的 `0/83`。这是本阶段发现并修掉的唯一工具缺陷。

未修改任何 Bash 产品代码（`install.sh`、`scripts/`、`config/`），未改版本号、未动 tag/Release。

## 3. 实际执行的测试与结果

### 3.1 Stage gate（Linux，bash 5，Go 1.24）

```bash
python3 tests/go-parity/parity/scripts/run_stage_gate.py --bash-repo /bash
```

| 检查 | 结果 |
|---|---|
| Bash oracle | `LIVE_PINNED_CLEAN`：独立 clone `HEAD=4752f77`，`install.sh` 干净且哈希匹配 |
| L0 差分 | **83 / 83 MATCH，0 失败** |
| Go 来源 | `BUNDLED_TOY_GO_DEMO`（非生产；`release_certified=false`） |
| Bridge 合成契约 | **39 / 39**（`production_migration_certified=false`） |
| fail-closed 单测 | **7 / 7 OK**（0.121 s） |
| 总结 | `STAGE GATE PASS: baseline/differential/Bridge/fail-closed tests only; NOT a production release` |

### 3.2 L0 逐函数记录

证据：[`functional_parity.json`](../../tests/go-parity/parity/evidence/functional_parity.json)
（每行含 `case / feature / op / args / bash{rc,stdout,stderr} / go{...} / match`）。

| 函数（Bash 基线行号） | 用例数 | 结果 | 失败原因 |
|---|---|---|---|
| [`version_compare`](../../install.sh#L422) | 14 | 全匹配 | 无 |
| [`version_series_difference`](../../install.sh#L450) | 10 | 全匹配 | 无 |
| [`format_uri_authority_host`](../../install.sh#L1682) | 9 | 全匹配 | 无 |
| [`yaml_quote_scalar`](../../install.sh#L1695) | 7 | 全匹配 | 无 |
| [`vless_urlquote`](../../install.sh#L9190) | 11 | 全匹配 | 无 |
| [`format_xhttp_path`](../../install.sh#L9213) | 8 | 全匹配 | 无 |
| [`relay_is_valid_host`](../../install.sh#L11177) | 24 | 全匹配 | 无 |

边界/快照限制见 `scope_limit`：仅 CWD/HOME/TMPDIR 快照、无主机隔离；
只覆盖 7 个纯函数，**不代表 F01–F28**。

### 3.3 环境探测（真实失败记录）

| 尝试 | 结果 |
|---|---|
| macOS `/bin/bash` 3.2 + 无 `/etc/os-release` | 原始跑出 0/83（stderr 为 `declare -A: invalid option` 与 os-release 缺失），已判定为**宿主不满足**而非 Go 差异 |
| 加入前置检查后同一命令 | `BLOCKED Bash oracle: /etc/os-release is required…`（清晰阻断） |
| Linux `ubuntu:24.04`、bash 5 | 83/83 |

### 3.4 Fixture 校验

```bash
docker run --rm -v "$PWD/tests/fixtures/legacy":/fx:ro \
  -v /tmp/xray-cirepro/bin/xray:/usr/local/bin/xray:ro ubuntu:24.04 \
  bash -c 'mkdir -p /var/log/xray; for f in reality-direct reality-nginx tls-multi custom-dns-routing; do \
    /usr/local/bin/xray -test -config "/fx/$f/xray-config.json"; done'
```

| 样本 | Xray `-test` |
|---|---|
| `reality-direct` | PASS |
| `reality-nginx` | PASS |
| `tls-multi`（ws+gRPC+xHTTP、多用户、loopback） | PASS |
| `custom-dns-routing` | PASS |
| `relay` | **未验证**（环境无 Nginx 二进制） |
| `xtls-only` | 设计上不提供可运行配置（只读拒绝样本） |

### 3.5 CI 红灯（R19）

- `main@4752f77` 的 Run `42048259341`：唯一失败 job 为 `Stats Readout (ubuntu:24.04)`；
  4 项失败集中在**首次查询**，后续查询全绿；`release-gate` 仍 success（R20 证据）。
- 根因：测试固定 `sleep 1` 未等 StatsService 就绪；上游 #176 以
  `c75d11f`/`160f01c`/`95c4cff` 修复并合入 `59a87c6`。
- 本地同镜像同 Xray 版本复跑：5/5、CI 顺序 3/3、32 CPU 压测 3/3 全绿；无法复现固定触发条件。
- 结论：**已修复（上游）**，不是产品稳定缺陷；本阶段未修改该测试。
- 本分支 push 后的 CI 结果尚未产生（本轮未触发 Actions），因此不把“分支 CI 全绿”写成已通过。

## 4. F01–F28 覆盖状态

| 维度 | 统计 |
|---|---|
| Go 迁移状态 | **28 / 28 = 未实现** |
| Bash 基线证据 | 已验证 18 项；部分验证 9 项；未验证 1 项（F25） |
| 已批准安全差异 | D1 失败 jail 通配删除、D2 limits/SELinux 全局调优、D3 远程浮动脚本、D4 XTLS 只读 |

完整逐项表见 [`FUNCTION_PARITY.md`](FUNCTION_PARITY.md)。
「已验证」只描述 Bash 基线；没有任何一项被标为 Go 已验证。

## 5. 尚未解决的问题与阻断原因

| 项 | 状态 | 原因/下一步 |
|---|---|---|
| F01–F28 Go 实现 | 未实现（阻断 Phase 02+） | Phase 01 才允许开始最小 Go 核心 |
| R01–R18 Bash 风险 | 仍存在，未修 | 不在 Phase 00 授权范围；需用户决定是否先修 Bash |
| R19 Stats flake | 已由上游修复 | 本分支 CI 未运行，需 push 后复核 |
| F25 无自动化 | 未验证 | 只能人工验证；不得签收 |
| Relay Nginx 语法 | 未验证 | 环境无 Nginx；Phase 02 用真实 Nginx 容器补 |
| 真实 ACME / 真实 VPS | 未执行 | 用户约束明确禁止；不得伪造为通过 |
| `go-release-qualification.yml` | 红灯（设计如此） | 缺生产 Go、28 个功能测试、迁移/回滚证据 |
| `release-candidate-gate` | PR 场景 skipped | 无 candidate 输入；未造假绿 |

## 6. 是否具备进入 Phase 01 的条件

**CONDITIONAL GO（有条件进入）**：

- 满足 Phase 00 出口门槛：L0 真实源码差分 83/83、F01–F28 初始矩阵、防误报发布门禁均已落地；
- 契约、资源所有权表、Bridge 契约、发布迁移契约、fixtures 均已交付；
- 条件：
  1. F25 保持「未验证」，不得在 Phase 01 签收；
  2. Relay fixture 的 Nginx 语法、真实 ACME、真实 VPS 仍为未验证，不得在文档中写成通过；
  3. R01–R18 的 Bash 风险继续以「仍成立」跟踪，不允许因为 Go 开工而忽略；
  4. 本分支 push 后的 CI 结果需复核 Stats Readout 是否稳定。

## 7. 对应 Git commit SHA

- 阶段交付提交：`__PHASE00_COMMIT__`（本文件随后单独记录最终 head）。
- 分支：`develop/go-native`（未合并 `main`）。
