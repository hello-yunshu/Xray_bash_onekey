# P2 CI 红灯与 Bash/Go 验收缺口（2026-11-19）

代码提交：`4c986c26`（`fix(ci): authenticate parity stages and separate ANSI history`）
基线：`8ac1385f`（P1）

## 1. 三条 CI 红灯

### 1.1 Stage gate：`44424910844`

根因：`test_fail_closed.py::test_unverified_release_must_fail` 固定读取真实账本，并断言“全 PENDING、rc=2”。
账本在 `9b965843` 已签收，`check_release_gate.py` 在缺少 pinned Bash/Go/CI 参数时返回 3，测试语义与账本状态脱节。

修复：
- 测试在临时目录复制 `scripts/` 与 `cases/`，把 28 项状态改为 `PENDING_GO_IMPLEMENTATION` 后调用同一 gate，断言 `rc=2` 且输出 `pending 28`；
- 新增 `test_signed_ledger_still_needs_pinned_evidence_and_ci`：真实已签收账本无参数时仍必须 `rc=3`，并在 stderr 指明需要完整 pinned Bash checkout。

这样既不降低 gate 标准，也不再要求仓库永远停留在未签收状态。

验证：

```bash
python3 tests/go-parity/parity/tests/test_fail_closed.py
# Ran 10 tests ... OK
```

### 1.2 Preview：`44424910823`

根因：`check_preview_gate.py::check_gate_and_ledger` 要求账本“恰好 28 项且全部 PENDING”，签收后的 develop 分支每次 push 必然失败。

修复（工作流阶段条件，而非 `if: false` 伪绿）：
1. 新增 `Detect feature-ledger stage`：校验 id 恰为 F01–F28，输出 `mode=pending|signed`；账本不合法则直接失败。
2. 只有 `mode=pending` 才安装运行时依赖并运行 preview fixtures。
3. `mode=signed` 运行 `scripts/check_signed_stage.py`：
   - 校验 release gate 摘要等于 `RELEASE_GATE_SHA256`；
   - 校验 28 项全部为 `VERIFIED_GO_PARITY` / `APPROVED_SAFE_DIVERGENCE`；
   - 校验每条证据文件存在、`run.json.fixture` 匹配、`rc=0`、`rc.txt=0`；
   - 运行真实二进制的 `--help` 与 `version`；
   - 输出 `previewRun=false`、`status=NOT_APPLICABLE_SIGNED_LEDGER`、`releaseAuthority=NONE`。

该分支不会把“未运行 preview”写成 PASS，也不会获得发布权限。

新增测试：
- `test_preview_refuses_signed_ledger`：已签收账本仍必须以 `rc=2` 拒绝 preview；
- `test_signed_stage_smoke_runs_without_claiming_preview`：signed smoke 输出 `preview not run` 与 `release authority: NONE`。

工作流静态校验：`actionlint .github/workflows/go-preview-qualification.yml` → exit 0。

### 1.3 Test Install / security-regression：`44424910819`

根因：ANSI 扫描把 `tests/e2e-diff/evidence/**` 的历史抓取日志当作生产输出（32,898 处），
并要求所有测试 fixture 都带 `color-test-fixture` 注解（7 处缺失）。

修复（分类而非全局忽略 `.log`）：
- `historical-evidence`：仅 `tests/e2e-diff/evidence/**`，计入 inventory，不计生产风险；
- `test-fixture`：`tests/**`、`.github/test/**`、`i18n/tests/**`；
- 注解强制只保留在 `.github/test/**` 与 `i18n/tests/**`；
- 生产风险判定逻辑不变：`install.sh` 等普通输出仍会被扫描；
- 新增自检：captured log → history，`collect/normalize.py` → fixture，`install.sh` → production-risk。

本地实跑结果：

```bash
python3 .github/test/test_color_output.py
# Result: 73 passed, 0 failed
# INFO: ANSI inventory: total=32987, production-risk=0, docs=0,
#       test-fixtures=58, canonical=0, history=32898
```

## 2. Bash/Go 双端验收缺口

### 2.1 OPS 分类

`tests/e2e-diff/matrix.json` 新增顶层 `acceptance`：

- 总计 34 行；
- 双端数据面证据：`OPS-09`、`OPS-19`、`OPS-21`、`OPS-31`、`OPS-32`（5 行）；
- 其余 29 行最多为 `GO_ONLY_PASS`，不得写成 `DUAL_SIDE_PASS`；
- 说明字段明确“只有 dualSideVerifiedOps 有双端数据面证据”。

矩阵文件仅新增 3 行、修改 0 行结构（保持原格式）。

### 2.2 M8 ACME 拆分

`M8.bashVariants` 明确两条路径：

| 路径 | 环境 | 等级 | 说明 |
|---|---|---|---|
| `goAssisted` | `E2E_ACME=1 E2E_ACME_MODE=go` | `HYBRID_BASH_GO` | Bash 安装器驱动，但签发通过 `idleleo xray cert issue` 调用 Pebble |
| `pureBashAcme` | `E2E_ACME=1 E2E_ACME_MODE=bash` | `BLOCKED` | 一次性镜像不含 acme.sh，runner 无外网获取；不能声称纯 Bash 基线 |

驱动 `tests/e2e-diff/drivers/bash_install.sh` 已加入 pure-Bash 前置判定：
找不到 `$HOME/.acme.sh/acme.sh` 时写出 `acme-pure-bash.json`（`status=BLOCKED`）并以 3 退出，
不会安装或调用 `idleleo`。

`bash -n tests/e2e-diff/drivers/bash_install.sh` → exit 0。

## 3. 未完成 / 未运行

| 项 | 等级 | 原因 |
|---|---|---|
| 三条工作流在 GitHub 上的新一轮真实运行 | `NOT_RUN` | 本轮不执行 `git push`；需推送修复分支后由 CI 触发 |
| `DUAL_SIDE_PASS` 扩充 | `NOT_RUN` | 需要实际运行 34 行 Docker 矩阵并抓取双端数据面证据 |
| 纯 Bash ACME | `BLOCKED` | 缺少 acme.sh 与外部 Pebble 可达性 |

## 4. 复现命令

```bash
python3 .github/test/test_color_output.py
python3 tests/go-parity/parity/tests/test_fail_closed.py
bash -n tests/e2e-diff/drivers/bash_install.sh
actionlint .github/workflows/go-preview-qualification.yml
python3 - <<'PY'
import json
d=json.load(open('tests/e2e-diff/matrix.json'))
assert d['acceptance']['counts']=={'dualSide':5,'goOnly':29}
PY
```
