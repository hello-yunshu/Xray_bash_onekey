# P2 CI 红灯与 Bash/Go 验收缺口（2026-11-19）

代码提交：`4c986c26`（`fix(ci): authenticate parity stages and separate ANSI history`）
基线：`8ac1385f`（P1）

## 1. 三条 CI 红灯

### 1.1 Stage gate：`44424910844`

根因：`test_fail_closed.py · test_unverified_release_must_fail` 固定读取真实账本，并断言“全 PENDING、rc=2”。
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

根因：`check_preview_gate.py · check_gate_and_ledger` 要求账本“恰好 28 项且全部 PENDING”，签收后的 develop 分支每次 push 必然失败。

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

### 2.3 当前 SHA 全量 P2 实跑（2026-11-19 补跑）

`E2E_RUN_ID=20261119-p2full E2E_CONCURRENCY=4 bash tests/e2e-diff/run_p2_matrix.sh`
（commit `a56a448d`，scope `installs=[M1..M10] edits=[E1..E8] ops=[OPS-19,OPS-21,OPS-09,OPS-31,OPS-32]`）：

| 项 | 结果 | 证据 |
|---|---|---|
| M1–M10 安装 | 两侧 `rc=0`，round1/round2 数据面 `reality/ws/grpc/xhttp/relay:ok`，L6 `ok` | `tests/e2e-diff/evidence/20261119-p2full/p2/install-matrix.md` |
| E1–E8 编辑 | 全部 `allPassed=true` | 同目录 `E*/go/edit/checks.json` |
| OPS-09/19/31/32 | `PASS` | `install-matrix.md` 的 OPS 表 |
| OPS-21 | `BLOCKER`（仅 bash 侧） | bash driver 在 GeoData 刷新下载失败时 `tb_apply_rules` 直接 `return`（rc=0）且未写入规则；Go 侧 4 项全过 |

OPS-21 的 bash 失败不是 Go 回归：`bash-apply.log` 显示 `GeoData 下载失败, 无法应用规则`，
驱动随即观测到 `rulesAdded=false before=1 after=1`。这是 oracle 在无稳定外网时的环境依赖，
不是降低标准的理由；修复方式是让驱动明确回答离线刷新提示并重试 off 后的控制探针：

```bash
E2E_RUN_ID=20261119-ops21 E2E_ONLY=OPS-21 bash tests/e2e-diff/run_p2_matrix.sh
# [OPS-21] verdict=PASS   (commit 1b519028, rc=0)
```

relay 的真实转发探针在 M10 场景内执行（Go 侧）：

```bash
E2E_RUN_ID=20261119-m10relay2 E2E_ONLY=M10 bash tests/e2e-diff/run_p2_matrix.sh
# commit 911f91d2, doctor-relay.rc.json {"rc":0}, healthy=true, evidenceLevel=REAL_CLIENT_PASS
```

接管/迁移回归：

| run | commit | 结果 | 说明 |
|---|---|---|---|
| `20261119-r1` | `a56a448d` | 85 PASS / 1 FAIL | 唯一失败是 M4 INJ bash 安装 `rc=124`；日志显示 Nginx 下载 `curl: (18) partial file`，属外网中断 |
| `20261119-inj` | `43ceb680` | 26 PASS / 0 FAIL | 重跑同一 M4 注入场景通过 |

### 2.4 真实 CI 复跑（`CI_RUN`）

工作分支已推送并创建 draft PR #182（base `develop/go-native`，**不合并**）：
`https://github.com/hello-yunshu/Xray_bash_onekey/pull/182`。
同一 SHA `4f12543e` 上六条工作流全部 `success`：

| 工作流 | run id | 结论 | 链接 |
|---|---|---|---|
| Go parity stage gate | `44527239779` | success | `https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44527239779` |
| Go preview qualification (NOT FOR RELEASE) | `44527239752` | success | `https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44527239752` |
| Go production parity release qualification | `44527239918` | success | `https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44527239918` |
| Go real-root change acceptance (container) | `44527240183` | success | `https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44527240183` |
| Test Install | `44527240075` | success | `https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44527240075` |
| Privacy Guard | `44527239956` | success | `https://github.com/hello-yunshu/Xray_bash_onekey/actions/runs/44527239956` |

首轮在 `4ab08050` 上暴露了一个真实的文档卫生问题：hardening 文档里的
`path · symbol` 写法（原先使用 Rust 风格分隔符）被 `check_evidence_hygiene.py`
按公网 IPv6 字面量命中，导致 stage gate 与 Privacy Guard 失败。
修复只改文档写法，未降低卫生规则；`4f12543e` 复跑后两条工作流均为 success。
这正是 P2-01 要证明的“CI 真正运行”，而不是用 `actionlint` 或本地结果冒充。

## 3. 未完成 / 未运行

| 项 | 等级 | 原因 |
|---|---|---|
| 三条工作流在 GitHub 上的新一轮真实运行 | `CI_RUN` PASS | 见 2.4；六条工作流在同一 SHA `4f12543e` 全部 success |
| 34 行 OPS 全量 | `PARTIAL` | 本轮实跑 5 行双端数据面（09/19/21/31/32），其余 29 行仍是 `GO_ONLY_PASS`/`NOT-RUN` |
| 纯 Bash ACME | `BLOCKED` | 缺少 acme.sh 与外部 Pebble 可达性 |
| 独立 VM 接管/迁移 | `BLOCKED` | 容器结果不能替代真实旧安装 |

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
