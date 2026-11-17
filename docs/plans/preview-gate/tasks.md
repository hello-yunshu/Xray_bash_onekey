# Preview 通道与首批 6 项夹具 — 任务清单

对应规格：[spec.md](spec.md)。批准后按顺序执行；每项完成即汇报，不 push。

## 执行节奏（用户调整，2026-11-11）

按四步走，不要一次推六个夹具：

1. **T0 + T1 + T2**（管道 + F01）一起；跑完**停下汇报**，等确认后再进第二步。
2. **F05 + F11** 两个一起。
3. **F26 + F27 + F28** 三个一起，F28 最后。
4. **T8 + T9** 各自成段。

每个夹具一个 commit，保证可以单独 revert；不合并成组提交。

## T0 前置校验

- [ ] 记录 `check_release_gate.py` / `feature_contracts.json` 的 SHA-256，并确认与 `preview_contract.json` 中的 pin 一致。
- [ ] 确认 `install.sh` 当前 SHA-256（预览如实记录，不冒充 pinned 基线）。
- [ ] 确认 Docker 可用、arm64/amd64 架构、可下载 Xray 与 `golang:1.24` 镜像。

## T1 Preview 通道骨架

- [ ] 新增 `tests/go-parity/parity/cases/preview_contract.json`（6 项，`PENDING_PREVIEW`，含 scope/not_verified）。
- [ ] 新增 `tests/go-parity/parity/scripts/check_preview_gate.py`：
  - [ ] 首行 `PREVIEW — NOT FOR RELEASE`，结尾 `release authority: NONE`。
  - [ ] release gate / feature ledger 哈希不变校验。
  - [ ] 28 项仍全为 `PENDING_GO_IMPLEMENTATION`。
  - [ ] 证据来源二选一：`--container-evidence` 或 `GITHUB_ACTIONS` + `GITHUB_SHA`。
  - [ ] 拒绝 tag / release 事件。
  - [ ] `--go-bin` 的 ELF + 架构校验。
  - [ ] 夹具执行：`python3 -I`、`--go-bin`、`--bash-repo`、`timeout=240`。
  - [ ] 输出 `preview_qualification.json`。
- [ ] 新增 `tests/go-parity/parity/features/fixture_support.py`（断言、超时、证据、前置条件）。
- [ ] 新增 `tests/go-parity/parity/scripts/run_preview_container.sh`（构建二进制 + 启动 systemd 容器 + 执行闸门）。
- [ ] 新增 `tests/go-parity/parity/ci/go-preview-qualification.yml`（只读权限，无 tag/release）。

## T2 F01夹具（首个跑通即汇报）

- [ ] 新增 `features/F01_test.py`：写前拒绝、fresh install、systemd/User、`xray -test`、真实握手、清理。
- [ ] 容器内跑绿；报告模板结构、断言方式、超时处理、证据路径。
- [ ] commit 1：`preview(gate): add preview-qualification channel and F01 fixture`。

## T3 F05

- [ ] 新增 `features/F05_test.py`：relay 片段、`nginx -t`、真实 TCP 回显、无 Xray/UUID/证书副作用。
- [ ] 跑绿 → 汇报 → commit 2。

## T4 F11

- [ ] 新增 `features/F11_test.py`：status/restart/stop/start/logs、非法 unit、sandbox root。
- [ ] 跑绿 → 汇报 → commit 3。

## T5 F26

- [ ] 新增 `features/F26_test.py`：`legacy-xtls-removed`、verdict blocked、只读哈希不变、prepare 拒绝且无 journal。
- [ ] 跑绿 → 汇报 → commit 4。

## T6 F27

- [ ] 新增 `features/F27_test.py`：version/help 退出码、unknown → 2、sandbox uninstall/purge 语义。
- [ ] 跑绿 → 汇报 → commit 5。

## T7 F28

- [ ] 新增 `features/F28_test.py`：`show/status/share` 离线只读、字段断言、零写入。
- [ ] 跑绿 → 汇报 → commit 6。

## T8 负向验证

- [ ] 缺夹具 → 闸门 RED。
- [ ] 改 `check_release_gate.py` → 闸门 RED，还原。
- [ ] 改账本状态 → 闸门 RED，还原。
- [ ] 破坏 F05 nginx → 闸门 RED。
- [ ] `git diff --stat` 证明两个禁改文件零改动。

## T9 台账对齐（单独 commit）

- [ ] `docs/release/FEATURE_PARITY_RESULTS.md`：记录 preview 通道与 6 项夹具事实，不改 0/28 签收结论。
- [ ] `docs/go/BASH_GO_REAL_RUNTIME_PARITY_REPORT.md`：补充 preview 证据等级，A2 计数保持已修正值。
- [ ] `docs/go-migration/reference/TRACEABILITY_MATRIX.md`：状态列与实际一致。
- [ ] `docs/go/FUNCTION_PARITY.md`：补充 preview 通道说明与 6 项证据，标签不变。
- [ ] commit 7：`docs(status): align parity ledgers with preview channel`。

## T10 收尾

- [ ] 汇总 6 项结果、未验证项（真实 VPS / 公网 CA / 双机主备）、后续批次建议。
- [ ] 明确未 push，等待确认。
