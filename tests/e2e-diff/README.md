# bash vs Go 差分套件（tests/e2e-diff）

用同一批容器场景分别驱动 **bash 版 `install.sh`** 与 **Go 版 `idleleo`**，逐层比对安装、菜单操作、子脚本与升级链的差异。

本目录**独立于** `tests/go-parity/a2`：a2 已被 `go-parity-stage.yml` 门禁引用，本套件只读引用其镜像与驱动，不修改 a2 任何文件。

## 状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| P0 基线冻结 | 已完成 | 场景矩阵、提示词表、ED 骨架、本 README、证据目录 |
| P1 环境与驱动冒烟 | 未开始 | 不在 P0 范围内 |

## 目录

```
tests/e2e-diff/
  README.md                 # 本文件
  matrix.json               # P0 冻结：M1–M10 安装矩阵 / OPS-01–30 / S1–S9 / 升级链
  expected_diffs.json       # P0 冻结：EXPECTED-DIFF 登记表（当前 5 条 pending）
  drivers/prompts.tsv       # P0 冻结：bash 交互提示词 → 应答映射
  evidence/<run-id>/        # 每次运行的证据（文本/JSON 可提交，大文件放 /tmp 只记 sha256）
  image/ mirror/ collect/ compare/ cases/   # P1 起逐步新增，P0 尚未创建
```

## run-id 规则

`YYYYMMDD-HHMM-<git 短 sha>`，取开始运行时的本地时间（Asia/Shanghai）与 `git rev-parse --short HEAD`。

P0 的 run-id 为 `20261113-1721-fee7a68`。

## 冻结内容（P0）

`matrix.json`：

- `install`：M1–M10，覆盖 Reality 标准/前置 Nginx/附加传输、TLS ws/gRPC/xHTTP/组合、ACME、无 TLS、中转节点。
- `ops`：OPS-01–OPS-30，覆盖主菜单 2/3/4/5/6/7/8/9 的可交互操作；每条带 `verdict`（`must-match` / `go-missing` / `allowed-diff`）。
- `subscripts`：S1–S9，被主流程调用的外部子脚本（fail2ban、traffic_blocker、file_manager、auto_update、ssl_update、geo_update、acme.sh、tcp.sh、superspeed.sh）。
- `upgrade`：官方路径 R1（`idleleo xray install --keep-config`），R2 bridge 只在 M1/M4 抽测；断言 U1–U8；失败注入 I1–I4。
- `layers`：L0 退出码 / L1 产物清单 / L2 配置语义 / L3 运行时状态 / L4 连通性 / L5 日志 / L6 幂等。

`drivers/prompts.tsv`：

- 列：`flow / seq / context / prompt_regex / answer / confidence / source`。
- `verified` 53 行（来自 a2 已跑通的 expect 转录与 install.sh 菜单行号），`inferred` 52 行（由 install.sh 字符串推导）。
- **所有 `inferred` 行必须在 P1 首次真实运行时确认**；未确认前不得据此判定业务差异。任何提示未匹配都记 `HARNESS-ERROR`，禁止盲发回车。

`expected_diffs.json`：

- 只预置 5 条待批准项：ED-001 Nginx 负载均衡（OPS-09）、ED-002 Fail2ban（OPS-19）、ED-003 流量阻断（OPS-21）、ED-004 清除日志（OPS-22）、ED-005 Rill AI（OPS-29）。
- 每条必须有 `owner` + `approved_by` + `expires`；当前全部为空、`status: pending`。
- `pending` / 过期 / 未知 / 通配（`*`）一律按 `DIFF-BLOCKER`，不是豁免。

## 已知未决项（P0 如实记录）

| 项 | 状态 | 处理 |
|---|---|---|
| M8（ACME） | `eligible: false` | Pebble 在本容器网络的 HTTP-01/TLS-ALPN 解析方案未定，结果记 `HARNESS-BLOCKED`，不判过 |
| Go 侧 argv | 全部 `verified: false` | P1 用 `idleleo ... --help` 核实后才允许作为真实调用 |
| M2（Reality + Nginx） | 待核实 | Go 是否有等价前置能力未知；若无，记 capability gap，不伪造通过 |
| prompts `inferred` | 52 行 | P1 首次运行确认，未确认不得用于判定 |
| ED 条目 | 5 条全部 pending | 未批准即 BLOCKER；P7 前必须清零或补齐审批 |

## 证据

每次运行写入 `evidence/<run-id>/<阶段>/`。P0 证据在 `evidence/20261113-1721-fee7a68/p0/`：

- `run.json`：run-id、commit、冻结时间、产物 sha256、自检结果、未决项。
- `self-test.log`：`compare_real_runtime.py --self-test` 输出。
- `a2/`：a2 reality/raw 冒烟转录（存在即为跑过；缺失表示未执行）。

## 复跑 P0 自检

```bash
python3 tests/go-parity/a2/compare_real_runtime.py --self-test
A2_EVIDENCE="$PWD/tests/e2e-diff/evidence/<run-id>/p0/a2" \
  bash tests/go-parity/a2/run_bash_real_install_container.sh reality raw
```

## 判定门槛（后续阶段）

- `must-match` 项出现未登记的差异 → `DIFF-BLOCKER`。
- `EXPECTED-DIFF` 只按 `(id, scenario, layer, path, field)` 精确抑制，报告必须引用 ED 号。
- `go-missing` 表示 Go 无该能力，记录为 capability gap，不按差异豁免。
- 任何 `HARNESS-ERROR` 必须在进入下一阶段前归因清除。
