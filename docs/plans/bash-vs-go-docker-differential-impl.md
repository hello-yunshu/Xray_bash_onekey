# 实施计划：bash vs Go Docker 差分测试与无缝升级验证

前置文档：[bash-vs-go-docker-differential.md](./bash-vs-go-docker-differential.md)（方案稿）。
本文件是可直接照做的执行计划，不含代码改动。

## 0. 已拍板的决策

| 决策 | 结论 | 落地方式 |
|---|---|---|
| 升级官方路径 | **R1 `idleleo xray install --keep-config`** 为主 | M1–M10 全部走 R1；R2 bridge 三阶段仅在 M1/M4 抽测 |
| EXPECTED-DIFF 批准 | 逐条登记，**必须**有 `owner` + `approved_by` + `expires`；缺任一项或过期 → 按 `DIFF-BLOCKER` 处理 | `tests/e2e-diff/expected_diffs.json` 机读；比较器只按 `(id, scenario, layer, path/field)` 精确抑制；报告必须列出被抑制项与 ED 号 |
| 禁止批量豁免 | 一条差异一个 ED | 比较器拒绝 `scenario: "*"` 且 `layer: "*"` 的条目 |
| 接入门禁 | 本轮**不接**现有 28 项判据 | 先手动/夜间触发；稳定后另行提议 |

## 1. 复用与新增

**直接复用（不改动）**

- `tests/go-parity/a2/Dockerfile`：Ubuntu 24.04 + systemd + expect + jq 的 disposable 镜像底座。
- `tests/go-parity/a2/drive_install.exp`：真实交互安装的 expect 驱动范式（按提示逐条应答）。
- `tests/go-parity/a2/compare_real_runtime.py`：inbound 按 tag 匹配、字段级对比、approved/UNCOVERED 语义、`--self-test`。
- `tests/go-parity/acme/run_acme_container.sh`：Pebble 本地 ACME。
- `tests/go-parity/lib/docker_common.sh`：`ensure_xray_bin`、`cgroup_mount_args`、`docker_arch`。
- `tests/go-parity/parity/run_realroot_container.sh`：privileged systemd 容器参数范式。
- `install.sh` 的 `XRAY_QUALIFICATION_MODE` + `SHELL_RELEASE_BASE_OVERRIDE` 离线钩子；`IDLELEO_ACME_LEGACY=1`。

**不改 a2 的原因**：`go-parity-stage.yml` 会跑 `compare_real_runtime.py --self-test` 与真实对比，动它等于动现有门禁。本次全部新增到 `tests/e2e-diff/`，a2 只读引用。

**新增目录**

```
tests/e2e-diff/
  README.md                 # 运行手册（谁、怎么跑、证据在哪）
  matrix.json               # P0 冻结的场景矩阵
  expected_diffs.json       # ED 登记表
  image/Dockerfile          # FROM a2 底座 + 本套件依赖
  mirror/                   # 本地 raw/release/geo 静态文件与启动脚本
  drivers/
    bash_menu.exp           # 交互菜单驱动（从 a2 派生，覆盖 reality/tls/none/relay）
    prompts.tsv             # 提示词 → 应答 映射表（P1 导出）
    go_cli.py               # Go 侧命令驱动
    subscripts.py           # 外部子脚本驱动
    upgrade.py              # R1/R2 升级与回滚编排
  collect/
    manifest.sh             # 产物清单采集
    runtime.sh              # unit/ss/nginx -t/xray -test
    normalize.py            # 归一化规则（版本化）
  compare/
    artifacts.py  config.py  logs.py  connectivity.py  report.py
  cases/
    install.json  ops.json  scripts.json  upgrade.json
  evidence/<run-id>/...
```

## 2. 通用约定（所有阶段适用）

| 项 | 约定 |
|---|---|
| 镜像 | `idleleo-e2e:24.04`，基于 a2 Dockerfile 的同一 `ubuntu:24.04@sha256:fe8156...`，构建时记录 image id 到 `run.json` |
| 容器 | `--privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock $(cgroup_mount_args)`；server 与 client 同一 docker network |
| 标签 | `--label e2e.run=<run-id> --label e2e.scenario=<Mx> --label e2e.side=bash|go`；收尾 `docker ps -aq --filter label=e2e.run=<run-id> \| xargs -r docker rm -f` |
| 输入 | UUID `7a4ab30c-b199-4840-a31e-316f4f73a72b`、域名 `example.com`、端口池 `443/8443/10086/65535`；来自 `cases/*.json`，禁止脚本内硬编码 |
| 服务就绪 | `systemctl is-system-running` ∈ {running, degraded} 且目标端口 `ss -lnt` 命中，才算开始采集 |
| 采集时刻 | 就绪后固定 5s 观察窗，同场景两侧使用同一窗口 |
| 重试 | 仅允许 `HARNESS-ERROR` 重跑 1 次；业务差异不重试 |
| 证据 | 文本/JSON 进 `evidence/<run-id>/`（可提交）；tar/镜像层等大文件放 `/tmp`，只记 sha256 |
| 归一化 | 时间戳、PID、临时目录、ANSI、颜色、行序；规则文件带版本号，变更需说明 |

## 3. P0 基线冻结

**前置**：仓库 `develop/go-native` 工作区干净；Docker 可用。

**步骤**

1. 把方案第 4 节的 M1–M10、4.2 菜单项、4.3 子脚本、升级用例写进 `matrix.json`（每条含 `id, side, entry, inputs, layers, expected_owner`）。
2. 用 `--help` 与 `grep -n 'menu_read\|read -rp' install.sh` 校核菜单编号/提示词，产出 `drivers/prompts.tsv` 初版；缺失的提示词标 `TODO-P1`。
3. 建立 `expected_diffs.json`，只预置 5 条待批准项：Nginx 负载均衡/serverNames、Fail2ban、流量阻断、清除日志、Rill AI。全部 `status: pending`（未批准即 BLOCKER）。
4. 基线自检（不改代码）：
   - `bash tests/go-parity/a2/run_bash_real_install_container.sh reality raw` 跑通一次，确认现有交互驱动可用；
   - `python3 tests/go-parity/a2/compare_real_runtime.py --self-test` 绿；
   - 起 `mirror/` 容器，`curl` 校验 `/raw/v<ver>/scripts/ssl_update.sh` 与 `/releases/download/v<ver>/...` 可达。
5. 在 `README.md` 写清镜像来源、run-id 规则（`YYYYMMDD-HHMM-<git短sha>`）、证据目录。

**容器/场景**：仅基线冒烟容器（reality/raw），跑完即删。

**判定标准**：`matrix.json` 覆盖 10 个模式；`prompts.tsv` 无未解释空项；a2 冒烟 rc=0 且抓到 `/etc/idleleo/conf/xray/config.json`；self-test rc=0；镜像与 mirror 可用。

**产物**：`matrix.json`、`expected_diffs.json`、`prompts.tsv`、`README.md`、`evidence/<run-id>/p0/`。

**回滚**：删除 `tests/e2e-diff/` 即回到起点；P0 不修改任何既有文件。

**并行**：步骤 1/2/3 可并行；步骤 4 依赖 1；步骤 5 最后。

## 4. P1 环境与驱动冒烟

**前置**：P0 全绿。

**步骤**

1. 构建 `tests/e2e-diff/image/Dockerfile`：FROM a2 底座，补 `python3-pip pexpect nftables iptables iproute2 curl jq ca-certificates`；记录 image id。
2. 完成 `drivers/bash_menu.exp`：在 a2 的提示映射基础上增加 **tls（自签/ACME）** 与 **relay** 分支；每步 `expect` 超时即失败，禁止盲发回车。
3. 完成 `drivers/go_cli.py`：编译同 commit 的 `idleleo`（`golang:1.27.4@sha256:08bcb9...`，`-buildvcs=false`），封装 `install/uninstall/status/show/config inspect/change/service/stats/schedule/bridge/metadata/tcp/speedtest`。
4. 完成 `collect/manifest.sh`、`runtime.sh`、`normalize.py`：先在同一个已知目录上做自检（造 3 个文件的 fixture，断言清单/manifest 与归一化稳定）。
5. 冒烟：M1（reality/raw）与 M4（tls/ws 自签）各跑两侧，L0–L4 全采。

**容器/场景**：M1、M4；每场景 server(bash|go) + client 各一。

**判定标准**：两侧安装 rc=0；客户端握手成功；`manifest.json` 两侧字段结构一致；`normalize.py` 对同一输入两次输出一致；任何提示未匹配均记为 HARNESS-ERROR 且不得计为通过。

**产物**：`evidence/<run-id>/p1/{M1,M4}/{bash,go}/...` + `p1/smoke.md`。

**回滚**：仅新增文件；`docker rm -f $(docker ps -aq --filter label=e2e.run=<run-id>)`。

**并行**：1/2/3 并行；4 依赖 1；5 依赖 1–4。

## 5. P2 安装模式全量

**前置**：P1 冒烟全绿。

**步骤**

1. 按 `cases/install.json` 跑 M1–M10，每模式两侧各 2 次（全新 + 重复安装）。
2. 每场景采集 L0–L6：rc、产物清单、配置语义、运行时、连通性、日志、幂等。
3. `compare/report.py` 生成模式级对比表；差异必须落到 `MATCH / ED-xxx / BLOCKER / HARNESS-ERROR`。
4. 对已预置的 5 条 pending ED 做评审签字；未签字的保持 BLOCKER。

**容器/场景**：M1–M10 × {bash, go} × 2 轮；ACME 场景挂 Pebble 网络。

**判定标准**：10 个模式两侧都能装出可连通环境；`必须一致` 项零未登记 BLOCKER；幂等轮不产生重复 inbound/cron；所有 HARNESS-ERROR 已归因并清除。

**产物**：`evidence/<run-id>/p2/<scenario>/{bash,go}/` + `p2/install-matrix.md`。

**回滚**：删 `evidence/<run-id>/p2` 与容器；代码回滚 `git checkout -- tests/e2e-diff`。

**并行**：模式间并行（建议 5 并发，每并发独占 network）。**门禁**：P2 未全绿，禁止进入 P5。

## 6. P3 交互操作全量

**前置**：P2 全绿；至少 M1/M4/M9 的持久容器态可复现。

**步骤**

1. 按 `cases/ops.json` 覆盖 4.2 全部菜单项与 4.4 只读命令；每组独立起容器，从 P2 的标准前置态重建。
2. 「必须一致」组做双向对比；「Go 暂无」组只采 bash 基线并落 ED 或能力缺口表。
3. 文件管理/备份恢复项检查产物与可恢复性（备份→删→恢复→L1 清单一致）。
4. 只读命令做字段级对比（`--json` 键集合、空值语义、rc）。

**判定标准**：所有「必须一致」项 MATCH；「Go 暂无」项有 ED 或缺口登记；备份恢复往返 L1 清单一致；无新增静默失败（命令 rc=0 但无实际效果）。

**产物**：`p3/ops-matrix.md` + 每组原始 stdout/stderr/状态快照。

**回滚**：容器即弃；不影响 P2 证据。

**并行**：按菜单组并行（信息/服务/证书/配置变更/更新/工具/备份），共 4 并发。与 P4、P5 可并行。

## 7. P4 外部子脚本

**前置**：P1 的 mirror/Pebble 可用；P2 至少 M1/M4 环境可重建。

**步骤**

1. 九个脚本各跑三态：正常、重复执行、失败（断网 / 非 root / 依赖缺失，按脚本能力选）。
2. 采集：退出码、规则/配置产物、systemd 状态、cron 行、日志关键行。
3. 与 Go 对应能力对比：`tcp`（BBR 状态）、`speedtest`（固定参数）、geo（文件语义）；Go 无对应的登记缺口。
4. legacy `acme.sh` 只在 `IDLELEO_ACME_LEGACY=1` 下跑，与 Go `xray cert issue/renew` 对比证书可用性与续签 cron。

**判定标准**：三态均有记录；正常态产物符合脚本预期；失败态不破坏已装环境（升级前 L1 清单不变）；cron 无重复。

**产物**：`p4/scripts-matrix.md` + 每脚本 `run.log`、产物清单。

**回滚**：脚本只在 disposable 容器内执行；失败态若污染容器，直接销毁重建。

**并行**：脚本之间并行（3 并发）；Pebble 相关串行，避免端口冲突。

## 8. P5 升级正向（R1 主，R2 抽测）

**前置**：P2 全绿（硬门禁）。

**步骤**

1. 每个模式：bash 安装 → 客户端连通性基线 → 快照（L1 清单 + `tar` 到 `/tmp`）。
2. R1：`idleleo xray install --keep-config --binary /opt/xray/xray --container`（不传 `--rewrite-config`）。
3. 断言 U1–U7：
   - U1 配置语义等价；U2 证书/私钥字节与 mtime 不变；U3 unit/端口不变；U4 `xray -test`/`nginx -t`；U5 客户端不改配置仍连通；U6 `status --json` 与 bash 侧 mode/transport/role 一致；U7 cron/schedule 无重复无丢失。
4. R2 抽测：M1/M4 走 `bridge audit → prepare → validate → activate`，断言同 U1–U5。
5. 输出升级兼容表与差异。

**判定标准**：U1–U5 对 M1–M10 全过；U6/U7 通过或有 ED；R2 抽测无阻塞差异；失败必须给出具体字段/文件。

**产物**：`p5/upgrade-matrix.md`、每场景 `before/after` 清单、`diff.json`。

**回滚**：升级后任何断言失败，立即 `xray uninstall --keep-config` + 恢复快照（P6 的 U8 脚本可提前复用）；容器销毁。

**并行**：模式间并行（4 并发）；R2 抽测在 R1 全绿后串行。

## 9. P6 失败注入与回滚演练

**前置**：P5 全绿。

**步骤**

1. 四类注入各在独立容器执行：
   - 配置损坏（写入非法 JSON）；
   - 证书缺失（移走 cert/key）；
   - 端口占用（先起进程占 443）；
   - 目录只读（bind mount 后 `mount -o remount,ro`；不支持则 `chattr +i` 兜底并标注）。
2. 每次注入后执行 R1，断言：rc≠0、错误指向具体项、bash 侧 L1 清单与注入前一致。
3. U8 回滚演练：`xray uninstall --keep-config` → 恢复快照 → `systemctl daemon-reload` → 服务 active → 客户端连通。
4. 记录注入方式、错误文本、恢复耗时（仅记录）。

**判定标准**：4 类注入均「报错明确 + 状态未被打断 + 可恢复」；恢复后 L1 清单 sha256 与快照一致、连通性恢复。

**产物**：`p6/failure-injection.md` + 每例 `before/after` 清单与日志。

**回滚**：本阶段本身就是回滚验证；容器销毁即清理。若注入方法在 CI 环境不可用，标 `HARNESS-ERROR` 并改用等价方法，不得直接判过。

## 10. P7 汇总与评审

**前置**：P3/P4/P5/P6 全部结束（允许有已签字 ED，不允许未归因 BLOCKER）。

**步骤**

1. 合并各阶段报告，生成总表：场景、判决、证据链接、ED 号。
2. 单列「Go 暂无对应能力」清单与建议优先级。
3. 单列「未覆盖项」：真实公网 CA、非 Ubuntu 发行版、真实云厂商网络等。
4. 给出是否建议接入 CI 的结论（默认：先夜间手动，稳定后再提）。

**判定标准**：每条差异可追溯到证据文件；无 `HARNESS-ERROR` 残留；报告能被第三方按 README 复跑。

**产物**：`docs/plans/bash-vs-go-parity-report.md`（或 `evidence/<run-id>/SUMMARY.md`）+ `expected_diffs.json` 定稿。

**回滚**：纯文档，删除即可。

## 11. 依赖与并行关系

```
P0 ──> P1 ──> P2 ──┬──> P3 ──┐
                   ├──> P4 ──┼──> P7
                   └──> P5 ──> P6 ──┘
```

- 硬门禁：P2 全绿才可进 P5；P5 全绿才可进 P6。
- P3/P4/P5 之间无数据依赖，可三线并行（各自独占 run-id 下的容器与目录）。
- P1 内部 1/2/3 并行；P2/P3 内部按场景并行；P6 串行。
- 资源上限：同时最多 5 个 privileged 容器；超出则排队。

## 12. 每一步的通用回滚动作

| 对象 | 回滚方式 |
|---|---|
| 新增代码/脚本 | `git checkout -- tests/e2e-diff` 或删除该目录；a2 与现有脚本零改动 |
| 容器 | `docker ps -aq --filter label=e2e.run=<run-id> \| xargs -r docker rm -f` |
| 网络/Pebble | `docker network rm e2e-<run-id>-*`；Pebble 容器随 network 清理 |
| 证据 | 删除 `evidence/<run-id>`；不影响仓库其他部分 |
| 升级态 | 卸载 + 快照恢复（P6 脚本）；快照 tar 保存在 `/tmp/e2e-<run-id>/` |
| CI | 本轮不改 workflow；后续接入若不稳定，删对应 step 即恢复 |

## 13. 出口条件

1. P0–P2 全绿，M1–M10 两侧可连通。
2. P3/P4 无未归因 BLOCKER；ED 均有 owner/approver/expires。
3. P5 U1–U5 全过；P6 四类注入 + U8 全过。
4. P7 报告完成，未覆盖项与能力缺口列清。
5. `git status` 仅含 `tests/e2e-diff/**` 与 `docs/plans/**`；现有 28 项判据、`feature_contracts.json`、manifest、`tcp.sh`/`superspeed.sh`/`acme.sh` 均无 diff。
