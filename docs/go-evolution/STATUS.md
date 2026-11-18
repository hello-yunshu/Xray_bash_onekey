# Go 演进进度状态

- 更新时间：2026-11-19
- 开发分支：`work/go-evolution-audit-20261118`（未推送、未合并 `main`、未打 tag、未发布）
- 基线：`develop/go-native` = `d4858a1150d3f83202e95aa9dfea2244832c8b3e`
- Bash pin：`3b2a5045fec4535e189a0b25ca27dc534945bab5`

## 阶段状态

| 阶段 | 状态 | 出口产物 | 证据 |
|---|---|---|---|
| S0 基线审计 | 完成 | `docs/go-evolution/00-baseline.md` | `tests/e2e-diff/evidence/20261118-0605-full`（M1–M10/E1–E8/OPS-32） |
| P1 迁移差异与安全收口 | 完成 | `docs/go-evolution/01-parity-and-safety.md` | 对照矩阵、OPS-01..34 分类、键/密文脱敏、统一变更事务 |
| P2 Go 原生能力升级 | 完成 | `docs/go-evolution/02-native-value.md` | `tests/e2e-diff/evidence/goevo-p2-*`（doctor/backup/repair/preflight 实机） |
| P3 低中断试点与资格收口 | 完成（编码/测试/提交/迁移链实跑） | `docs/go-evolution/03-final-qualification.md` | `goevo-p3-20261119-0303`（60/60）、`goevo-p3-matrix-0242-a9875aff/p2`（M1–M10、E1–E8、OPS 全 PASS）、`goevo-r1r2-20261119-0420-6ad3be97`（R1/R2 64/64）、`20261119-0440-8c002dde/r1`（I1–I4 42/42） |

最终看板（矩阵 §七）见 `03-final-qualification.md` §6.5：M1–M10 10/10、OPS 5 双端 + 18 单边、E1–E8 8/8、R1/R2 2/2、G01–G06 6/6、负面/故障 16/16、S4–S9 6/6 PASS（S1–S3 交互菜单由 OPS 覆盖）、F01–F28 仍 28 NOT_RUN（账本未签收）。

## 已完成

- 热用户变更仅由 `--experimental-hot` 开启；配置为真相源，先持久化后经 loopback API 应用；rc=8 表达半失败，重试可收敛；并发持 15s 锁；重启不丢用户。
- `xray api status|enable`、`ops summary [--json]`；不新增数据库/守护进程/Web。
- 实机发现并修复 `repair` 权限回归（`0600 root:root` → `0640` + 组 `xray`）；`doctor` 新增 `service-access`，以服务账户实测可读。
- 锁检测改为真实 `flock`，消除变更后误报。
- 全量矩阵实跑通过：M1–M10 两侧 rc=0、L4 两轮真实客户端全 ok、L6 幂等 ok；E1–E8 全 PASS；OPS-09/19/21/31/32 PASS；P3 套件 60/60。
- 复核 E5 时发现 Nginx 平滑重载期间新旧 worker 瞬时并存，单次握手采样会误判；驱动改为 30s 内连续 3 次命中新证书才判定收敛（`be141822`）。
- Bash→Go 真实接管已实跑（`run_r1_upgrade.sh`，M1/M4）：`--keep-config` 与 bridge 五步均保留配置字节、证书、端口、cron 与在线流量；过程中修复四个迁移缺陷（目录穿越权限、ws/grpc 端口与路径继承、接管端口探测、Bash 版 Nginx 主配置路径），见 `03-final-qualification.md` §6.6。
- 升级失败注入 I1–I4 实跑：非法 JSON、缺证书、端口占用、只读目标均被拒绝且不改前态；I4 的不可恢复回滚会留 journal 并由 `idleleo xray recover` 清除（`80ad240f`，含全新 Reality 端口预检）。
- 矩阵未驱动的 18 个 OPS 行完成 Go 单边实跑（`run_ops_sweep.sh`，36 assertions）；`stats`/`metadata import` 的缺失前置条件按文档化拒绝断言。
- S4–S9 辅助脚本实跑（`run_s_scripts.sh`，`s-20261119-full/s`，58 PASS / 0 FAIL）：S4 正常/重复/坏元数据 fail-safe；S5 用 Pebble 完成真实续期与 CA 不可达恢复；S6 真实 GitHub Release 下载与失败不破坏现网；S7 acme.sh 下载安装并验证 `--version/--help`；S8 `tcp` sandbox 全链路且真实内核正确拒绝；S9 真实验速与干净失败。历史 tcp.sh/superspeed.sh 均记录 URL+sha256 且 `bash -n` 通过。
- Go 全库单测、gofmt、vet 通过；证据卫生扫描 0 findings。

## 阻断

1. **受保护 CI 不可得**：分支未推送，无远程 workflow 运行；F01–F28 依规则保持 `PENDING_GO_IMPLEMENTATION`。本地等价门禁已跑：隐私扫描 0 findings、账本迁移策略 17 tests OK、A2 自检 PASS、go 全库测试通过。
2. **真实节点证据缺失**：无真实 VPS/VM 的 systemd/journald、证书续期与断电证据；不伪造，账本不推进。
3. **S7/S8 子项仍受外部条件限制**：acme.sh 的下载/安装/调用已实测，但真实签发需域名+公网 CA；`tcp` 已在 sandbox 验证全链路，真实内核 BBR 需 VPS 内核。S1–S3 为交互菜单脚本，其能力由 OPS 双端/单边实跑覆盖。

## 下一步

1. 在真实 VPS/VM 复跑 P3 套件、M8 调度与 R1/R2 接管，补齐断电/长期旧连接场景，并验证 S7 签发与 S8 真实内核应用。
2. 补齐 OPS 未驱动行的 Bash 对照驱动（当前 18 行只有 Go 单边证据）。
3. 推送分支并接入受保护 CI，获取远程 workflow 证据。
4. 仅在独立证据满足 `check_ledger_transition.py`/`check_release_gate.py` 时更新 `feature_contracts.json`。

## 发布资格

`check_release_gate.py` → `RELEASE BLOCKED: pending 28; missing executable feature tests 0; JSON statuses alone never grant success`（rc=2）。当前建议：正式发布 NO-GO；实验能力 GO（默认关闭）。
