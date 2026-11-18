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
| P3 低中断试点与资格收口 | 编码/测试/提交完成；最终全量重跑 BLOCKED（环境无外网） | `docs/go-evolution/03-final-qualification.md` | `goevo-p3-p3-final-015931`（60/60）、`p3-edits/p2`（E1–E4 PASS） |

## 已完成

- 热用户变更仅由 `--experimental-hot` 开启；配置为真相源，先持久化后经 loopback API 应用；rc=8 表达半失败，重试可收敛；并发持 15s 锁；重启不丢用户。
- `xray api status|enable`、`ops summary [--json]`；不新增数据库/守护进程/Web。
- 实机发现并修复 `repair` 权限回归（`0600 root:root` → `0640` + 组 `xray`）；`doctor` 新增 `service-access`，以服务账户实测可读。
- 锁检测改为真实 `flock`，消除变更后误报。
- Go 全库单测、gofmt、vet 通过；证据卫生扫描 0 findings。

## 阻断

1. **容器无外网**（本次运行环境）。宿主可出网，但 Docker 内即使按 IP 访问也失败；`ip.me`、GeoData、受管 Nginx 构件、ACME 与外部 Reality target 均不可达。
   - 影响：M1–M10、E5–E8、ACME/relay 场景本次无法复跑；记为 `BLOCKED`，不冒充 PASS。
   - 复现：`docker run --rm idleleo-e2e:24.04 sh -c 'curl -4 -fsS https://ip.me'` → `Could not resolve host`；`curl -k https://1.1.1.1` → `Couldn't connect`。
   - 恢复后动作：重跑 `run_p2_matrix.sh`（完整 M1–M10 + E1–E8 + OPS）与 `run_p3_hot.sh`。
2. **受保护 CI 不可得**：分支未推送，无远程 workflow 运行；F01–F28 依规则保持 `PENDING_GO_IMPLEMENTATION`。本地等价门禁已跑：隐私扫描 0 findings、账本迁移策略 17 tests OK、A2 自检 PASS、go 全库测试通过。

## 下一步

1. 外网恢复后全量重跑矩阵，重点 TLS/ACME/relay 与 M8 调度。
2. 在真实 VPS/VM 取证并接入受保护 CI，之后才评估账本推进。
3. 仅在独立证据满足 `check_ledger_transition.py`/`check_release_gate.py` 时更新 `feature_contracts.json`。

## 发布资格

`check_release_gate.py` → `RELEASE BLOCKED: pending 28; missing executable feature tests 0; JSON statuses alone never grant success`（rc=2）。当前建议：正式发布 NO-GO；实验能力 GO（默认关闭）。
