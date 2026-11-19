# 整改计划与执行记录（2026-11-19）

> 基线 `b8b31f7e`，整改提交 `4527b721`。本计划先验证、后修复；不重写既有审计结论，
> 只把每条结论落到当前代码与可复核证据。

## 1. 阶段与门禁

| 阶段 | 内容 | 退出条件 | 实际结果 |
| --- | --- | --- | --- |
| A 复核 | 对齐审计材料、HEAD、工具链、测试入口 | 每条 P0/P1 都有代码锚点与复现路径 | 完成；见 `AUDIT_ISSUES.md` |
| B 修复 | P0-B 元数据派生；P0-A/P0-C 仅补证据 | 红测能击中缺陷，修复后绿；真实 Nginx/容器证据 | 完成 |
| C 对照 | Reality/TLS/None × raw/ws/gRPC/xHTTP/组合；relay；Nginx 拓扑；历史 98 项矩阵；OPS Go sweep | 每行有 Go/Bash/数据面/结论 | 完成（`audit-final-20261119`、`matrix-20261120-final`、`audit-ops-20261120`） |
| D 回归 | gofmt/vet/build/test/offline/race；`bash -n`；故障注入 | 全绿；离线全量测试可复现 | 完成（31 个故障/迁移用例 PASS） |
| E 交付 | 5 份文档 + 证据脚本 + `summary.json` | 状态、命令、退出码、SHA 完整 | 完成 |

## 2. 修复顺序与理由

1. **P0-B 先修**：安全影响是“把 TLS 节点分享成明文”，且用户按错误提示仍无法得到
   正确结果；改动局限在 CLI 参数回填，风险可控。
2. **P0-A 不改语义**：代码与既有单测已保留绑定/超时；缺的是“真实 Nginx + 跨容器”
   证据，因此只加证据脚本，避免为测试改产品。
3. **P0-C 不改语义**：事务化备份/恢复、锁、journal、故障注入已在 `8ac1385f`、
   `43ceb680` 落地；本轮用 Bash 固定样本验证扫描零写入、prepare 不碰运行时、
   recover 回滚。
4. **P1 只复核**：运输矩阵、rollback、离线测试、race/所有权测试都已存在；发现缺口
   才补测试，不扩大功能。

## 3. P0-B 实现决策

- 元数据是“管理意图”，运行时配置是“事实”；只在**共享入口无法自证**时使用元数据。
- `--public-security` 显式值永不被覆盖；`--host/--public-port` 同理。
- 元数据未知 TLS 值不猜测，保持 `ShareConfig` 的拒绝路径。
- 不把 `privateKey/UUID/shortId` 写入分享输出；链接仍从运行时配置派生。

## 4. 风险与控制

| 风险 | 控制 |
| --- | --- |
| 元数据与运行时冲突（如元数据 TLS=TLS，运行时已直连 TLS） | 显式标志优先；冲突时 `ShareConfig` 仍按运行时判定并要求声明 |
| 测试通过但真实 Nginx 不接受配置 | P0-A 用 managed Nginx 真实 `nginx -t`，并用双容器数据面验证 |
| 迁移脚本在真实机器上改文件 | P0-C 用固定 Bash 样本 + 沙箱标记；prepare/recover 只比较运行时 5 项哈希 |
| 测试依赖公网导致不可复现 | 全量测试在 `--network none` 下执行；e2e 用容器内 origin |
| 误合并/误发布 | 仅提交 `work/go-hardening-parity-20261119`；不合并 main、不发 Release |

## 5. 回滚

- 代码回滚：`git revert 4527b721` 即可恢复“必须显式传 `--public-security`”的旧行为。
- 证据脚本失败不改变产品状态；容器/网络均在 `trap` 中清理。
- 若元数据回填导致任何 e2e 分享差异，先回退该提交，再按 `PARITY_MATRIX.csv` 定界。
- 98 项矩阵断言修正可单独回退：恢复旧的回环端口比较会重新产生 20 个假 GAP，
  但不影响产品运行时；产品回退仍只需 `git revert 4527b721`。

## 6. 未实施 backlog

| 项 | 状态 | 原因 / 下一步 |
| --- | --- | --- |
| 独立 VPS / systemd 真机 / 真实 cron | `BLOCKED` | 任务书禁止操作生产 VPS；需专用测试机 |
| 公网 CA / DNS-01 / EAB 纯 Bash ACME | `BLOCKED` | 需要受控公网域名与 CA |
| 外部 IPv6 数据面 | `NOT_RUN` | 默认 Docker bridge 无 IPv6；需双栈宿主 |
| 多版本 Xray/Bash 配置矩阵 | `NOT_RUN` | 需固定历史 Release |
| OPS Bash 侧在当前 HEAD 复跑 | `NOT_RUN` | 本轮只跑 Go sweep；双端历史证据在 `be141822` |
| OPS-07/08/17b/24/27/30 | `GAP` | 尚无 Go 等价 CLI；OPS-05/06/10 可用 `xray edit` 但无同名 OPS 行 |
| 旧 Stats Ubuntu CI 红灯 | 未重查 | 需下载失败日志后单独修复 |
| M8 公网 ACME | `NOT_RUN` | 与公网 CA 项同因 |

这些项不阻断“交付整改证据”，但阻断“发布/合并”判断。
