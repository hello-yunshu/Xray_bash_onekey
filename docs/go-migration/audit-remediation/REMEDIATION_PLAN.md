# 整改计划与执行记录（2026-11-19）

> 基线 `b8b31f7e`，整改提交 `4527b721`。本计划先验证、后修复；不重写既有审计结论，
> 只把每条结论落到当前代码与可复核证据。

## 1. 阶段与门禁

| 阶段 | 内容 | 退出条件 | 实际结果 |
| --- | --- | --- | --- |
| A 复核 | 对齐审计材料、HEAD、工具链、测试入口 | 每条 P0/P1 都有代码锚点与复现路径 | 完成；见 `AUDIT_ISSUES.md` |
| B 修复 | P0-B 元数据派生；P0-A/P0-C 仅补证据 | 红测能击中缺陷，修复后绿；真实 Nginx/容器证据 | 完成 |
| C 对照 | Reality/TLS/None × raw/ws/gRPC/xHTTP/组合；relay；Nginx 拓扑；历史 98 项矩阵；OPS Go sweep；OPS 双端 5 行 | 每行有 Go/Bash/数据面/结论 | 完成（`audit-final-20261119`、`matrix-20261120-final`、`audit-ops-20261120`、`audit-ops-dual-20261120`） |
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
| OPS 双端复跑 | 部分完成 | OPS-09/19/21/31 已双端 PASS；OPS-32 在 `1cd248e6` 重跑（`fix-20261120-p2i`）ws/reality 均 PASS；其余 18 个 ID 只有 Go 单侧 sweep |
| OPS-08 / OPS-27 | `FIXED_VERIFIED`（集成待跑） | `241cc99f` 新增 `xray guard show/set` 与 `xray cert clear`；Go 单测、CLI smoke、真实 `nginx -t` 均通过；Bash 双端交互仍 `NOT_RUN` |
| OPS-30 | `INTENTIONAL_DELTA` | 语言切换为 `allowed-diff`，不要求逐字节一致 |
| OPS-05/06/07/10/17b/24 | 已有等价路径 | 分别由 `xray edit --uuid/--target/--server-names`、`xray tls`、`update nginx`、`schedule run` 覆盖，只是没有同名 OPS 行 |
| 旧 Stats Ubuntu CI 红灯 | 未重查 | 需下载失败日志后单独修复 |
| M8 公网 ACME | `NOT_RUN` | 与公网 CA 项同因 |

这些项不阻断“交付整改证据”，但阻断“发布/合并”判断。

## 7. 2026-11-20 复审决策

1. **元数据归属优先于便利性**：`xray share` 只有在 `--path` 与
   `metadata.runtimeConfigPath` 规范化同路径、且 `runtimeSha256` 匹配时才使用
   元数据；跨 root / 跨配置不得回填。宁可让用户补 `--public-security`，也不能
   把无关元数据套到别的配置上。
2. **Host 与 SNI 永久分离**：Reality 的 `serverNames` 只作为 SNI/伪装身份；连接
   地址必须显式 `--host`。TLS+Nginx 仍允许从运行时 `tlsSettings.serverName`
   推导 Host（该值本就是公网域名）。
3. **测试必须自洽**：Fixture 自己的 `share` 必须带 `--root`，不得依赖宿主机
   `/etc/idleleo`；所有 Reality 探针显式给 Host。
4. **证据不携带宿主信息与临时密钥**：`environment.txt` 只记录 SHA256 与仓库相对
   路径；fixture 根目录移出 evidence；`f.run(redact=True)` 脱敏 argv/stdout。
5. **不为通过而放宽断言**：F28 从 35/2 恢复为 57/0 是修复代码与测试自洽性的结果，
   没有跳过用例；OPS/矩阵失败项全部保留并按实际环境标 `BLOCKED`/`NOT_RUN`。
6. **回滚**：`git revert 9f66b22a f217a2fa` 会恢复“SNI 当 Host + 跨 root 元数据”
   的旧行为，仅在确认元数据不会跨 root 复用时才可考虑。

## 8. 2026-11-20 收尾修复决策（`1cd248e6`）

1. **`--host` 是渲染输入，不是配置字段。** `EditRequest.Host` 只决定
   `OldShareURI`/`NewShareURI`/`ShortIDLinks` 的 authority，不写入
   `streamSettings`；缺省时退回 `shareHostFor(spec)` 并保持旧行为。
   含 `/` 或 `://` 的值直接拒绝，避免把 URL 拼进链接。
2. **`--host` 单独使用不产生变更。** `config edit` 仍是变更命令；只给 `--host`
   会返回 “nothing to edit”，并在文案里说明它只影响链接渲染。Reality 编辑未给
   `--host` 时，报告追加警告而不是失败（兼容既有调用方）。
3. **E2E 两侧同源。** E7/E8 的 CLI 与驱动都显式 `--host 127.0.0.1`，
   `oldLinkCaptured`/`backupHasOldShareUri` 不再依赖 SNI 恰好等于探测地址。
4. **OPS-32 判定以可复现为准。** nginx 在 `fail_timeout` 后以衰减权重放行后端，
   A 的命中本就稀疏；要求 A 链延伸到窗口末尾测到的是 worker 采样运气。改为完整
   窗口尾部 `2*fail_timeout` 内 A ≥ `stable_min` 且相邻间隔 ≤ `fail_timeout`，
   同时保留“先 A 后 B”的 first-A 记录，避免把一次命中当成恢复。
5. **旧数据不回写。** p2d 的 `ops.json` 保持原判，重算结果单独放在
   `artifacts/audit-remediation/followup-20261120/ops32-reanalysis/`，新结论以
   p2i 的新探测为准，保证“原始证据”与“分析结论”可区分。

## 9. 第三轮 Docker 验收决策（`df3f3838`）

1. **A1**：不接受“按路径通配删除证书”。实现所有权 + 在用引用证明、dry-run 计划、
   staging + journal 恢复；保留 ACME 账户与第三方域名。Bash 旧行为登记为
   `INTENTIONAL_SAFETY_DELTA`，不在验收里复现危险路径。
2. **A3**：`guard show` 不再使用 `enabled/isolate` 默认值，改为从实际 Nginx
   主配置、include 与 fragment 推导；`guard set` 先锁后读、写 journal、回滚失败
   聚合为 `RECOVERY_REQUIRED`。
3. **A4**：先验证是否为真实断连。父提交 `Generate` 已补前导 `/`，候选测试复制到
   父提交仍通过；真实 Xray 26.10.31 对 `/xhttp` 与 `/xhttp/` 四交叉均接受。
   因此**不做全量重写**，只保留 `normalizeXHTTPPath` 作为编辑路径的防御性统一，
   并按语义差异记录。
4. **A2/A5**：A2 仅做影响面复核，不把旧绿证写成候选新执行；A5 的 Test Install
   在 `aa4b9da9` CI 通过，但历史静默退出的根因未定位，因此 A5 仍记 `PARTIAL`，
   不以一次绿色 CI 或重试掩盖。
5. **B4 不降级**：任务书明确禁止 Go-only sweep 替代 34 个 OPS 与 9 个 subscripts。
   本轮未完成的部分原样留在账本，Docker 候选因此 NO-GO。
6. **发布**：保持 draft PR；不合并、不打 tag、不发版、不操作生产 VPS。
