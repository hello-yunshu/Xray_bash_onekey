# 审计整改问题追踪（2026-11-19）

> 代码基线：`4527b721fda1dee39545f63ae35f27f9f5078e4f`（父提交 `b8b31f7e`，对比基线
> `origin/develop/go-native` = `9b965843`）。分支 `work/go-hardening-parity-20261119`。
> 本文只记录**当前 HEAD 可复核的事实**；未执行的项标 `NOT_RUN`/`BLOCKED`，不当作通过。
> 未读取任务书中的 ChatGPT 链接，不作任何“已读”声明。

## 1. 方法

1. 逐条把审计材料（`AUDIT_V4.md`、`AUDIT_REPORT.md`、`TRACEABILITY_MATRIX.md`、
   `RELEASE_MIGRATION_CONTRACT.md`）映射到当前源码路径与函数。
2. 对每个 P0/P1 先写最小复现或对照脚本，在 Docker 内用真实 Nginx/Xray/容器网络执行。
3. 只有“代码 + 真实执行 + 可复核证据”同时成立才标 `FIXED_VERIFIED` /
   `ALREADY_FIXED_VERIFIED`；仅代码存在而缺执行证据的保持 `OPEN`。
4. 测试结论词汇：`MATCH / GAP / GO_FAILED / BASH_FAILED / REFUSED / NOT_RUN`。

## 2. P0 问题

| ID | 原问题 | 当前事实（HEAD） | 状态 | 证据 | 提交 |
| --- | --- | --- | --- | --- | --- |
| P0-A | 中转配置丢失 listen 绑定，或把 `proxy_timeout` 改成易断流的值，导致公网暴露/绕行 | `xraycfg.RelayConf` 保留 `listen <addr>`、`proxy_timeout 720m`、`proxy_socket_keepalive on`；`xray install --role relay --listen` 全链路可传；非法地址 exit 1 且不改 fragment | `ALREADY_FIXED_VERIFIED` | `artifacts/audit-remediation/p0a/summary.json`：4 个地址 `nginx -t` 全 0；`127.0.0.1`/`::1` 本机可达、跨容器不可达；`0.0.0.0` 跨容器可达；3 个非法值全部拒绝且配置哈希不变 | `b8b31f7e`（语义） + 本轮证据脚本 |
| P0-B | Bash TLS 节点的 Xray 在回环以 `security=none` 运行，分享入口把公网链接写成 `security=none` | `xraycfg.ShareConfig` 已 fail-closed，但 `xray share` 从未读取管理元数据，错误提示要求“使用 metadata tls”却无实现 | `FIXED_VERIFIED` | `internal/cli/share_metadata_test.go` 6 例；红测（注释回填调用）`TestXrayShareUsesMetadataForPublicTLS` 必 FAIL；修复后 6/6 PASS | `4527b721` |
| P0-C | 迁移/恢复覆盖真实资源（入口、配置、证书、cron） | 备份/恢复已事务化：互斥锁、持久 journal、原子写、SIGKILL/ENOSPC/EROFS/EACCES、入口漂移与第三方入口保护；`bridge audit` 只读 | `ALREADY_FIXED_VERIFIED` | `p0c/summary.json`：6 个 Bash fixture 扫描前后全树哈希一致；`prepare` 后 runtime 5 项哈希不变；`recover` 回到 `ROLLED_BACK`；`go-safety-tests.log` 全绿 | `8ac1385f`、`43ceb680` + 本轮证据 |

### P0-B 变更细节

- 仅当 `--public-security/--host/--public-port` **未显式给出**时，从
  `metadata.json` 的 `TLS`、`Install.ServerNames[0]`、`Install.Port` 回填。
- 映射：`TLS→tls`、`Reality→reality`、`None→none`；未知值不回填，保持 fail-closed。
- 显式标志优先；无元数据时行为与旧版完全一致（回环 `security=none` + 未声明公网
  security 仍拒绝）。
- 同一份元数据继续提供 `ShareLinkOnly` 的 `fp/spx`，不新增敏感字段。

## 3. P1 问题

| ID | 原问题 | 当前事实 | 状态 | 证据 |
| --- | --- | --- | --- | --- |
| P1-A | 只覆盖常见模式，传输/元数据对照不完整 | P2 矩阵在当前 HEAD 复跑 Reality/TLS/None × raw/ws/gRPC/xHTTP/组合，外加 Reality+Nginx 与 relay；元数据、Xray 配置、分享链接分层对照 | `FIXED_VERIFIED` | `tests/e2e-diff/evidence/audit-final-20261119/p2/`；见 `PARITY_MATRIX.csv` |
| P1-B | 多文件部署可能半更新 | 部署在首字节写入前 fsync journal；任何失败执行 `restoreTransaction` 并恢复服务 enable/active；Nginx 作为独立组件显式报告残留 | `ALREADY_FIXED_VERIFIED` | `logs/p1b-deploy-rollback.log`（5 个回滚用例 PASS，0 FAIL） |
| P1-C | 测试隐式依赖公网 DNS/DoH，结果不可复现 | 全量 `go test ./...` 在 `--network none` 容器内通过；e2e 使用容器内 origin 与真实 Nginx/Xray 数据面 | `ALREADY_FIXED_VERIFIED` | `logs/go-test-offline.log`；P2 L4 |
| P1-D | 长期运行/资源所有权/退出码未验证 | 备份/恢复/修复/计划/存储在 `-race` 下通过；fail2ban 只改自有文件、日志清理只截断普通文件、计划任务测试通过 | `ALREADY_FIXED_VERIFIED` | `logs/p1d-race.log`、`logs/p1d-ownership.log` |

## 4. 仍未闭环（不得当作已修复）

| 项 | 状态 | 原因 / 下一步 |
| --- | --- | --- |
| 独立 VPS（systemd 真机、重启、cron 真实交接） | `BLOCKED` | 任务书禁止操作生产 VPS；本仓库无独立测试机 |
| 公网 CA / DNS-01 / EAB 的纯 Bash ACME | `BLOCKED` | 需要公网域名与 CA；只能在受控域名下执行 |
| 外部 IPv6 数据面 | `NOT_RUN` | Docker 默认 bridge 无 IPv6；已证明 `::` 监听与 `::1` 数据面，外网 IPv6 需双栈宿主 |
| 多版本 Xray/Bash 配置矩阵 | `NOT_RUN` | 需要固定历史发行物；当前只使用仓库 fixture 与固定 Xray `26.10.31` |
| 正式发布与 `main` 合并 | `INTENTIONAL_DELTA_APPROVED` | 任务书明确禁止；仅提交工作分支 |
