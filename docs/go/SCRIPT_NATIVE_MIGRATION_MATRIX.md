# 辅助脚本 Go 原生化迁移矩阵（2026-11-08 审计）

> 范围：仓库内 `scripts/*.sh` 14 个，以及 `install.sh` 的 TCP 入口。
> 结论基于源码审读 + 本轮 Phase 01–04 的真实容器行为，不含真实 VPS 验证。
> 判定标签：**已迁移** / **部分迁移** / **保留 Bash（本轮不迁移）** / **出范围（仓库工具）**。

## 1. 总览

| 脚本 | 行数 | 运行时角色 | Go 现状 | 判定 | 风险 |
|---|---:|---|---|---|---|
| `auto_update.sh` | 515 | cron 自动升级 Xray/Nginx/GeoData/统计 | `idleleo schedule`（GeoData/统计 timer）、Go release 自升级；Xray/Nginx 升级仍走 Bash | 部分迁移 | 高：混合升级器；证书/回滚边界复杂 |
| `xray_stats.sh` | 854 | 只读统计 + watch + reset | `idleleo stats`（只读、真实 `xray api statsquery`）；`stats-collect` | 部分迁移 | 中：watch/reset 未迁移 |
| `geo_update.sh` | 244 | GeoData 下载/校验/替换/重启 | `idleleo geodata-refresh` + systemd timer（真实 Xray 验证） | 已迁移（核心） | 低：旧布局迁移未覆盖 |
| `ssl_update.sh` | 237 | ACME 证书续期 + reload | Phase 04 仅实现“外部续约契约”（指纹变化才 reload、未变不重启、私钥可读拒绝 reload、到期降级） | 保留 Bash（无 ACME） | 高：容器无公网域名/CA，不能伪造成已迁移 |
| `fail2ban_manager.sh` | 1249 | Fail2ban jail/trusted/unban | 无 | 保留 Bash | 中：历史差异“不得 `rm -f jail.d/*.local`” |
| `traffic_blocker.sh` | 1393 | 国家/IP 流量阻断、自定义路由 | 无 | 保留 Bash | 高：需规则生成后 `xray -test` |
| `file_manager.sh` | 370 | serverNames/server 文件管理 | 无独立 CLI（部分能力在 `xray generate`） | 保留 Bash | 低 |
| `rill_xray_agent_bootstrap.sh` | 21 | Rill 引导 | 无 | 保留 Bash | 低 |
| `rill_xray_agent_install.sh` | 375 | Rill agent 安装/升级 | Bridge audit/prepare/validate/activate/recover 与 `rill status` | 部分迁移 | 中：安装命令未迁移 |
| `rill_xray_agent_manager.sh` | 1180 | 执行策略/模式/epoch 管理 | 无 | 保留 Bash | 高：权限相关 |
| `rill_xray_agent_uninstall.sh` | 240 | 两阶段卸载 | 无 | 保留 Bash | 中 |
| `rill_xray_agent_verify.sh` | 64 | 静态 + live contract 校验 | 无独立命令；Bridge 的 validate 有重叠 | 保留 Bash | 低 |
| `checkout_external_repo.sh` | 50 | CI 检出外部仓库 | 无 | 出范围 | 无 |
| `merge_checked_pr.sh` | 47 | CI 合并受检 PR | 无 | 出范围 | 无 |
| `tcp.sh`（运行时下载，不在仓库） | — | BBR/加速菜单 | `idleleo tcp status/plan/apply/rollback`（仅 bbr-fq） | 部分迁移（安全子集） | 高：远程无哈希脚本 |

`install.sh` TCP 入口：

| 位置 | 行为 | Go 现状 | 判定 |
|---|---|---|---|
| `install.sh:10851-10864` `bbr_boost_sh` | 有 `scripts/tcp.sh` 就执行；否则从 `raw.githubusercontent.com/ylx2016/Linux-NetSpeed` 下载后执行 | `idleleo tcp ...` 只管理 `/etc/sysctl.d/90-idleleo-tcp.conf`，支持回退与漂移拒绝 | 部分迁移（安全子集，未替换菜单） |
| `install.sh:13384-13387` `-tcp/--tcp` | 调 `bbr_boost_sh` | 同上 | 未接线 |
| `install.sh:15493-15496` 菜单 28 | 调 `bbr_boost_sh` | 同上 | 未接线 |

## 2. 建议的迁移顺序（下一轮）

1. **低风险、已有 Go 原语**：把 `geo_update.sh` 的旧布局迁移补齐，替换 cron 中的
   `geo_update.sh`（`idleleo schedule` 已可用）。
2. **只读补齐**：`xray_stats.sh` 的 `watch` 作为 `idleleo stats --watch`；`reset`
   增加二次确认与事务记录。仍然只读配置。
3. **TCP 接线（可选）**：给 Bash 菜单增加“优先调用 `idleleo tcp`，失败再回退旧路径”
   的显式开关；不得默认执行远程 `tcp.sh`。
4. **Rill**：把 install/uninstall/verify 收敛到 Bridge 状态机；manager 的权限/epoch
   部分最后做，需专门威胁模型。
5. **高复杂、低收益**：`fail2ban_manager.sh`、`traffic_blocker.sh`、
   `auto_update.sh` 的 Xray/Nginx 升级器。建议保持 Bash 直到有真实 VPS 回归环境。

## 3. 共性风险

- **远程脚本无哈希**：`tcp.sh` 是最高风险项；Go 原生实现替代路径已给出，但未默认接线。
- **`/usr` 只读沙箱**：logrotate 的 nginx 日志目录位于 `/usr/local/nginx/logs`，
  受 `ProtectSystem=full` 限制（已由 `ReadWritePaths` drop-in 修复，见
  [DECISIONS.md](DECISIONS.md) D-001）。迁移脚本到 Go 时不得重新引入对 `/usr` 的写。
- **混合升级器**：`auto_update.sh` 同时升级 Xray/Nginx/GeoData/统计；Go 只接管了
  GeoData/统计/自升级，任何“全量接管”都需要先解决证书与回滚。
- **ACME**：`ssl_update.sh` 无法在容器内真实验收，保持 Bash 是当前唯一诚实选择。

## 4. 明确不迁移

- `checkout_external_repo.sh`、`merge_checked_pr.sh`、`scripts/*.py`（release/CI 工具）
  不属于运行时路径，保留在仓库工具链。
