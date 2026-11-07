# Phase 00 — Bash ↔ Go 配置桥接契约

> 目标：Go 管理器接管时，**不重写用户配置、不丢字段、不把 Bash 元数据当成事实来源**。
> 基线：`4752f77` 的 `install_config_*` 字段与 `config/vless_*.json` 模板。
> 本文件只定义契约与 schema 草案；Phase 00 不实现 Go 桥接。

## 1. 两层模型

| 层 | 位置 | 性质 |
|---|---|---|
| Bash 元数据层 | `/etc/idleleo/conf/install_config.json`（0600） | 面向菜单/分享的**缓存与展示字段**，可能过期或被手改 |
| 运行事实层 | `/etc/idleleo/conf/xray/config.json` + `status_config.json` | Xray 真正加载的配置 |
| 展示层 | `/etc/idleleo/info/xray_info.inf`、`xray_info_clash.yaml`（0600） | 由运行事实派生的分享信息 |
| Go 所有权层（新增） | `/etc/idleleo/v1/metadata.json`（0600） | 记录 Go 新建了哪些资源、指纹、来源、可删除性 |

**权威顺序**：运行事实层 > Bash 元数据层 > 展示层。
冲突时以 Xray 配置为准，并把差异写入 `drift`，**不得静默写回**。

## 2. 字段映射

### 2.1 Reality（`shell_mode=Reality`）

| `install_config` 字段 | Xray 配置位置 | 桥接规则 |
|---|---|---|
| `id` / `email` | `.inbounds[].settings.clients[].id/email` | 以 Xray 配置为准；用于展示时可读回退 |
| `privateKey` | `.streamSettings.realitySettings.privateKey` | **只以 Xray 配置为准** |
| `publicKey` / `password` | 派生值（`xray x25519 -k privateKey`） | 不信任缓存；需要时重算 |
| `shortIds` | `.streamSettings.realitySettings.shortIds` | 以 Xray 为准；空数组合法 |
| `target` | `.streamSettings.realitySettings.target` | 以 Xray 为准；变更需 `xray -test` |
| `serverNames` | `.streamSettings.realitySettings.serverNames` | 以 Xray 为准；与 Nginx SNI guard 必须一致 |
| `spiderx_path` | `.streamSettings.realitySettings.spiderX` | 以 Xray 为准 |
| `port` | `.inbounds[].port` | 以 Xray 为准 |
| `net` | `.streamSettings.network` | `raw`/`tcp` 等；不得把未知值猜成 `raw` |
| `tls` | `.streamSettings.security` | `Reality` 断言失败则拒绝桥接 |
| `reality_add_nginx` / `reality_nginx_sni_guard` / `unknown_sni_policy` / `decoy_domain` | Nginx 配置，不在 Xray config | 从 Nginx 文件只读探测；冲突时报告，不自动合并 |
| `reality_add_balance` / `reality_balance_role` | 多 inbound/Nginx upstream | 需要结构探测，不能仅凭字符串 |
| `ipv4_address` / `ipv6_address` / `network_mode` | 监听地址（不是 Xray DNS） | 以 Xray `listen` 为准；`network_mode` 仅展示 |
| `shell_version` / `xray_version` / `nginx_build_version` / `idc` | 无运行时对应 | **仅展示**，不得参与路径/权限/决策 |

### 2.2 TLS / ws / gRPC / xHTTP（`shell_mode=TLS` 或 `None`）

| 字段 | Xray 位置 | 规则 |
|---|---|---|
| `port`、`ws_port`、`grpc_port`、`xhttp_port` | 对应 inbound `port` | 以 Xray 为准；组合模式按 inbound tag 识别 |
| `net` / `transport_mode` | `.streamSettings.network` | tag + network 双重识别；未知组合拒绝 |
| `path` / `ws_path` | `.streamSettings.wsSettings.path` | 以 Xray 为准 |
| `serviceName` | `.streamSettings.grpcSettings.serviceName` | 以 Xray 为准 |
| `xhttp_path` | `.streamSettings.xhttpSettings.path` | 以 Xray 为准 |
| `tls` | `.streamSettings.security` | `TLS` 需要证书存在且 `xray -test` 通过 |
| `cert` 路径 | 不在 install_config，固定 `/etc/idleleo/cert/` | 只读；不得复制/替换证书内容 |

### 2.3 Relay（`shell_mode=Relay`）

| 字段 | 事实位置 | 规则 |
|---|---|---|
| `relay_backend_host/port` | `/etc/idleleo/conf/nginx/relay-stream.conf` 的 `proxy_pass` | 以 Nginx 文件为准；解析失败则拒绝 |
| `relay_listen_addr/port` | `relay-stream.conf` 的 `listen` | 同上 |
| `relay_enabled` | Nginx 配置 + 服务状态 | 以实际配置/进程为准 |
| Xray / UUID / 证书 | **不应存在** | 发现残留只报告，不接管、不删除 |

### 2.4 自定义用户数据（必须保留）

以下字段不属于项目生成的固定值，桥接/备份/恢复必须原样保留：

- `.dns.servers` 及其它 `dns` 字段（用户 DoH/自定义 DNS）；
- `.routing.rules` 中非项目指纹的规则；
- `.outbounds` 中非项目 tag；
- 用户手改的 Nginx 片段（非项目文件名）。

fixture `custom-dns-routing/` 覆盖该场景。

## 3. 不可信字段清单

以下字段**禁止**直接用于：拼路径、决定删除范围、决定所有者、决定是否覆盖：

- `install_config.host`、`.email`、`.id`、`.path`、`.serverNames`、`.decoy_domain`
- `shell_version`、`xray_version`、`idc`
- `info/xray_info.inf` 中的任何展示字段

必须改用：Xray 配置解析结果 + 文件指纹 + Go 所有权记录。

## 4. Go 元数据 schema v1（草案）

路径：`/etc/idleleo/v1/metadata.json`，权限 `0600`，原子写（临时文件 + rename），
schema 校验失败时**拒绝启动管理操作**并进入只读诊断。

```json
{
  "schema_version": "idleleo/v1",
  "install_id": "00000000-0000-4000-8000-000000000000",
  "created_at": "2026-11-06T00:00:00Z",
  "updated_at": "2026-11-06T00:00:00Z",
  "mode": "reality",
  "manager": {
    "provider": "go",
    "version": "0.0.0-phase00",
    "compatible_bash_version": "3.3.4"
  },
  "bridge": {
    "last_import_from_bash": {
      "at": null,
      "source_shell_version": null,
      "drift": []
    }
  },
  "ownership": [
    {
      "id": "own-0001",
      "kind": "file",
      "path": "/etc/idleleo/conf/xray/config.json",
      "provider": "project",
      "created_by": "bash",
      "removable": true,
      "fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "release_asset": null,
      "notes": "shared with user edits; never delete on drift"
    },
    {
      "id": "own-0002",
      "kind": "cron",
      "path": "root-crontab:auto_update.sh",
      "provider": "project",
      "created_by": "go",
      "removable": true,
      "fingerprint": "line:0 1 * * * bash /etc/idleleo/scripts/auto_update.sh",
      "release_asset": null,
      "notes": "delete by fingerprint only"
    }
  ],
  "user_data": {
    "custom_dns": true,
    "custom_routing": true,
    "custom_outbounds": true,
    "custom_nginx_fragments": true
  },
  "last_transaction": {
    "id": "txn-0001",
    "state": "committed|rolled_back",
    "journal_path": "/etc/idleleo/v1/journal/txn-0001.json"
  }
}
```

约束：

- `ownership[].path` 必须是规范化绝对路径；拒绝 `..`、glob、通配符。
- `fingerprint` 只用于「是否仍是我们写的那一份」，**不能**替代权限/所有权检查。
- `removable=false` 的资源永不由 Go 删除。
- `bridge.last_import_from_bash.drift` 记录字段级差异（字段、Bash 值、运行值），不自动修复。

## 5. 桥接操作矩阵

| 操作 | 读取 | 写入 | 网络 | 前置条件 | 失败行为 |
|---|---|---|---|---|---|
| Detect | Bash 元数据 + Xray 配置 + Nginx 片段 | 无 | 无 | root 或只读模式 | 返回结构化 JSON，退出非 0 仅在无法解析 |
| Import | 同上 | `metadata.json`（仅 draft） | 无 | 显式用户确认 | 不覆盖现有 metadata，保留 draft |
| Migrate | 同上 + 备份 | journal、备份、staged 配置、metadata | 无 | 显式确认 + 健康检查计划 | 逐级回滚到迁移前 |
| Activate | staged 配置 | 运行配置 + 服务 | 本地 | `xray -test` + `nginx -t` 通过 | 恢复上一份配置与服务状态 |
| Drift check | 全部 | 无 | 无 | 任意 | 只报告 |
| Reject XTLS ONLY | `install_config.tls=XTLS` | 无 | 无 | 任意 | 只读退出，提示不支持 |

### 5.1 事务与日志

1. 生成 `journal`（目标路径、原指纹、备份路径、计划动作）。
2. 备份到 `/etc/idleleo/backups/<txn>/`。
3. 写 staged 文件并校验（JSON 解析、`xray -test`、`nginx -t`、权限）。
4. 原子替换 + 重启/重载。
5. 健康检查（进程 active、端口、`--json` 统计、入口联通性可配置）。
6. 成功 → journal `committed`；任一步失败 → 恢复备份 + 原服务状态，journal `rolled_back`。

### 5.2 只读契约

`--show`、`--stats`、`--json`、日志读取、`-h` 等只读命令：

- 不触发 Detect/Import/Migrate；
- 不写任何文件（包括日志锁、metadata、cron）；
- 不访问网络（Bash 基线在启动阶段会联网，这是 R05；Go 必须修正）。

## 6. 兼容与拒绝

| 场景 | 行为 |
|---|---|
| Bash `3.3.4` + Reality/TLS/Relay | 可 Import；需字段级 drift 报告 |
| Bash 旧版（`tls=XTLS`） | **拒绝迁移**，只读说明；不启动 Xray 接管 |
| 混合残留（Relay 上发现 Xray 配置/证书） | 报告并拒绝自动清理 |
| `install_config.json` 缺失但 Xray 配置存在 | 允许 Detect；Import 需从运行配置重建，标记 `metadata_missing` |
| metadata schema 不合法 | 管理操作拒绝启动，进入只读模式 |

## 7. 验收挂钩

- fixture：`tests/fixtures/legacy/{reality-direct,reality-nginx,tls-multi,relay,custom-dns-routing,xtls-only}`。
- L0/Bridge 合成测试只证明「纯函数/参考实现」；Phase 00 不声称桥接已实现。
- 下游阶段必须新增：Import 幂等、drift 不覆盖、XTLS 拒绝、Relay 无 Xray、事务回滚、只读零写入。
