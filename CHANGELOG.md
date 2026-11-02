# CHANGELOG

## 3.3.0 — 2026-11-02

首个把第四阶段优化完整交付的 Shell 版本。

### 新增

- **中转节点**：独立的 Nginx Stream 单目标 TCP 转发角色，不安装 Xray、不终止 TLS、
  不收集落地私钥；支持改目标、改监听端口、Nginx 更新与卸载。
- **GeoData 原生热更新**：普通节点由 Xray 进程按 `0 3 * * 1` 自行下载并热重载
  Loyalsoldier `geoip.dat` / `geosite.dat`，不再依赖外部 cron，也不重启 Xray。
- **自动更新可靠性**：失败记录改为 `{组件, 目标版本, 时间}`；同一坏目标不反复重试，
  元数据出现新目标会自动重试；旧 `.xray` / `.nginx` 永久标记不再阻断未来版本。
- **元数据源回退**：jsDelivr 失败或返回非法/缺字段 JSON 时回退 GitHub Raw，
  两个源都必须通过字段与版本格式校验；既有 Release/SHA/manifest 校验不变。
- **版本降级保护**：按数字段比较版本；元数据回退到更旧版本时拒绝自动降级，
  `install.sh` 与 `auto_update.sh` 同步生效。
- **REALITY 客户端下限**：模板显式写入 `minClientVer: 1.0.0`，存量配置在更新前补齐，
  不覆盖用户设置，配置测试失败时逐字节回滚。
- **证书故障恢复**：证书续签失败不再把原本运行的 Nginx 留在停止状态；
  Xray 日志目录与文件的权限收紧为 `750` / `640`。
- **无 TLS 后端默认回环**：新建 ws/gRPC/xHTTP ONLY 安装默认监听 `127.0.0.1`，
  需要公网可达时必须显式指定地址。

### 变更（不兼容）

- **移除 XTLS ONLY 模式**。旧安装不会被自动删除或迁移；重装/切换会被明确拒绝，
  需要用户主动重新部署。`xtls-rprx-vision`（Vision 流控）与 Reality 均保留。
- 纯中转节点为独立服务器角色，不支持与普通节点同机混装，也不支持多落地、UDP/QUIC、
  PROXY Protocol 或智能分流。

### 兼容性

- 支持从 **3.3.0 及更高版本** 直接升级到后续 3.3.x。
- **3.2.9 / 3.2.10 / 3.2.11** 不支持直接升级到 3.3.0：请先升级 Shell（`-u`）再更新 Xray，
  或使用重装路径（保留或重建配置）。资格门禁按此策略验证真实支持路径，不使用
  expected-incompatible 豁免把失败刷成通过。

### 验证

- 本地定向回归：自动更新失败记录 46 断言、REALITY 下限 12、降级守卫 29、
  Xray 更新事务 53；安装菜单 221、重装调用链 160、GeoData 93、中转 112。
- 容器整机：Reality 32/32、Reality+Nginx 51/51、ws/gRPC/xHTTP 33/33、TLS 31/31、
  中转 30/30；Linux（Debian 12）`test_xray_version_pipefail` 通过。
- 真实 VPS 上的证书续签恢复、中转→真实落地端到端、Reality/TLS 外网完整数据面、
  低内存峰值与 `ProtectSystem` 组合仍需实机验证。
