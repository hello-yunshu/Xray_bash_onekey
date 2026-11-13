# Nginx 线复检整改任务（按主功能口径分级）

规格：`docs/plans/nginx-line-review/spec.md`
状态：A1-A7、CFG-1～CFG-9、D-023 已完成；仅剩 T8（Block 3 真实 root）。

## 必改（A 类：主功能不一致）

### T1 默认本机 IP 403（A1）✅

- 文件：`internal/nginx/localip.go`（新增）、`internal/deploy/deploy.go`、`internal/nginx/install.go`、`internal/nginx/install_test.go`
- 改动：`LocalAddress(ctx)` 探测（`ip -4 route get` 回退 `hostname -I`）；`deploy.Install` 默认填充 `LocalIP`，失败 warning；`RewriteMainConfigWithWarnings` 锚点放宽为 `error_page ... 504`，未命中告警。
- 验证：`TestInstallAddsLocalIPGuard`、`TestRewriteWarnsWhenAnchorMissing`。

### T2 卸载/重装闭环（A2）✅（方案 1）

- 文件：`internal/nginx/install.go`、`internal/deploy/deploy.go`、`internal/cli/xray.go`、`internal/cli/flags.go`
- 改动：默认删除 `etc/idleleo/conf/nginx`；`--keep-nginx-conf` 保留；stop 失败且仍 active → 返回错误不删树；删除失败 `errors.Join` 返回；deploy 透传 `KeepNginxConf` 并回传错误。
- 验证：`TestUninstallRemovesManagedLayout`（默认删除 + KeepConf 保留两个分支）。

### T3 权限验证 + symlink（A3、A4）✅

- 文件：`internal/nginx/install.go`、`internal/nginx/install_test.go`
- 改动：`VerifyLayeredPermissions(root)`（mode/owner + `runuser` 读证书不可写）；Install/Finalize 接入；`walkFiles` 跳过 symlink 并 warning；certDir 解析失败 warning（Verify 与之同口径容错）。
- 验证：`TestVerifyLayeredPermissionsDetectsDrift`、`TestInstallToleratesSymlinkInCertDir`、`TestCertDirResolutionWarning`。

### T4 回滚健壮性（A5、C5）✅

- 文件：`internal/nginx/install.go`
- 改动：`restore` 聚合 `errors.Join` 且不短路（daemon-reload 失败后仍恢复 enable/disable/start/stop）；快照逐项恢复；备份删除失败记 warning。
- 验证：`TestRestoreKeepsGoingAfterDaemonReloadFailure`。

### T5 同 build 幂等（A6）✅

- 文件：`internal/nginx/install.go`
- 改动：`repairManagedState` 检测并修复主配置/unit/权限漂移；未漂移时不动服务，漂移时 `-t` 通过后再重启。
- 验证：`TestSameBuildRepairsMainConfigDrift`、`TestEnsureServiceSkipsRestartWhenUnchanged`、`TestInstallSkipsSameBuild`（完整配置保留）。

### T6 事务失败提示（A7）✅

- 文件：`internal/deploy/deploy.go`
- 改动：托管 Nginx 安装失败时返回的报告带 `NginxManaged/NginxDir`，错误信息提示 `idleleo xray uninstall`；修正“runtime untouched”误导注释。
- 验证：`TestManagedNginxFailureReportsResidualInstall`、`TestManagedNginxResolveFailureClaimsNothing`。

## 登记（B 类：有意分叉）

### T7 写入 DECISIONS D-023 ✅

- 文件：`docs/go/DECISIONS.md`
- 内容：manifest 严格校验、解包固定权限、HTTPS 重定向、user 回退、多 user 行、`-p`、`nginx_build_version`、无 metadata 清理、启动等待，以及 4.1.3 的配置细节分叉。

## 必改（Xray 协作配置，CFG）

### T9 TLS 配置对齐（CFG-1～CFG-5、CFG-9）✅

- 文件：`internal/xraycfg/xraycfg.go`、`internal/xraycfg/xraycfg_test.go`、`internal/deploy/deploy.go`
- 改动：
  - `01-xray-80.conf`：ACME + 301（非 443 带端口）。
  - 443 server 用 `spec.PublicPort`，四条 listen（IPv4/IPv6 + QUIC）、`http2 on`。
  - real_ip、ciphers、ecdh、session、tickets、early_data、HSTS、403 error_page、`location / 403`。
  - ws/grpc/xhttp 超时/头/buffering/`client_max_body_size 0`；xhttp 改 `grpc_pass`。
  - `02-xray-server.conf` upstream 与 `127.0.0.1.*Servers` 片段。
  - 默认证书 `/etc/idleleo/cert/xray.crt|key`（`--cert/--key` 覆盖）。
  - `verifyNginx` 的 http 包装 include `frags/*.conf`，保证 upstream 可解析。
- 验证：`TestGenerateTLSMatchesBashFront`、`TestGenerateTLSHonoursPublicPort`。

### T10 Reality 配置对齐（CFG-6、CFG-6b、CFG-7）✅

- 文件：`internal/xraycfg/xraycfg.go`、`internal/nginx/install.go`、`internal/nginx/install_test.go`
- 改动：
  - `ModeRealityNginx` 复用完整 SNI Guard stream（协议/SNI map、deny、isolate、日志），公网端口用 `spec.PublicPort`。
  - Xray inbound 固定 9443（`127.0.0.1`），避免与 Nginx 公网端口冲突。
  - 生成 `127.0.0.1.realityServers`、`<serverName>.serverNames`、`03-isolate.conf`。
  - Stream 模式主配置在 `http {` 后 include `03-isolate.conf`（去重），Install 建占位。
- 验证：`TestGenerateRealityNginxFrontsBackendPort`、`TestStreamModeIncludesIsolate`。

### T11 受管文件清理（CFG-8）✅

- 文件：`internal/deploy/deploy.go`
- 改动：写入前删除工具自有文件（01/02/03 与 `*.{serverNames,realityServers,wsServers,grpcServers,xhttpServers}`），保留 operator 文件。
- 验证：`TestWriteNginxArtifactsRemovesStaleManagedFiles`。

## 后续（Block 3）

### T8 privileged 真实 root 验收 ⏳

- 真实安装、`nginx -V`、enable/start/reboot、卸载、symlink 证书、并发、失败注入。
- 证据写入 `tests/e2e-diff/`。
- 完成前不得宣称与 bash 等价。
