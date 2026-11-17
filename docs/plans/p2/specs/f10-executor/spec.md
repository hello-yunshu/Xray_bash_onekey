# F10 执行器与命令规格（`xray tls`）

状态：已实施并经双跑验证（2026-11-17，CONTAINER_VERIFIED）。
证据：`tests/go-parity/evidence/f10-2026-11-17`。

## 1. 范围

Bash `-tls`（`install.sh` 的 `tls_type`）在托管 Nginx 上切换 TLS 版本：

- TLS 安装：只支持 TLSv1.3（h3/quic 要求），选项 1 被拒绝并循环重新询问；
- Reality + Nginx：`$ssl_preread_protocol` map 中切换 `TLSv1.2 1;` 的注释；
- 其他模式：不支持；配置文件不存在：失败；
- 变更后用 `sed -i` 直写，重启 Nginx（若托管）与 Xray。

Go 侧新增 `idleleo xray tls --version 1.3|1.2+`，不复制 `sed -i` 的无校验写入。

## 2. 实测事实

1. Reality 安装的 `etc/idleleo/conf/nginx/00-xray.conf` 含
   `map $ssl_preread_protocol $is_valid_protocol {` 与
   `        #TLSv1.2    1;`、`        TLSv1.3    1;`。
2. TLS 安装的 server 块（`03-xray-https.conf`）含
   `    ssl_protocols         TLSv1.2 TLSv1.3;`；`02-xray-server.conf` 只是
   upstream include，不含 `ssl_protocols`。
3. Bash `tls_type` Reality choice 2 的 sed 只改注释前缀，保留缩进、关键字后
   空格与行尾；choice 1 反向注释。
4. Bash TLS choice 2 的 sed 保留缩进与 `ssl_protocols` 后空格，值改为
   `TLSv1.3;`；choice 1 只打印拒绝并继续循环。
5. Bash 成功路径无条件 `systemctl restart xray`，Nginx unit 存在时先 restart
   nginx；无备份、无 `nginx -t`、无回滚。
6. 沙箱根无 systemd 时 Go 跳过 reload 并返回 warning，`reloaded=false`。
7. 缺 metadata 返回 rc=3（“缺少 manager metadata”）；无 `ssl_protocols` /
   `$ssl_preread_protocol` 的根返回 rc=1（“not a managed Nginx front”）；
   TLS/Reality 之外的模式返回 rc=1。
8. 非法、缺失、未知旗标返回 rc=2，且不写盘。

## 3. 设计决定

- D1 命令名 `xray tls`，参数 `--version 1.3|1.2+`，支持 `--json` 与
  `--container`；不新增交互循环。
- D2 文件定位按内容而非固定路径：`ssl_protocols`（TLS）或
  `$ssl_preread_protocol` + `TLSv1.2` 行（Reality），`*.conf` 按名称排序取首个。
- D3 REALITY 写入使用与 Bash 相同的正则语义（缩进、关键字后空格），值固定为
  `1;`；TLS 值固定为 `TLSv1.3;`。目标状态相同则 `changed=false`，不重启。
- D4 写入前保留原字节与原权限；`nginx -t` 失败、reload 失败均还原并报错。
- D5 reload 仅针对托管 Nginx；不重启 Xray（TLS 版本是 Nginx 设置，重启 Xray
  无收益且中断服务）。
- D6 TLS 安装拒绝 `1.2+`，返回 rc=1 与 h3/quic 说明，替代 Bash 的循环。

## 4. 分类

| 项 | 分类 | 说明 |
|---|---|---|
| Reality `1.2+` 文件字节 | aligned | 与 Bash `tls_type` choice 2 逐字节一致 |
| Reality `1.3` 文件字节 | aligned | 与 Bash choice 1 逐字节一致 |
| TLS `1.3` 文件字节 | aligned | 与 Bash TLS choice 2 逐字节一致 |
| TLS `1.2+` | approved-difference | Go rc=1 明确拒绝；Bash 循环 |
| 回滚 | approved-difference | Go 校验/还原；Bash sed 直写 |
| 重启范围 | approved-difference | Go 仅 reload Nginx 且沙箱根跳过；Bash 重启 nginx+xray |
| 文件定位 | new-go-behavior | Go 按内容定位，Bash 用全局 `nginx_conf` |

## 5. 场景（F10_test.py）

- S1 真实 Reality 安装 + 真实 `nginx -t`；`1.2+` 改 map，重复调用 no-op，
  `1.3` 回到原始字节。
- S2 Bash 基线：提取 `tls_type`，choice 2/1 与 Go 产物逐字节比较。
- S3 守卫：非法/缺失/未知旗标 rc=2，目录树摘要不变。
- S4 破坏主配置 → 切换 rc=1 且原字节保留；恢复后同一命令成功。
- S5 TLS 安装：`1.2+` rc=1（h3/quic）且零写盘；`1.3` 改 `ssl_protocols`；
  Bash TLS choice 2 逐字节一致。
- S6 门禁：缺 metadata rc=3；无托管前端 rc=1；ws-only rc=1。

## 6. 缺口

- 沙箱根不执行 systemd reload，托管 reload 路径只有单元级桩验证。
- 未在真实 VPS 验收；未做线上 TLS 握手或客户端协议协商验证。
- 未覆盖用户自建 Nginx（非 Idleleo 托管）的 TLS 文件。

## 7. 证据与验收

- 固定镜像 `idleleo-preview@sha256:ba371758104034125c9519079ef15838d8d4faf9eb23a0a1721bc0789b1234de`：
  run1 38/38、run2 38/38，0 failed。
- `meta.txt`、`commands.log`、`observed.json`、`baseline-compare.json`、
  `run{1,2}-fixture-result.json`、`f10-work/`。
- hygiene：0 findings。
- 单元测试：`go test ./internal/deploy -run TLS`。
