# Phase 02 报告（Xray 完整能力，容器级）

- 日期：2026-11-06
- 分支：`develop/go-native`（未合并 `main`，未打 tag，未发 Release）
- 实现提交：`22eac4cec2e4c1329c707bf48c8e316101f1ec26`（本轮 Go 代码与测试）
- 判定口径：2026-11-06 **用户明确授权**，`CONTAINER_VERIFIED` 即视为出口门槛满足；
  真实 VPS / 真实 ACME / 宿主 systemd 为更高等级 `REAL_VPS_VERIFIED`，**不再阻塞**。
- 本报告所有证据等级均为 **容器级**，不存在“真实 VPS 已验证”的表述。

## 1. 结论

**Phase 02 可验收部分：PASS（容器级证据）。** Docker 内完成完整的 fresh install E2E、
事务回滚与故障注入、容器 systemd、Reality 真实数据面、Relay/Nginx 语法与真实 TCP 转发、
Xray 原生 GeoData 两轮刷新周期。

- Phase 02 容器 E2E：**36 passed, 0 failed**（`phase02-exit=0`）。
- Relay/Nginx：TLS 片段与 stream 片段 `nginx -t` 通过，真实网络内 PING 经 Nginx stream 转发回显。
- GeoData：两次破坏后分别恢复到 `16475156B`（源文件 `16475153B` + 下载器 3 字节 Lua guard）。
- Phase 01 回归：**32/34 passed**（C12.1/C12.2 红：本分支携带未发布的 3.3.5，
  与已发布 pin `4752f77` 的 `install.sh` 有意偏离；C12.3/C12.4 绿）。
  审计原文的 “35/35” 是过期记录，已按实测更正。
- Go 质量门禁：`gofmt`/`go vet`/`go test`/`go test -race` 全绿。

**不具备生产发布资格**：F01–F28 仍无一项 Go 状态为“已验证”；本轮只把有实测子集的功能
推进到“部分实现（容器级）”。

## 2. 环境与镜像

| 项 | 值 |
|---|---|
| 宿主 | macOS，Docker（OrbStack），`linux/arm64` |
| 测试镜像 | `idleleo-phase02-test:24.04`，image ID `sha256:b2971f8e8a220e23d1b9b36c63def57595144826ae1b4d745368f09754c4b8f4` |
| 基础镜像 | `ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` |
| 容器内 OS / systemd | Ubuntu 24.04.5 LTS；`systemctl is-system-running` = `running` |
| 特权 | `--privileged --cgroupns=host`，挂载 `/sys/fs/cgroup:rw` |
| 真实 Xray | 26.10.31，`sha256:5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328` |
| Nginx | `nginx:1.27`，`sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d` |
| GeoData origin | 本地 `nginx:1.27` HTTPS/2，固定 digest，资产为官方 `geoip.dat`（`16475153B`） |
| 网络 | E2E 使用独立 Docker 网络；GeoData 资产经本地 HTTPS/2 origin 下载 |

## 3. 改动文件

| 文件 | 内容 |
|---|---|
| `internal/xraycfg/{xraycfg,users,share,relay}.go` | Reality/TLS/none 配置生成、用户增删查、分享 URI/Clash、Nginx stream 片段 |
| `internal/xraycfg/xraycfg_test.go` | 生成矩阵、用户生命周期、主用户保护、IPv6、分享一致性 |
| `internal/deploy/deploy.go` | fresh install / 卸载 / 保留配置重装；容器写入门槛；服务账户与日志目录权限 |
| `internal/cli/xray.go`、`internal/cli/cli.go` | `xray generate/share/relay/user/install/uninstall` 子命令 |
| `internal/app/app.go` | 用户事务（`change.Apply` + metadata 漂移检查）；成功后刷新 metadata 指纹，避免自伤漂移 |
| `tests/go-parity/phase02/Dockerfile` | 固定 digest 的 systemd 测试镜像 |
| `tests/go-parity/phase02/run_phase02.sh` | 8 组 E2E：fail-closed、fresh install、Reality 数据面、事务/回滚/故障、重装保留、生成矩阵、purge、GeoData |
| `tests/go-parity/phase02/run_phase02_container.sh` | 构建镜像/二进制、privileged systemd、本地 HTTPS/2 GeoData origin |
| `tests/go-parity/phase02/run_relay_nginx.sh` | Nginx TLS/stream 语法 + 真实 TCP 转发 |
| `docs/go/PHASE_02_REPORT.md` | 本报告 |

## 4. 验证记录（实际命令与结果）

### 4.1 Go 质量门禁

```bash
/tmp/gotoolchain/go/bin/gofmt -l cmd internal         # 无输出
/tmp/gotoolchain/go/bin/go vet ./...                  # PASS
/tmp/gotoolchain/go/bin/go test ./...                 # PASS
/tmp/gotoolchain/go/bin/go test -race ./...           # PASS
```

### 4.2 Phase 02 容器 E2E

```bash
GO=/tmp/gotoolchain/go/bin/go bash tests/go-parity/phase02/run_phase02_container.sh
```

```text
image: idleleo-phase02-test:24.04
image-id: sha256:b2971f8e8a220e23d1b9b36c63def57595144826ae1b4d745368f09754c4b8f4
xray-bin: /tmp/xray-26/xray sha256=5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328
systemd: running
xray: Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 linux/arm64)
image: Ubuntu 24.04.5 LTS
...
PASS pre-write rejection leaves no config/unit/binary (exit 2)
PASS fresh install writes report
PASS systemctl is-active xray
PASS systemctl is-enabled xray
PASS unit keeps User=xray
PASS xray runs as service account xray
PASS installed config passes real xray -test
PASS client fetched HTTP through reality tunnel (bytes=577)
PASS add user via transaction + real service restart
PASS write-fail fault leaves config byte-identical (exit 13)
PASS service-fail rolls config back byte-identically (exit 9)
PASS journal records rolled_back state
PASS uninstall keeps config
PASS reinstall with --keep-config
PASS custom DNS preserved byte-for-byte
PASS generate+test {reality,tls-ws,tls-grpc,tls-xhttp,none-ws,reality-nginx}
PASS none mode non-loopback refused without confirmation
PASS relay nginx fragment generated
PASS uninstall --purge
geodata refresh: cycle1=16475156B cycle2=16475156B (origin=16475153B expected=16475156B)
PASS two native GeoData refresh cycles restored both corruptions
== Result: 36 passed, 0 failed ==
phase02-exit=0
```

关键点说明：

- **Reality 数据面**使用真实 Xray 客户端 + 服务端；因 Xray 26 的 freedom 对回环/私网目标
  “blackholing”，测试目标改为公网 `http://example.com/`，取回 **577 字节**并含 `Example Domain`。
- **服务稳定性**：`User=xray` + `/var/log/xray` 归属服务账户（`xray:xray 0750`）后，
  `systemctl is-active` 与 `ps -o user=` 均通过。
- **事务**：用户变更走 `change.Apply`（锁 → 校验 → 提交 → 服务钩子），成功后刷新 metadata
  指纹；`write-fail` 零写入（exit 13），`service-fail` 回滚原字节（exit 9），journal 记录 `ROLLED_BACK`。
- **GeoData**：官方 `geoip.dat` 由本地 HTTPS/2 origin 提供，Xray 原生 `cron: "* * * * *"`
  两轮均完成“破坏 → 下载 → 替换 → 重载”，文件恢复为 `源大小 + 3B`。

### 4.3 Relay / Nginx

```bash
bash tests/go-parity/phase02/run_relay_nginx.sh
```

```text
== nginx -t (TLS server snippet) ==
nginx: the configuration file /work/nginx-tls-main.conf syntax is ok
nginx: configuration file /work/nginx-tls-main.conf test is successful
== nginx -t (stream relay syntax) ==
nginx: the configuration file /work/nginx-stream-syntax.conf syntax is ok
nginx: configuration file /work/nginx-stream-syntax.conf test is successful
nginx: the configuration file /work/nginx-stream-main.conf syntax is ok
nginx: configuration file /work/nginx-stream-main.conf test is successful
PASS relay TCP bytes forwarded (PING echoed)
nginx-image: nginx:1.27 sha256:6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d
```

### 4.4 Phase 01 回归

```bash
IDLELEO_XRAY_BIN=/tmp/xray-26/xray bash tests/go-parity/phase01/run_phase01_container.sh
# PHASE01: 32/34 passed, 2 failed
```

C12 当前真实状态（与上表一致）：

- C12.1 `install.sh bytes match pin`：**FAIL**。`develop/go-native` 的
  `install.sh`（3.3.5）尚未发布，与 pin `0af8e8f2…`（v3.3.4 资产）不同；
- C12.2 `product code diff empty`：**FAIL**。`git diff 4752f77..HEAD -- install.sh
  scripts config` 非空，原因是 Bridge 迁移入口与版本号变更；
- C12.3、C12.4：**PASS**。C12.4 改为加载已发布 pin（`git show $PIN:install.sh`），
  不再把 develop 上未发布的 3.3.5 误判为 legacy 损坏。

结论：C12.1/C12.2 是“发布前应有的红”，不是回归；发布 3.3.5 并更新 pin 后才会转绿。

## 5. F01–F28 状态变化

只列出本轮发生状态变化的项；其余保持 Phase 01 状态。

| 功能 | 变化 | 容器级证据 |
|---|---|---|
| F01 Reality 安装 | 未实现 → 部分实现（容器级） | fresh install、systemd active/enabled、`xray -test`、Reality 数据面；reality-nginx 仅生成+`-test` |
| F02 TLS 安装 | 未实现 → 部分实现（容器级） | ws/gRPC/xHTTP 配置生成 + 真实 `xray -test`；真实域名/证书未做 |
| F03 none+ws | 未实现 → 部分实现（容器级） | 生成 + `-test`；非回环守卫 exit 2 零落盘 |
| F05 Relay | 未实现 → 部分实现（容器级） | stream 片段 + `nginx -t` + 真实 TCP 转发；仍不能创建 Xray/UUID/证书 |
| F06 用户管理 | 未实现 → 部分实现（容器级） | list/add/remove、真实服务重启、主用户保护、事务/回滚/故障；UUIDv5 未实现 |
| F07 shortId/spiderX | 未实现 → 部分实现（容器级） | shortId 追加、分享 `sid/spx`；完整映射未实现 |
| F08 端口/SNI Guard | 部分实现（Phase 01）→ 部分实现（容器级） | serverNames/target 校验与生成；SNI Guard 未实现 |
| F11 服务启停/日志 | 部分实现（Phase 01）→ 部分实现（容器级） | install/uninstall 的 enable/start/stop/disable；日志读取未实现 |
| F16 GeoData | 未实现（Go） | Go 未生成/管理；Xray 原生双周期已容器级验证 |
| F18 分享/Clash | 未实现 → 部分实现（容器级） | 真实配置派生 URI 字段；xHTTP Clash 明确告警；二维码未实现 |
| F19 备份/恢复/保留重装 | 未实现 → 部分实现（容器级） | 卸载保留配置、`--keep-config` 重装逐字节保留自定义 DNS；backup/restore 未实现 |
| F27 卸载/purge | 部分实现（Phase 01）→ 部分实现（容器级） | 卸载保留配置、`--purge` 删除配置/log、服务停用 |
| F28 运行态/分享展示 | 部分实现（Phase 01）→ 部分实现（容器级） | `status/show` + `share` 读取真实安装结果；输出契约未逐字段差分 |

F12（真实 ACME）**不纳入本轮验收**：容器内没有公网域名与可签发 CA，无法做真实签发；
不伪造签发结果，保留为未验证项（`REAL_VPS_VERIFIED` 等级）。

## 6. 仍未验证 / 不纳入本轮

- 真实公网 VPS 上的 fresh install、宿主 systemd、真实防火墙落盘与 NAT 前置。
- 真实 ACME 签发/续期（容器内无域名/CA，明确不纳入本轮）。
- 中转节点 → 真实落地 VPS 的 REALITY 端到端链路（容器只分别验证两段）。
- TLS 模式的真实安装（需要真实域名 + 证书）。
- backup/restore、日志读取、二维码、UUIDv5、SNI Guard、完整用户映射。
- F01–F28 无一项升格为“已验证”。

## 7. 约束遵守

- 未修改真实 VPS、未执行真实迁移、未覆盖用户配置。
- 未合并 `main`、未打 tag、未发 Release。
- 未删除测试或降低阈值；`.workbuddy/` 与 `docs/plans/` 保持未跟踪、不提交。
