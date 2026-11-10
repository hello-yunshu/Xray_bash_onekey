# 2026-11-08 Docker 阶段复跑与迁移验收

> 证据等级 **DOCKER_SERVICE_VERIFIED / DOCKER_MIGRATION_VERIFIED**。
> 所有命令均在固定 digest 容器内真实执行；**不是**真实 VPS 验收，不得写成生产签收。
> 本轮只读复跑，未改宿主机网络、内核、未碰真实 VPS。

## 1. 运行环境

| 项 | 值 |
|---|---|
| 日期 | 2026-11-08 |
| 分支 | `audit/bash-go-native-parity`（自 `develop/go-native` `dd97eb1` 拉出） |
| 复跑 commit | `dac717a`（Phase 01–04 全部在 `git clone --no-hardlinks` 的干净克隆中执行） |
| 宿主 | macOS arm64，Docker 29.8.2（OrbStack，容器内核 7.2.12-orbstack） |
| 真实 Xray | Xray 26.10.31，linux/arm64，sha256 `59396499…d5328` |
| 真实 Nginx | nginx/1.24.0 (Ubuntu 24.04.5 LTS) |
| 网络 | Phase 01/矩阵 `--network=none`；Phase 02 用本地固定 GeoData origin，仅构建期访问镜像源 |

镜像 digest（构建产物）：

| Phase | 镜像 | image-id |
|---|---|---|
| 01 | `idleleo-phase01-test:1.24` | `sha256:8af4eaa68338d882c32104e30d347f575f5c23730c6249fb82b78bebd3bab6c5` |
| 02 | `idleleo-phase02-test:24.04` | `sha256:cf25f15229b42f8d5b96428a943c2816d230b923cdf4f23862f6a47f8ce3e1c3` |
| 03 | `idleleo-phase03-test:24.04` | `sha256:fd059c2d824e2456ec09adac2ab7d9b368294f5e627b4eea64a813a4969a2b39` |
| 04 | `idleleo-phase04-test:24.04` | `sha256:30d16f7c5e4c20070ad18e104d59aa549b929d2ce44dcfb83e2066493ba80fec` |

## 2. 实际命令与结果

```bash
git clone --no-hardlinks --branch audit/bash-go-native-parity <repo> /tmp/xray-c
cd /tmp/xray-c
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase01/run_phase01_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray IDLELEO_GEO_CACHE=/tmp/geoip-host.dat \
  bash tests/go-parity/phase02/run_phase02_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase03/run_phase03_container.sh
IDLELEO_XRAY_BIN=/private/tmp/xray-26/xray bash tests/go-parity/phase04/run_phase04_container.sh
```

| Phase | 真实结果 | 退出码 | 日志 |
|---|---|---|---|
| 01 CLI/事务/真实 Xray 校验 | **33 / 35 通过，2 失败** | 1（预期红） | [phase01.log](../../tests/go-parity/evidence/c-2026-11-08/phase01.log) / [c01_c12.md](../../tests/go-parity/evidence/c-2026-11-08/phase01/c01_c12.md) |
| 02 安装/卸载/GeoData/配置矩阵 E2E | **36 / 36 通过** | 0 | [phase02.log](../../tests/go-parity/evidence/c-2026-11-08/phase02.log) |
| 03 Bridge 迁移 E2E | **219 / 219 通过** | 0 | [phase03.log](../../tests/go-parity/evidence/c-2026-11-08/phase03.log) |
| 04 升级/服务/Rill/Stats 资格测试 | **42 / 42 通过** | 0 | [phase04.log](../../tests/go-parity/evidence/c-2026-11-08/phase04.log) |

合计 **330 / 332**。两项红色为**产品事实差异，不是回归**，见下节。

### 2.1 Phase 01 的两项红色（不得篡改 pin）

| ID | 期望 | 实际 | 判定 |
|---|---|---|---|
| C12.1 | `install.sh` 与 pin `0fa7052e` 字节一致（`a8e4d850…358c`） | `1a2af27e…2b7f` | FAIL |
| C12.2 | 产品代码 diff 为空 | `install.sh` +26/−1 | FAIL |

机制：`2d44d98`（logrotate `ReadWritePaths` drop-in）在 v3.3.6 发布**之后**修改了
`install.sh`，因此 `develop/go-native` 的产品代码不再与已发布 pin 字节一致。本轮的
硬约束是**保留 pin 不改**，所以这两项必须红；它们是“下次发版才会消失”的预期差异，
不是测试失效。其余 C01–C11、C12.3、C12.4 全部通过，真实 Xray 校验 `C06.real`
（`xray -test`）返回 0。

### 2.2 Phase 01 夹具缺陷修复（真实发现，非放水）

首次复跑计数为 `33/35`，但 TSV 只有 34 行：`C12.2` 的多行 `git diff` 被直接写入
TSV，嵌入换行把一行拆成两行，导致 TOTAL/FAILED 虚增。修复方式是在 `record()`
里对 `act` 做与 `cmd/detail` 相同的换行/制表符折叠（commit `dac717a`），
失败状态与 diff 内容**完整保留**，复跑后 35 行、`33/35`，与真实判定一致。
没有删除断言、没有改期望、没有把 FAIL 改成 PASS。

## 3. 迁移流程真实证据（Phase 03）

### 3.1 Bridge 状态机

容器内以真实 `systemd`、真实 Xray 26.10.31、真实 Nginx 1.24 执行：

| 阶段 | 实测 |
|---|---|
| Audit | reality/tls/relay/xtls/rill 五类均真实审计；reality 识别 1 用户、无 Nginx；xtls 判定 `legacy-xtls-removed` + `blocked` |
| Prepare | 真实写入 journal `PREPARED`，报告 state/hashes；运行配置、入口、cron 全部逐字节不变；tls 自定义片段未 `--acknowledge-custom` 时 exit 6 且不写 journal |
| Validate | `xray -test` + `nginx -t` 真实通过；注入漂移时 exit 6 |
| Activate | 真实提交 journal；schedule units 安装并 enable；旧 Bash 入口保留为恢复备份；迁移后 `systemctl restart xray`、`systemctl reload nginx` 成功 |
| Recover | 独立 `idleleo-recover` 在 after-activating / after-entry-switch / after-cron 三个时点均 exit 0，journal → `ROLLED_BACK`，运行配置逐字节还原 |

### 3.2 故障注入（真实执行，非模拟）

| 场景 | 结果 |
|---|---|
| 重复 audit | 识别 already-migrated；重复 prepare exit 3；COMMITTED 后 recover exit 3 |
| 缺少 recovery 入口 | activate 拒绝 exit 3，journal 停在 `VALIDATED`；recover 丢弃候选并 `ROLLED_BACK` |
| 验证后漂移 | validate exit 6；未到 `VALIDATED` 时 activate exit 3 |
| Rill 观测漂移 | validate exit 6；回滚报告漂移、观测文件逐字节未改 |
| 世界可读私钥 | validate 阻止 reload |
| 自定义 Nginx 片段 | 未确认时 exit 6，零落盘 |
| XTLS ONLY | 只读识别 + 阻断，不执行迁移，入口/cron/journal 均不变 |

## 4. F01–F28 覆盖变化（本轮）

- 状态标签本轮**只有一处变化**：`F25` 由「未实现」→「部分实现（容器级）」，
  因为 D 工作包新增 `idleleo tcp status/plan/apply/rollback`（Go 原生、仅管理
  `/etc/sysctl.d/90-idleleo-tcp.conf`）。仍未实现测速，也不执行远程 `tcp.sh`。
- 其余 27 项保持上一轮标签；C 阶段 330/332 的复跑**加强证据但不升格**：
  没有任何一项变成「已验证」，更没有真实 VPS 签收。
- 正式签收计数仍为 **0 / 28**（`REAL_VPS_VERIFIED` 口径）。

逐项覆盖结果与限制见 [FUNCTION_PARITY.md](FUNCTION_PARITY.md) 与
[BASH_GO_REAL_RUNTIME_PARITY_REPORT.md](BASH_GO_REAL_RUNTIME_PARITY_REPORT.md)。

## 5. 本轮不能宣称的事项

1. 这些是**容器级**结果，Phase 02–04 使用 privileged systemd 容器，宿主是 Docker VM
   内核，不是目标 Ubuntu VPS。
2. 真实 ACME 签发/续期仍未验收（无公网域名与 CA）。
3. Phase 01 的 C12.1/C12.2 红是已知产品差异，不代表 Go 与 Bash 行为不等价；
   但也不得把这两项写成“通过”。
4. 未改宿主网络/内核，未重启宿主服务。
