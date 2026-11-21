# Docker 与 VPS 的能力边界

> 本轮允许的等价：可丢弃的 Linux 容器、独立网络命名空间、真实 systemd 容器、
> 真实 Nginx/Xray 客户端、本地 CA/Pebble。不能等价的一律标 `VPS_DEFERRED`。

## 1. Docker 已证明

| 能力 | 证据 | 说明 |
| --- | --- | --- |
| 双端安装/幂等/回滚 | `round3-final-20261120-1821-df3f3838/p2` | M1–M10 两侧 install rc=0，两轮 L4/L6 ok |
| 真实数据面 | 同上 + `docker-final-r1.../r1` | 独立客户端容器真实拨号，不是配置比对 |
| 真实 Nginx | `ops08-27-real-nginx.log`、P0-A | `nginx -t` 与跨容器监听边界 |
| 真实 ACME 协议 | `round3-final.../p2/M8` | Pebble `acme_directory=https://pebble:14000/dir`，签发 exit=0 |
| 冷恢复 | `goevo-coldrestore-docker-final-cold...` | 源容器销毁，目标容器恢复并重启后客户端仍通 |
| 故障注入 | `logs/p1e-fault-injection.log`、A1/A3 | 无 root、只读、ENOSPC/EROFS/EACCES、断网、坏 journal、SIGKILL、并发、回滚失败 |
| 离线门禁 | `gate-final.log`、`race-final.log` | `--network none` 全量测试与 8 包 `-race` |
| 前后端升级/接管 | `docker-final-r1.../r1/assertions.txt` | R1/R2/INJ 106 PASS / 0 FAIL |

## 2. 只能由独立 VPS 证明（VPS_DEFERRED）

| 项 | 原因 | 本轮替代与限度 |
| --- | --- | --- |
| systemd 真机重启、开机自启、掉电恢复 | 容器不是独立内核/固件，OrbStack 重启不等于 VPS 断电 | 已做容器 stop/start 与冷恢复；不声称掉电安全 |
| 公网 CA（Let's Encrypt 生产）/DNS-01/EAB | 任务禁止操作生产 VPS 与真实域名 | Pebble 只证明 ACME 协议互操作；公网 CA 标 `BLOCKED` |
| 外部 IPv6 数据面 | 宿主无公网 IPv6，Docker 默认 bridge 无 IPv6 路由 | 已证明 `[::]` 监听与 `::1` 数据面；外部客户端标 `VPS_DEFERRED` |
| 真实 SSH 断线/长时间会话 | 容器内无独立 sshd 与公网链路 | 以进程 SIGKILL/重启近似；不声称 SSH 场景 |
| 多版本 Xray/Bash 历史发行物矩阵 | 需固定历史 Release 资产与多个可复现旧环境 | 本轮只做固定 fixture 与 Xray `26.10.31`；标 `NOT_RUN` |
| 30 分钟 + 两个调度周期 soak | 无现成长期 runner，任务书不要求新增架构 | 标 `NOT_RUN`，不以短时通过替代 |
| 第二发行版关键 smoke | 本轮只准备 Ubuntu 24.04 E2E 镜像 | 标 `NOT_RUN`；不扩展 OS 支持承诺 |

## 3. 结论口径

- **Docker 开发候选**：只对“容器可执行项”下结论；未执行项必须在
  `final-gates.json` 中逐条列出，不能用 Go-only sweep 或旧证据替代。
- **正式发布**：必须等 VPS_DEFERRED 与任务书授权同时满足；本轮一律
  `尚未授权 / NO-GO`。
- 任何“容器内通过”都不等价于“生产 VPS 通过”；报告与 PR 描述均不得这样写。
