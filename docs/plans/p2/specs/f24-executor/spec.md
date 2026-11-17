# F24 执行器与容器交付规格（`container` 命令 + 产品镜像）

状态：待实施（Spec Mode，2026-11-17）。目标级别 CONTAINER_VERIFIED。
对应 Bash：`docker/docker-entrypoint.sh`、`docker/fake-systemctl`、`docker/Dockerfile`。
R16：不能假设宿主 systemd/DBus；容器内必须能不依赖 systemd 启停自有服务。

## 1. 现状与问题

1. 现有镜像只有 Bash 交付：`/usr/bin/idleleo -> /etc/idleleo/install.sh`；Go 二进制不在镜像内。
2. `docker-entrypoint.sh` 的 `_start_services`/`_stop_services`/`_watchdog` 全部通过
   `systemctl` 启停，依赖 `docker/fake-systemctl` 的伪 unit 状态；无真实 systemd。
3. Go `service` 包只驱动真实 systemd unit，且 `--root /` 在容器内需要
   `--container` + `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY`，容器交付没有入口。
4. `docs/release/KNOWN_LIMITATIONS.md` 明确「本轮 Docker 只是测试环境」。

## 2. 范围

### 2.1 新增 Go 包 `internal/container`

`runtime.go`：

- `type Mode string`：`systemd` / `direct`。
- `DetectMode() Mode`：`/run/systemd/system` 是目录且 PATH 有 `systemctl` 时为
  `systemd`，否则 `direct`。
- `type StatusReport struct {SchemaVersion int; Root string; InContainer bool; Mode Mode;
  Xray ServiceState; Nginx ServiceState; Warnings []string}`；
  `ServiceState{Required, Config bool, PidFile string, Pid int, Alive bool, Source string}`。
- `Status(root string) (StatusReport, error)`：只读。读 `store.LoadMetadata` 与
  `<root>/etc/idleleo/conf/xray/config.json`；pid 文件为
  `<root>/run/idleleo/container-{xray,nginx}.pid`；`Alive` 用 `os.FindProcess` +
  `signal 0` 判定；systemd 模式额外调用一次 `systemctl is-active`（失败记 warning，
  不伪造运行态）。
- `Up(ctx, Spec{Root, AllowContainerWrites, DryRun}) (UpReport, error)`：
  - `host.RequireSystemWrite(root, ack)`；
  - 加载 metadata，决定需要哪些服务：`Xray` 始终需要；`Nginx` 仅当 metadata
    `TLS != "None"` 且存在 `etc/idleleo/conf/nginx`；
  - `systemd` 模式：`systemctl start xray`（及 nginx），记录 `source=systemd`；
  - `direct` 模式：`os/exec` 直接启动
    `<root>/usr/local/bin/xray run -config <root>/etc/idleleo/conf/xray/config.json`
    与 `<root>/usr/local/nginx/sbin/nginx -c <root>/usr/local/nginx/conf/nginx.conf -g "daemon off;"`
    （nginx 配置不存在时仅 xray），stdout/stderr 追加到
    `<root>/var/log/idleleo/container.log`（0640），pid 写入上述 pid 文件（0644）。
  - 幂等：pid 存活且属于同一 root（读 `/proc/<pid>/cmdline` 校验包含 root 路径，
    找不到 `/proc` 时只校验存活）则跳过；
  - 至少启动一个服务返回 0；一个都没启动返回 1；
  - `DryRun` 只输出计划，不建目录、不写 pid、不启动进程。
- `Down(ctx, Spec{...}) (DownReport, error)`：先按 pid 文件发 SIGTERM、等待 5s、
  SIGKILL 兜底；systemd 模式调用 `systemctl stop xray`/`nginx`；删除 pid 文件；
  二次调用为 no-op（`stopped=[]`，rc=0）。

### 2.2 CLI

- `internal/cli/container.go`：`container status|up|down`，`--json`、`--container`、
  `--dry-run`（仅 up）。
- `internal/cli/cli.go` dispatch 增加 `case "container"`。
- `internal/cli/flags.go` 增加
  `"container status"`、`"container up"`、`"container down"` 白名单：
  values 无；bools `json`、`container`、`dry-run`（后两者仅 up 接受，其余 rc=2）。
- 帮助文本 `internal/i18n/i18n.go` 增加三行。

### 2.3 产品镜像与入口

- `docker/Dockerfile`：新增 `FROM golang:1.27.4 AS gobuild`，在 `/src` 用
  `CGO_ENABLED=0 go build -mod=vendor -trimpath -o /out/idleleo ./cmd/idleleo`
  （构建上下文为仓库根，新增 `.dockerignore` 仅保留 `go.mod`/`go.sum`/`vendor`/
  `cmd`/`internal`/`docker`）；运行阶段 `COPY --from=gobuild /out/idleleo
  /opt/idleleo/bin/idleleo`，`chmod 0755`，`LABEL org.opencontainers.image.title`。
  保留 `/usr/bin/idleleo -> install.sh`（Bash 菜单兼容）与 `fake-systemctl`。
- `docker/docker-entrypoint.sh`：
  - 新增 `_go_container()`：`[[ -x /opt/idleleo/bin/idleleo ]] && [[ ! -d /run/systemd/system ]]`；
  - `_start_services`/`_stop_services` 在 `_go_container` 下改为
    `IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY /opt/idleleo/bin/idleleo container up|down --container`；
  - `_watchdog` 在 `_go_container` 下用
    `/opt/idleleo/bin/idleleo container status --json` 判定，不再调用 `systemctl`；
  - 其余模式（无 Go 二进制 / 有 systemd）行为逐字节保持。
- `docker/DOCKER.md`：补「Go 原生容器模式」一节，说明不再依赖 fake-systemctl 的
  启动路径、`container status/up/down`、日志位置和仍然存在的 gap。
- 不改 `install.sh`、不改 `docker/fake-systemctl`。

## 3. 设计决定

- D1 容器交付的判定依据是「systemd 是否可用」，不是镜像名或环境变量；两条路径都保留。
- D2 `direct` 模式由 Go 直接管理子进程与 pid 文件，不写 unit、不调用 DBus。
- D3 `up` 幂等且返回后服务继续运行；`down` 幂等；状态永远从 pid/真实进程推导。
- D4 真实根仍走 `host.RequireSystemWrite` 双重门禁；沙箱根必须带 marker。
- D5 镜像内 Go 二进制只做容器入口，不替换 `/usr/bin/idleleo`，Bash 菜单保持可用。
- D6 不把 fake-systemctl 当成 systemd 的等价物：Go 路径不读它，仅作为 Bash 兼容保留。

## 4. 分类

| 项 | 分类 | 说明 |
|---|---|---|
| 启停 xray/nginx 的最终效果 | aligned | Bash 经 fake-systemctl，Go direct 直接进程 |
| systemd 依赖 | approved-difference | Bash 依赖伪 unit；Go direct 无 DBus/unit |
| 状态可见性 | new-go-behavior | Go 输出 pid/alive/mode JSON；Bash 只打印 echo |
| 镜像内容 | new-go-behavior | 镜像新增 Go 二进制与 container 命令 |
| 日志位置 | approved-difference | Go 统一写 `var/log/idleleo/container.log` |

## 5. 场景（`tests/go-parity/parity/features/F24_test.py`）

- S1 空沙箱：`container status --json` → `inContainer=true`、`mode=direct`、
  两服务 `alive=false`，零写盘。
- S2 真实 nginx 树 + 假 xray 脚本（`#!/bin/sh sleep 60`）+ metadata：
  `container up --container --dry-run` 零写盘；去掉 dry-run 后 pid 文件存在、进程存活、
  `status` 的 pid 与文件一致、日志文件出现。
- S3 `container down --container` 停止进程并删 pid 文件，二次 down rc=0 且
  `stopped=[]`；`status` 回到 alive=false。
- S4 幂等：服务运行中再次 `up` 不重复启动（pid 不变）。
- S5 门禁：真实根 `/` 未确认 rc=2 且无写；`--root` 无 marker rc=2；未知旗标 rc=2。
- S6 静态交付契约：Dockerfile 含 gobuild stage 与 `/opt/idleleo/bin/idleleo`；
  entrypoint 含 `container up|down|status` 且 `_go_container` 不调用 systemctl；
  `fake-systemctl` 仍存在且可执行；DOCKER.md 提到 `container status`。
- S7 Bash 基线：从 `docker-entrypoint.sh` 提取 `_start_services`/`_stop_services`，
  把绝对路径改写进沙箱，`systemctl` 换成本地记录 shim 后真实执行；断言同样启动/停止
  xray+nginx（记录 `started=[xray,nginx]`）。Go direct 与 Bash 的差异写入
  `baseline-compare.json`（approved-difference：无 systemd、pid 日志）。

## 6. 缺口（必须写进证据与文档）

- 容器内没有真实 systemd，systemd 分支只能在真实 VPS 验收。
- 用假 xray 脚本代替真实 Xray 数据面；nginx 只验证进程与配置启动，不做客户端流量。
- 不在本轮实际 `docker build`（无网络/无 Docker-in-Docker 保证）；镜像契约由静态断言
  与 fixture 内运行 Go 二进制证明。
- 未验证 Docker Desktop、Podman、非 Linux 宿主。

## 7. 文件清单

新增：`internal/container/runtime.go`、`internal/container/runtime_test.go`、
`internal/cli/container.go`、`tests/go-parity/parity/features/F24_test.py`、
本 spec 三件套。
修改：`internal/cli/cli.go`、`internal/cli/flags.go`、`internal/i18n/i18n.go`、
`docker/Dockerfile`、`docker/docker-entrypoint.sh`、`docker/DOCKER.md`、
`docs/go/FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md`、
`tests/go-parity/parity/features/README.md`。

## 8. 验收与审批

- 固定镜像双跑：run1/run2 全绿、0 failed；证据
  `tests/go-parity/evidence/f24-2026-11-17`；hygiene 0 findings。
- 单元测试：`go test ./internal/container ./internal/cli`。
- 需要用户批准：新增 `container` 命令面、Dockerfile 多阶段构建、entrypoint 分叉。
