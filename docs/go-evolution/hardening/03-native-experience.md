# 03 · 原生体验与证据边界（P3）

- 分支：`work/go-hardening-parity-20261119`
- 代码提交：`911f91d2`（P3 探针与 relay 支持的最终代码）；`de43a36b` 只修正 P3 runner 的空数组展开
- 基线：`develop/go-native` @ `9b965843dccc955eee8b91903749500f082271f7`
- 执行时间：2026-11-19（Asia/Shanghai）
- 环境：macOS 宿主无 Go；全部 Go 构建/测试在 `golang:1.27.4` 容器内执行（`GOFLAGS=-mod=vendor`，`GOPROXY=off`，`GOTOOLCHAIN=local`）
- 真实运维场景在 `idleleo-e2e:24.04` 容器内执行：真实 systemd、真实 Xray、真实 nginx、真实本地 TLS origin

本文件只记录实际执行结果。没有执行的项一律标记 `NOT_RUN` 或 `BLOCKED`，不使用历史 SHA 的通过结果冒充当前 SHA。

## P3-01 doctor：三层证据与真实客户端探针

### 变更

新增 `internal/clientprobe`（真实 Xray 客户端 + 临时 SOCKS + HTTP 请求）与 `doctor --client-probe`：

| 证据级别 | 含义 | 产生条件 |
| --- | --- | --- |
| `FILE_AND_SERVICE` | 只读检查文件、权限、单元与服务状态 | 默认 |
| `TCP_REACHABLE` | 入站端口可建立 TCP 连接 | `--deep`，端口可连 |
| `TLS_HANDSHAKE` | 在入站端口完成 TLS 握手 | `--deep`，TLS 入站 |
| `REAL_CLIENT_PASS` | 真实 Xray 客户端经代理取得 origin 的 200 与正文 | `--client-probe` 成功 |

关键实现：

- `internal/doctor/doctor.go`
  - `Report` 新增 `evidenceLevel` 与 `limitations`。`healthy` 的语义仍是“没有 fail 的检查”，不再被解释为端到端可用。
  - 连接性证据改为 `TCP_REACHABLE` / `TLS_HANDSHAKE`，Reality 入站仍只到 `TCP_REACHABLE`。
  - `--client-probe` 从运行配置中选取第一个带用户的 VLESS 入站，推导 Reality 公钥（`xraycfg.DerivePublicKey`），启动已安装的 Xray 客户端，经临时 SOCKS 对 `--probe-url` 发起 HTTP GET，要求 `200` 且正文非空（或包含 `--probe-expect`）。
  - 失败为 `fail`，不是 `unknown`；缺少二进制、缺少 URL、无带用户入站均为 `skip` + `NOT_RUN`。
- `internal/clientprobe/clientprobe.go`
  - 临时客户端配置目录 `0700`、文件 `0600`，探针结束立即删除；只监听 `127.0.0.1` 的临时 SOCKS 端口；不写受管根目录、不重启服务、不改监听端口。
  - 支持 `raw` / `ws` / `grpc` / `xhttp`，安全层支持 `reality` / `tls` / `none`。
- `internal/cli/doctor.go`、`internal/cli/flags.go`
  - 新增 `--client-probe`、`--probe-url`、`--probe-expect`。`--client-probe` 缺少 `--probe-url` 时直接 rc=2，不静默降级。

### 覆盖范围与真实结果

| 传输 | 场景 | 结果 | 证据 |
| --- | --- | --- | --- |
| Reality + raw | P3 驱动真实安装后探针 | `LOCAL_RUN` PASS（62/62） | `evidence/goevo-p3-20261119-p3raw2/`，rc=0，`evidenceLevel=REAL_CLIENT_PASS` |
| Reality + ws | `E2E_TRANSPORT=ws` 真实安装 | `LOCAL_RUN` PASS（62/62） | `evidence/goevo-p3-20261119-p3ws2/`，E13b rc=0 |
| Reality + grpc | `E2E_TRANSPORT=grpc` 真实安装 | `LOCAL_RUN` PASS（62/62） | `evidence/goevo-p3-20261119-p3grpc2/`，E13b rc=0 |
| Reality + xhttp | `E2E_TRANSPORT=xhttp` 真实安装 | `LOCAL_RUN` PASS（62/62） | `evidence/goevo-p3-20261119-p3xhttp2/`，E13b rc=0 |
| relay | Nginx Stream 转发节点 | `LOCAL_RUN` PASS（真实 HTTP 经 relay） | `evidence/20261119-m10relay2/p2/M10/go/doctor-relay.json`：`relay-probe=ok`、`evidenceLevel=REAL_CLIENT_PASS`、`healthy=true`、rc=0 |

四条 Xray 传输均在 `911f91d2` 上由真实安装的 Xray 客户端完成请求；relay 没有 Xray 入站与用户凭据，
`doctor` 会识别 `role=relay`，解析受管 `stream{}` 片段并以真实 HTTP 请求穿过监听端口证明转发，
报告为 `REAL_CLIENT_PASS`，同时 limitation 明确它证明的是转发而不是 VLESS 会话。

实际探针输出（`p3raw2`，原始 JSON 摘录）：

```json
{
  "evidenceLevel": "REAL_CLIENT_PASS",
  "healthy": true,
  "client-probe": {
    "status": "ok",
    "message": "a real client reached the origin through 127.0.0.1:443",
    "detail": "HTTP/1.0 200 OK, 12 body bytes",
    "evidence": "REAL_CLIENT_PASS"
  }
}
```

（上表为 `E13b-doctor-probe/stdout.txt` 的字段摘录，完整 JSON 在证据目录。）

### 明确的边界

`Report.limitations` 固定写入并在 JSON 中输出：

- 证书链、SAN 与有效期来自受管 PEM，不查询公共 CA 信任库。
- 外部 origin、DNS 与云安全组不在本进程范围内；只能验证本机能到达的路径。
- Reality 入站的 TCP/TLS 握手不是用户会话；只有 `--client-probe` 能证明用户级可用。
- TLS 入站探针证明隧道，不证明公网证书链。
- relay 节点没有 Xray 入站与用户凭据；它的 `--client-probe` 是穿过 Nginx Stream 的真实 HTTP 请求，证明转发而不是 VLESS 会话。

## P3-02 update preflight：兼容性不再用布尔值冒充

### 缺陷

旧实现 `Compatible = configStatus != EvidenceFail`，当 `config-parses` 为 `not-run` 时仍输出 `compatible: true`。调用方会把“未验证”读成“已验证兼容”。

### 变更

`internal/componentupdate/preflight.go` 新增 `readiness`：

| readiness | compatible | 条件 |
| --- | --- | --- |
| `verified` | `true` | 构件 installable 通过，且 `config-parses` 实际通过 |
| `unverified` | `false` | 构件 installable 通过，但没有已安装配置可解析（`config-parses=not-run`） |
| `incompatible` | `false` | 构件失败、配置解析失败、降级或下载失败 |

`compatible` 字段保留以兼容旧消费方，但只有真正执行并通过配置解析时才为 `true`；CLI 文本输出同时打印 `readiness`。`docs` 与 JSON 均未把 `not-run` 宣称为可用。

新增测试：

```bash
docker run --rm -v "$PWD:/src:ro" -w /src \
  -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local golang:1.27.4 \
  bash -c 'export PATH=$PATH:/usr/local/go/bin; export GOCACHE=/tmp/gocache; \
  go test -count=1 ./internal/componentupdate'
```

结果：`ok github.com/hello-yunshu/Xray_bash_onekey/internal/componentupdate`，退出码 0（2026-11-19 本地执行）。

覆盖用例：`TestPreflightQualifiesXrayWithoutTouchingInstalledBinary`、`TestPreflightRejectsCandidateThatCannotParseInstalledConfig`、`TestPreflightRefusesDowngrade`、`TestPreflightRejectsScriptForRealRoot`、`TestPreflightWithoutInstalledConfigIsUnverifiedNotCompatible`、`TestPreflightNginxTestsCandidateAgainstInstalledConfig`。

### 版本矩阵的诚实边界

当前宿主与仓库只缓存一个真实 arm64 Xray 归档（校验值见 P3 证据 `xray_sha256=593964...`），没有多个真实候选二进制。测试用 fixture 脚本覆盖 `1.8.20`（已安装）与 `1.8.24`（候选）的升级路径，以及格式非法、ELF/架构不符、digest 不符、降级、无配置等分支。真实二进制版本矩阵：`NOT_RUN`，不得据此声称已覆盖全部历史版本。

## P3-03 hot-user：持久化先于运行态，崩溃与移除不回归

### 实际执行

```bash
E2E_RUN_ID=20261119-p3raw2 bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=20261119-p3ws2 E2E_TRANSPORT=ws bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=20261119-p3grpc2 E2E_TRANSPORT=grpc bash tests/e2e-diff/run_p3_hot.sh
E2E_RUN_ID=20261119-p3xhttp2 E2E_TRANSPORT=xhttp bash tests/e2e-diff/run_p3_hot.sh
```

真实结果（`tests/e2e-diff/evidence/goevo-p3-20261119-p3raw2/run.json`）：

| 字段 | 值 |
| --- | --- |
| runId | `20261119-p3raw2`（及 `p3ws2`/`p3grpc2`/`p3xhttp2`） |
| commit | `de43a36b117718c09fcb969fdc52a2c8a8701603`（Go 代码同 `911f91d2`） |
| image | `idleleo-e2e:24.04` @ `sha256:2e722b98...` |
| idleleo sha256 | `1934067cbd77f611b58b36fa72ef3a82db41c9ca66215981d18fedf242d7e77f` |
| xray sha256 | `5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328` |
| assertions | 62 |
| passed | 62（四条传输各自 62/62） |
| failed | 0 |
| driver_rc | 0 |
| 结论 | `PASS` |

关键场景与断言（均来自 `container/driver/assertions.txt`）：

- 无 API 时热添加：rc=8，报告“已持久化、未应用”，磁盘配置已含新用户，运行进程拒绝新凭据；进程崩溃重启后新用户可用。
- 有 API 时重试：跳过重复写入，只应用到运行入站，`api lsi` 可见用户。
- 真实客户端：B 经 `VLESS + Reality` 到达 origin。
- 热移除：磁盘与运行态同时移除；移除前已建立的连接继续完成，新连接被拒绝（rc=52）。
- 重启后：B 保留，被移除用户不复活。
- 并发热添加：两个用户都进入提交配置和运行入站。
- 权限回归：服务账号读不到配置时 doctor rc=1，repair 恢复 `0640` 与 `xray` 组，重启后真实客户端可用。
- `doctor --client-probe`：rc=0，`evidenceLevel=REAL_CLIENT_PASS`，`HTTP/1.0 200 OK` 12 字节正文。
- 最终 doctor：健康，rc=0。

## P3-04 真实 VM 边界

- 容器内冷恢复已单独完成（见 `01-security-recovery.md` §4，T04：源容器销毁、目标容器恢复、真实客户端）；
  这证明恢复事务与目标机权限解析，但仍是容器，不是独立 VM。
- 独立 VM 部署/接管：`BLOCKED`。本轮没有可用 VM，未执行，不得用容器结果替代。
- systemd 在真实主机重启后的掉电/重启恢复：`BLOCKED`。
- 真实 VPS 的生产变更：`BLOCKED`（任务书禁止）。
- 发布前必须在独立 VM 至少执行一次：安装 → 热加/热删 → repair → 重启 → doctor `--client-probe` → 备份/恢复，并保留与本次相同粒度的证据。

## P3 验收结论

- 代码层：P3-01/P3-02 已实现并有单元测试；P3-03 在本 SHA 上 raw/ws/grpc/xhttp 四条传输各 62/62 真实通过。
- 探针层：Reality 四条 Xray 传输的 `--client-probe` 均为 `REAL_CLIENT_PASS`；relay 以真实 HTTP 穿过 Nginx Stream 达到 `REAL_CLIENT_PASS`，并在 limitation 中明确它不是 VLESS 会话。
- 证据层：`LOCAL_RUN`（容器内真实 systemd/Xray/nginx/TLS origin）已具备；真实 CI 为 `CI_RUN` PASS（PR #182 @ `4f12543e`）；独立 VM 与生产 VPS 仍为 `BLOCKED`。
- 发布结论：P3 不改变 `NO-GO` 的最终发布判断；真实 CI 已复跑通过，仍需完成 P3-04 的真实 VM 验收与 P2 的 OPS 全量双端证据。
