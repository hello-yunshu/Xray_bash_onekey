# F03 执行器规格：无 TLS 后端回环监听

状态：待批准（批准前不写测试、不跑容器、不提交）
证据等级：CONTAINER_VERIFIED（固定 digest 容器内真实执行 Go 二进制与真实 `xray -test`；不接触真实 VPS、不使用公网 CA）
提交边界：仅新增执行器、证据与三处文档计数；`install.sh` 不改；生产 Go 代码只在执行器暴露真实缺陷时最小修复并附单测。

## 1. 目标

为 `feature_contracts.json` 的 F03（`无TLS后端回环监听`，P0）建立真实夹具
`tests/go-parity/parity/features/F03_test.py`，覆盖：

1. `xray generate --mode none` 的默认语义：入站 `security=none`、默认 `listen=127.0.0.1`、
   单传输端口 `10086`、无 Nginx 主配置与片段、分享 URI/Clash 走明文；
2. 回环守卫：显式非回环 `--listen` 未加 `--allow-non-loopback` 时 `rc=2` 且零写盘；
   加旗标后按值生成并仍由真实 `xray -test` 接受；
3. ws / gRPC / xHTTP / `ws+grpc+xhttp` 四种形态在 none 模式下的入站、端口池、端口冲突与
   三个入站监听地址；
4. `--public-port` 在无 Nginx 模式下的实际语义（只影响客户端视图）；
5. 与固定 Bash 基线（`transport_only` 分支 + `config/vless_tls.json` 模板 + 真实执行
   `modify_listen_address`/`modify_inbound_port`/`add_*_inbound`）的结构化对比，
   差异逐条写入 `baseline-compare.json`，不粉饰为对齐；
6. 明确登记本轮无法覆盖或不应伪造的缺口。

## 2. 已核实事实（实现依据）

| 事实 | 位置 |
|---|---|
| `--mode none` 的传输白名单是 ws/grpc/xhttp/`ws+grpc+xhttp`；缺省传输为 ws；raw/未知值报错 | `internal/xraycfg/xraycfg.go` 的 `Generate`（ModeTLS/ModeNone 分支） |
| none 模式缺省端口为 `10086`；`--port` 直接成为入站端口（与 TLS 的端口池语义不同） | 同上 |
| none 模式缺省 `listen=127.0.0.1`；非回环地址必须显式 `--allow-non-loopback`，否则返回错误（CLI 映射为 exit 2） | 同上 `Generate` 的 listen 校验与 `isLoopback`；`internal/cli/xray.go` 的 `specFromFlags`/`xrayGenerate` |
| 显式回环族 `::1` 被接受；`2001:db8::1` 默认被拒、加旗标后接受 | `internal/xraycfg/xraycfg_test.go` 的 `TestA1BindIPv4IPv6` |
| none 模式不生成 Nginx：`buildNginx` 只对 `ModeTLS` 返回内容，`xrayGenerate` 也只在非空时写 `--nginx-out` | `internal/xraycfg/xraycfg.go` 的 `buildNginx`；`internal/cli/xray.go` |
| 分享 URI 的 host 对 none 模式取 `spec.Listen`，端口取 `PublicPort`（缺省等于 `Port`），security=`none` | `internal/xraycfg/xraycfg.go` 的 `Generate`（`shareHost`）与 `buildShareURI`/`securityName` |
| Clash 片段对 none 模式不写 `tls`/`servername`；xHTTP 仍返回空并带 `clash-xhttp-unsupported` | 同上 `buildClash` |
| 多传输时主入站用 `--port`，附加传输从 10000–10999（xHTTP 11000–11999）升序选空闲端口；显式端口需互斥、不得等于公开端口、越界报错 | 同上 `portPicker`/`buildInboundDefs` |
| 当前 `extraListenFor` 对 none 模式返回固定 `127.0.0.1`：显式非回环时只有主入站跟随 `--listen` | 同上 `extraListenFor` |
| Bash `transport_only` 分支设 `tls_mode="None"`，从 `config/vless_tls.json` 模板重建，先用 `0.0.0.0` 追加传输，再统一由 `modify_listen_address` 改写 ws/gRPC/xHTTP 三个 tag | `install.sh` 的 `apply_install_profile`、`xray_conf_add`（None 分支） |
| Bash 的 none 缺省监听是 `127.0.0.1`（`ws_backend_listen_default`），交互式允许输入其它合法地址；`is_valid_listen_address` 校验 IPv4/IPv6，非法值在 `resolve_ws_backend_listen_addr` 回退 `127.0.0.1` | `install.sh` 的 `ws_backend_listen_default`/`ws_listen_address_choose`/`is_valid_listen_address`/`resolve_ws_backend_listen_addr` |
| Bash 的 none 入站端口取 `xport/gport/xhttpport`，与 `port` 无关；自动值为 10000–10999（xHTTP 11000–11999）随机 | `install.sh` 的 `modify_inbound_port`（非 Reality/TLS 分支）、`ws_inbound_port_set`/`grpc_inbound_port_set`/`xhttp_inbound_port_set` |
| Bash 的 none 分享链接直接用后端端口（`ws_port`/`grpc_port`/`xhttp_port`），没有公开端口概念 | `install.sh` 的 `generate_vless_link`（`ws`/`grpc`/`xhttp` 分支） |

## 3. 设计决定

- **默认不改生产代码。** 执行器是证据补齐。唯一已知的候选真实缺陷是「none 多传输显式非回环时，
  附加传输仍固定 127.0.0.1」（Bash 会统一改写三个入站）。若 S3 实测确认，则在 T6 做最小修复
  （`extraListenFor` 让 `ModeNone` 返回 `spec.Listen`）并补单测；该修复在提交说明中单列。
- 所有断言基于实际产物字段；tag、片段名、warning 从产物读取后断言结构不变量，并把实际值写入
  `observed.json`。不写死未核实的数值。
- 拒绝场景统一断言：`rc == 2`、`--out` 不存在或逐字节不变、`--nginx-out`/`--fragments-out` 无新增。
- none 模式必须断言「没有 Nginx 产物」：`--nginx-out` 不落盘、`--fragments-out` 不创建目录。
- Bash 基线既做静态断言也做真实执行：从固定 `install.sh` 按函数边界提取
  `ws_backend_listen_default`、`is_valid_listen_address`、`resolve_ws_backend_listen_addr`、
  `modify_listen_address`、`modify_inbound_port`、`add_ws_inbound`、`add_grpc_inbound`、
  `add_xhttp_inbound`、`modify_path`、`modify_email_address`，在临时目录对模板副本真实执行；
  无法脱离 TTY/网络的函数（`ws_listen_address_choose`、`transport_choose`、`apply_install_profile`、
  `install_xray_ws_only`）只做静态断言，并在 `baseline-compare.json` 标 `mode: static` 与原因。
- 固定测试输入：domain 不使用（none 不需要）；路径 `/ray/`、`/xhttp/`，service `idleleo-grpc`，
  钉选端口 `12086/12443/12444/12445`；不写入真实凭据。

### 3.1 必须登记的差异（候选，最终以实测为准写入 `baseline-compare.json`）

| 契约 | Go 行为 | Bash 行为 | 预期状态 |
|---|---|---|---|
| 缺省监听地址 | `127.0.0.1` | `127.0.0.1` | `aligned` |
| 非回环确认 | 未加 `--allow-non-loopback` 直接拒绝 | 交互式允许任意合法地址，仅告警 | `divergent-guard`（Go 更严格） |
| 附加传输监听地址 | 显式非回环时当前仅主入站跟随 | 三个入站统一改写 | 实测后修 Go，或记 `divergent-listen-propagation` |
| 监听地址格式 | 只判回环，不校验格式（带旗标可写出非法值） | `is_valid_listen_address` 校验，非法回退 127.0.0.1 | `gap: listen format not validated` |
| 缺省入站端口 | `10086` | 随机 10000–10999（xHTTP 11000–11999） | `divergent-default-port` |
| 公开端口 | `--public-port` 只改分享/Clash 端口 | none 模式无公开端口，链接用后端端口 | `divergent-flag-semantics` |
| 协议/标签拼写 | 小写 `vless` + Go tag | `VLESS` + `VLESS-ws-in` 等 | `divergent-naming` |
| 组合传输命名 | `ws+grpc+xhttp` | 菜单 5 `wsgRPCxhttp` | `aligned-semantics` |
| xHTTP Clash | 空 + `clash-xhttp-unsupported` | 生成 xHTTP 链接（Clash 渲染未执行） | `gap` |
| 真实 none 安装 | 仅生成配置 | 下载模板、装服务、启动 | `gap: install path not executed in container` |

## 4. 精确测试计划

文件：`tests/go-parity/parity/features/F03_test.py`（新建，复用 `run_fixture`）。

### S1 默认 none + ws
- `xray generate --mode none --out <json> --nginx-out <conf> --fragments-out <dir> --uuid ... --json`。
- 断言：`rc=0`；配置文件 `0600`；单入站 `protocol=vless`、`network=ws`、`security=none`、
  `listen=127.0.0.1`、`port=10086`、`wsSettings.path=/ray/`、email 非空；
  routing 规则指向该 tag；JSON payload `mode=none`、`transport=ws`、`port=10086`、`publicPort=10086`、
  `listen=127.0.0.1`；分享 URI `security=none&type=ws&path=/ray/&host=127.0.0.1` 且端口 10086；
  Clash 有 ws 代理、无 `tls:`/`servername:`；`--nginx-out` 不存在、`--fragments-out` 不存在；
  真实 `xray -test` `rc=0`。

### S2 回环守卫
- `--listen 0.0.0.0`：`rc=2`，stderr 含 `requires explicit confirmation`，零写盘。
- `--listen 0.0.0.0 --allow-non-loopback`：`rc=0`，入站与分享 host 均为 `0.0.0.0`，`xray -test` 通过。
- `--listen ::1`：`rc=0`，入站 `::1`，分享 authority 为 `@[::1]:10086`，`xray -test` 通过。
- `--listen 2001:db8::1`：默认 `rc=2`；加旗标后 `rc=0` 且 `xray -test` 通过。
- 缺口登记：`--listen not-an-ip --allow-non-loopback` 实测被接受，生成的配置由 `xray -test`
  拒绝；写入 `baseline-compare.json` 的 `gap: listen format not validated`（不据此改生产代码）。

### S3 四种传输形态
- gRPC：`network=grpc`、`grpcSettings.serviceName=idleleo-grpc`、`multiMode=true`、
  `idle_timeout=20`、`listen=127.0.0.1`；分享 `type=grpc&serviceName=`；`xray -test`。
- xHTTP：`xhttpSettings.path=/xhttp/`、`mode=auto`；分享 `type=xhttp&path=/xhttp/`；
  payload 无 Clash 且 warning 含 `clash-xhttp-unsupported`；`xray -test`。
- multi 钉选：`--port 12086 --ws-port 12443 --grpc-port 12444 --xhttp-port 12445`
  → 三个入站端口精确匹配、`listen` 全为 `127.0.0.1`、routing 三个 tag、warning `multi-transport`；
  `xray -test`。
- multi 自动：不传 `--*-port` → ws 在 10000–10999、grpc 在 10000–10999、xhttp 在 11000–11999，
  三者互不相同且不等于 12086。
- multi 非回环：`--listen 10.10.0.5 --allow-non-loopback` → **三个入站**都应为 `10.10.0.5`
  （与 Bash 对齐）；若实测仍为 127.0.0.1，记录 `divergent-listen-propagation` 并在 T6 修复。
- 冲突：`--grpc-port` 等于 `--ws-port`、任一端口等于 `--port`/`--public-port`、端口越界
  → `rc=2` 零写盘。

### S4 公开端口语义
- `--public-port 8443`：payload `publicPort=8443`、分享/Clash 端口 8443、配置入站端口仍 10086、
  无 Nginx 产物；`xray -test` 通过。
- `baseline-compare.json` 记录 none 模式无公开端口概念（Bash 链接用后端端口）。

### S5 覆盖保护与参数边界
- `--out` 已存在且无 `--force` → `rc=2` 且原文件逐字节不变；`--force` 覆盖成功。
- `--mode none --transport raw` / 未知 transport → `rc=2` 零写盘。
- `--transport grpc` 大小写（`GRPC`）按实测记录（预期接受并小写化）。

### S6 Bash 基线
- 静态：`apply_install_profile` 的 `transport_only` 分支设 `tls_mode="None"`；
  `ws_backend_listen_default` 返回 `127.0.0.1`；`is_valid_listen_address` 覆盖 IPv4/IPv6/非法值；
  `modify_listen_address` 对 None 取 `resolve_ws_backend_listen_addr` 并改写三个 tag；
  `modify_inbound_port` 非 TLS/Reality 分支取 `xport/gport/xhttpport`；
  `add_*_inbound` 缺省 listen `127.0.0.1`；端口池 10000–10999 / 11000–11999。
- 真实执行：对 `config/vless_tls.json` 副本依次执行 `add_ws_inbound`/`add_grpc_inbound`/
  `add_xhttp_inbound`（与 Go 相同的 path/service/端口）→ `modify_listen_address`
  （分别用默认与 `ws_backend_listen_addr=10.10.0.5`）→ `modify_inbound_port` → `modify_path`；
  产出 `bash-config.json`，并与 Go 三份配置做字段级对比写入 `bash-result.json`。
- Bash 配置也由真实 `xray -test` 校验（模板取自 `config/vless_tls.json`）。
- `baseline-compare.json` 覆盖 S1–S5 与 3.1 全部条目；静态无法执行的函数标 `mode: static` 与原因。

## 5. 证据与验证命令

证据目录：`tests/go-parity/evidence/f03-2026-11-17/`

1. `meta.txt`：commit、镜像 digest、`golang:1.27.4` 构建命令、`go_bin_sha256`、两次运行计数。
2. 构建：`docker run --rm -v "$PWD":/src -w /src -v /tmp/f03out:/out -e CGO_ENABLED=0 golang:1.27.4 go build -trimpath -o /out/idleleo ./cmd/idleleo`
3. 容器：固定 `idleleo-preview` digest，绑定二进制目录、仓库、证据目录与缓存真实 xray；
   `python3 -I` 连跑两次：
   `F03_test.py --go-bin /work/bin/idleleo --bash-repo /work/repo --xray-bin /work/xray`。
4. 卫生检查：`check_evidence_hygiene.py tests/go-parity/evidence/f03-2026-11-17` 必须 0 findings。
5. 通过标准：两次 `failed=0` 且 `passed` 一致；`observed.json`/`baseline-compare.json`/
   `bash-result.json` 存在；`commands.log` 含真实 argv；`xray -test` 真实退出码落盘。

## 6. 文档与提交

- `docs/go/FUNCTION_PARITY.md` F03 行：执行器覆盖 none 默认/守卫/四形态/公开端口与真实 `xray -test`；
  登记非回环守卫、格式缺口、安装路径缺口。
- `docs/plans/p2/tasks.md` G-3：19 → 20，剩余 8（F04/F09/F10/F13/F17/F20/F21/F24）。
- `tests/go-parity/parity/features/README.md`：20 个真实执行器，8 项仍缺。
- 单独提交：`test(parity): add F03 no-tls loopback executor`。
- 不 push、不合并 main、不打 tag/release。

## 7. 明确不做

- 不做真实 `xray install --mode none` 落盘与服务启动（登记为 `gap`）。
- 不启动 Xray 数据面做客户端连通；只用真实 `xray -test` 校验配置。
- 不把 Bash 的 `VLESS` 大写、随机端口、无公开端口等差异改成 Go 行为，也不反过来改测试。
- 不触碰工作区遗留的 `check_evidence_hygiene.py` 修改、` 2` 后缀文件与既有未跟踪内容。
