# F18-QR 规格：`xray share --qr` 终端二维码

状态：待批准（批准前不改生产代码、不跑正式两次容器、不提交）
证据等级：CONTAINER_VERIFIED（固定 systemd/e2e 镜像内真实 `qrencode` 4.1.1、
真实 Go 二进制、真实生成配置派生的分享链接；不宣称真机扫码验证）
提交边界：CLI 旗标 + 实现、F18 执行器与证据、三处文档；不新增 Go 依赖、
不改 `install.sh`、不改 `scripts/`、不 push/tag/merge、不接触真实 VPS。

## 1. 目标

补齐 F18「分享链接 / 二维码 / Clash」中唯一缺口：给 `idleleo xray share`
增加 `--qr`，在文本输出中打印当前分享链接的终端二维码，行为与 Bash 的
`qrencode -o - -t utf8` 输出逐字节一致，同时保持默认输出与 JSON 输出不变。

## 2. 已核实事实（2026-11-17）

| # | 事实 | 实测值 / 证据 |
|---|---|---|
| 1 | 当前 `--qr` 行为 | `idleleo xray share ... --qr` → `rc=2`，`unknown flag: --qr`（F18_test.py S8 既有断言） |
| 2 | Bash 二维码调用 | `install.sh` 共 10 处 `echo -n "${link}" \| qrencode -o - -t utf8`：reality、reality-v6、ws、ws-v6、grpc、grpc-v6、xhttp、xhttp-v6、用户链接、用户链接-v6 |
| 3 | Bash 依赖声明 | `install.sh:2754` `pkg_install "bc,curl,dbus,git,jq,lsof,python3,qrencode"`，qrencode 是既有外部依赖 |
| 4 | 仓库依赖模型 | `vendor/` 已提交；本环境无外网 DNS，`proxy.golang.org` 与 `goproxy.cn` 均 `i/o timeout`，无法新增第三方 Go QR 库 |
| 5 | 可用 qrencode | `idleleo-e2e@sha256:3012978e...` 内 `/usr/bin/qrencode` = **4.1.1**；`idleleo-realroot@sha256:d985e8ed...` 无 qrencode |
| 6 | 真实输出形态 | 样例 reality URI → `rc=0`，29 行、4446 字节，末字节 `0x0a`；暗模块为两个 `█`(U+2588)，静区 4 模块 |
| 7 | 旗标白名单 | `internal/cli/flags.go:111` `"xray share": specOf([]string{"path","inbound","public-port","host","public-security","user"})`；未知旗标统一 `rc=2` |
| 8 | 帮助文案 | 中文 `internal/i18n/i18n.go:43`、英文 `:145` 的 `xray share` 行 |
| 9 | 分享链接来源 | `xraycfg.ShareConfig` 返回 `info.ShareURI`，与文本 `share: <uri>` 同一值；JSON 模式输出 `ShareInfo` |
| 10 | 现有测试面 | `F18_test.py` 172/172（两次）；S8 断言 `--qr` 未知、输出无 `█`、不提 `qrencode`；S9 静态比对 10 处 qrencode 调用 |

## 3. 设计决定

1. **调用真实 `qrencode`，不内嵌 QR 编码器。** 与 Bash 使用同一二进制、同一参数
   （`-o - -t utf8`，stdin 为 URI），输出逐字节一致；不引入新依赖、不需要改
   `go.mod`/`vendor/`。运行时缺失 qrencode 时给出可执行安装命令。
2. **显式 `--qr`，默认输出不变。** 现有文本/`--json` 消费者不受影响；Bash 是
   「每链接自动打印」，Go 用显式旗标，登记为 approved-difference。
3. **`--qr` 与 `--json` 互斥。** 组合返回 `rc=2`（usage），不把二维码塞进 JSON。
4. **全有或全无。** 先 `LookPath` + 先把二维码渲染到内存，成功后才打印
   `mode=...`/`share:` 等任何输出；缺二进制或 `qrencode` 失败 → `rc=1`、stdout 为空。
5. **输出格式**：`share: <uri>` 之后新增一行 `qr:`，紧跟 `qrencode` 原始 UTF-8 矩阵
   （矩阵自身已带末尾换行），不再重复打印链接。

### 3.1 必须登记的差异

| 契约 | Go | Bash | 状态 |
|---|---|---|---|
| 二维码触发 | `share --qr` 显式开启 | 每个链接自动打印 | `approved-difference` |
| 二维码内容与编码 | 同一 URI、同一 `qrencode -o - -t utf8` | 同左 | `aligned` |
| `--json` 模式 | 不输出二维码；`--json --qr` rc=2 | 无 JSON 模式 | `approved-difference` |
| 缺 qrencode | rc=1 + 三平台安装提示、零输出 | 安装阶段已由包管理器装入 | `approved-difference` |

## 4. 测试计划（S1–S5）

- **S1 默认不变**：不加 `--qr` 时 rc=0、输出无 `qr:`、无 `█`、不含 `qrencode`；
  `--json` 仍只输出 `ShareInfo` JSON。
- **S2 `--qr` 正常路径**：rc=0；`share:` 后出现 `qr:`；`qr:` 之后的字节与直接执行
  `printf %s "$uri" | qrencode -o - -t utf8` 的 stdout 完全一致；URI 与 `share:` 行一致。
- **S3 守卫**：`--json --qr` rc=2 且不打印矩阵；`PATH` 指向空目录时 `--qr` rc=1、
  stdout 为空、stderr 含 `qrencode` 与安装提示；未知旗标仍 rc=2。
- **S4 Bash 基线**：真实 qrencode 4.1.1 与同一 URI 的字节对比；`install.sh` 的
  10 处调用点保持不变；记录 qrencode 版本/sha 与 `--qr` 输出 sha。
- **S5 回归**：F18 既有 172 条断言（URI/Clash/越界/ambiguous）全部保持；`go.mod`、
  `go.sum`、`vendor/` 无变化。

## 5. 证据与运行命令

```bash
docker run --rm -v "$PWD":/src -w /src -v /tmp/f18out:/out -e CGO_ENABLED=0 \
  golang:1.27.4 go build -trimpath -o /out/idleleo ./cmd/idleleo

docker run --rm -v "$PWD":/work/repo:ro -v /tmp/f18out:/work/bin:ro \
  -v "$PWD/tests/go-parity/evidence/f18-qr-2026-11-17:/work/evidence" \
  -e IDLELEO_PREVIEW_EVIDENCE=/work/evidence \
  idleleo-e2e@sha256:3012978e415b9bec250f738ddc7246a64837896fbeb52ed27571d8f3b8b24002 \
  python3 -I /work/repo/tests/go-parity/parity/features/F18_test.py \
    --go-bin /work/bin/idleleo --bash-repo /work/repo
```

证据目录：`meta.txt`（镜像 digest、qrencode 4.1.1、Go 二进制 sha、两次 passed/failed）、
`commands.log`、`observed.json`、`baseline-compare.json`、`qr-compare.json`
（Go `--qr` 矩阵与直接 qrencode 的 sha）、`run1/run2-fixture-result.json`。

## 6. 容器无法覆盖的缺口（不伪造）

1. 未用真实手机/解码器扫描，仅验证「与 qrencode 输出逐字节一致」和块字符结构。
2. 终端字体/宽度导致的显示折行未验证。
3. 宿主 qrencode 版本差异（容器 4.1.1，用户机器未覆盖）。
4. Bash 在安装菜单中自动打印全部链接的行为未执行（只做静态调用点与同一
   qrencode 真值对比）。

## 7. 提交边界

1. `feat(xray): add share --qr terminal QR code`：`internal/cli/xray.go`、
   `internal/cli/flags.go`、`internal/i18n/i18n.go`、`F18_test.py`、证据目录、
   `FUNCTION_PARITY.md` F18 行、`docs/plans/p2/tasks.md` F18 条目。
2. `docs(parity): mark F18 QR checklist complete`：仅本 spec 的 tasks/checklist 勾选。
3. 不提交：`check_evidence_hygiene.py` 的遗留修改、`f02/f07-executor`、` 2` 后缀文件。
