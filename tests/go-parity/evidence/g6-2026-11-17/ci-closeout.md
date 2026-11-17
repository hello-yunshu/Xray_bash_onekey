# G-6 CI 结清步骤（本地已核到同一阻塞点）

本地与 CI 使用同一个闸门脚本 `tests/go-parity/parity/scripts/check_release_gate.py`，判定顺序固定：

1. 账本完整性（28 个 ID 唯一）
2. `pending` / `missing executable feature tests`
3. 必填参数（`--bash-repo`、`--native-go-dir`、`--require-package`）
4. CI 身份（`GITHUB_ACTIONS=true` 且 `GITHUB_SHA` 等于签出提交）
5. L0 原生源码校验 + 28 个夹具逐个执行（各 240s）

## 1. 本地实测（同口径）

| 运行 | 文件 | 结果 |
|---|---|---|
| 无参数 | [release-gate.out](release-gate.out) | `RELEASE BLOCKED: pending 28; missing ... 0`，rc=2 |
| 与工作流相同参数 | [release-gate-with-args.out](release-gate-with-args.out) | 同上输出，rc=2（**先于**参数/CI 身份检查） |

因此本地与 CI 的**首个阻塞点一致**：28 项账本状态仍为 `PENDING_GO_IMPLEMENTATION`。
本地与 CI 唯一的差异在第 4 步：本机未设置 `GITHUB_ACTIONS`/`GITHUB_SHA`，即使账本清零也会返回 rc=3
（`only a checked CI runner may issue a release qualification result`）。本地无法、也不应绕过该检查。

## 2. CI 结清需要依次完成

1. **账本签收（人工决策，不可预置为绿）**
   - 对 F01–F28 逐项在真实 VPS/VM 上验收，或在评审中批准安全差异；
   - 只把有终态证据的项改成 `VERIFIED_GO_PARITY`，批准差异的项改成 `APPROVED_SAFE_DIVERGENCE`；
   - 禁止为了得到 rc=0 提前改状态（本仓库 G-6 明确不做）。
2. **补齐 6 项证据留档**：`F01`、`F05`、`F11`、`F26`、`F27`、`F28` 目前只有 preview 夹具输出，没有
   `tests/go-parity/evidence/f<NN>-*` 目录；需在容器内重跑夹具并把 `IDLELEO_PREVIEW_EVIDENCE` 的产物入库。
3. **触发方式**：`workflow_dispatch` 仍只对默认分支可见，但工作流已补
   `push: develop/go-native` 与 `pull_request` 触发器（与 preview 工作流一致），
   因此在未合入默认分支前也能由分支推送/评审实际运行；`workflow_call` 保持不变。
   仍然不能发布：`permissions: contents: read`，且无任何 tag/release 步骤。
4. **Runner 能力**：工作流现在自行安装 `nginx`、`libnginx-mod-stream`、`curl`、`jq`，
   并把 Xray 二进制装到 `/opt/xray/xray`；夹具需要 root（写 systemd unit 与
   `/etc/idleleo`），因此闸门以 `sudo -E env ... python3` 运行，并预先为两个
   checkout 写入 `safe.directory` 以避开 root 下的 git dubious-ownership。
5. **身份一致**：`sudo` 会重置部分环境，工作流显式透传
   `GITHUB_ACTIONS`/`GITHUB_SHA`（以及 `GOPROXY`/`GOTOOLCHAIN`/`GOFLAGS`）；
   `GITHUB_SHA` 必须等于 `--native-go-dir` 签出的提交，否则第 4 步以 rc=3 失败
   （这是防止用未评审源码出结论的设计，不是可绕过的环境问题）。

## 3. 完成判据

- 第 1–2 步完成后本地无参数运行应返回 rc=3（参数/CI 身份），而不是 rc=2；
- 在受保护 CI 中按第 3–5 步运行工作流，输出
  `RELEASE FUNCTIONAL QUALIFICATION PASS — still requires independent VM/systemd, multi-distro and protected publishing gate` 才是通过；
- 该 PASS 仍不构成发布许可，发布仍需独立 VM/systemd、多发行版与受保护发布闸门。

## 4. 工作流修复（2026-11-17）

`.github/workflows/go-release-qualification.yml` 修掉四处会在 ledger 签收后仍挡住 CI 的机制问题：

| 问题 | 修复 |
|---|---|
| 迁移分支上 `workflow_dispatch` 不可见，`gh workflow run` 404 | 补 `push: develop/go-native` 与 `pull_request` 触发 |
| 宿主机没有 nginx / Xray，夹具必然 RED | 新增运行时前置步骤（nginx、stream 模块、curl、jq、`/opt/xray/xray`） |
| 夹具以非 root 运行，无法写 unit 与 `/etc/idleleo` | 闸门改为 `sudo -E env ... python3`，并写入两个 checkout 的 `safe.directory` |
| 90 分钟 job 超时 < 28×240s 最坏耗时 | 提升到 180 分钟，并加同 ref 并发取消 |
| `sudo` 可能丢 `GITHUB_SHA`，导致闸门 rc=3 | 显式透传 `GITHUB_ACTIONS`/`GITHUB_SHA`/`GOPROXY`/`GOTOOLCHAIN`/`GOFLAGS` |

另加 `IDLELEO_PREVIEW_EVIDENCE` 与 artifact 上传，RED 时可直接取到夹具证据。

验证范围：YAML 解析通过，触发器/步骤/超时静态核对；本地闸门仍为
`pending 28`、rc=2（[release-gate.out](release-gate.out)），与 CI 首阻塞点一致。
`actionlint .github/workflows/go-release-qualification.yml` 返回 0。工作流关键项断言
（触发器、root、`GITHUB_SHA` 透传、`--require-package`、180 分钟）由本地脚本校验通过。
**未** 在 GitHub 上实际运行（本次未 push）；未改 `check_release_gate.py`，判定规则不变。
