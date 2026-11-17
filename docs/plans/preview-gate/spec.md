# Preview 通道与首批 6 项夹具 — 执行规格（方案 B，已按拍板收紧）

状态：按用户“方案 B 开工”的直接指令执行，不再提确认问题。
基线：`fix/go-parity-install-acme-closeout`，HEAD `cb792ce`，不 push。

## 1. 只做这些事

1. 新增 `tests/go-parity/parity/scripts/check_preview_gate.py`。
2. 新增 `tests/go-parity/parity/cases/preview_contract.json`，只列已有夹具的子集。
3. 新增 `tests/go-parity/parity/features/fixture_support.py` + 6 个夹具：F01、F05、F11、F26、F27、F28。
4. 新增容器启动脚本与 preview workflow 模板。
5. 最后单独提交台账对齐。

不做：不改 `check_release_gate.py`、不改 `feature_contracts.json`、不碰 28 项签收、不伪造 F02/F04/F12/T3 真机结论。

## 2. 与发布闸门的唯一差异

| 项 | `check_release_gate.py` | `check_preview_gate.py` |
|---|---|---|
| 契约 | `feature_contracts.json` 28 项 | `preview_contract.json` 子集 |
| 状态门槛 | 全部 VERIFIED/APPROVED | 只要求非“已验证”，夹具真实通过 |
| 证据来源 | 仅受保护 CI（GITHUB_ACTIONS + SHA） | 容器 `--container-evidence` 或 GH Actions |
| Go 来源 | 从干净 Git 源码构建 | 接受 `--go-bin`，记录 SHA/架构（预览不声称可发布） |
| Bash 来源 | 强制 pinned commit | 接受 `--bash-repo`，记录 `install.sh` SHA |
| 输出 | RELEASE ... | 首行 `PREVIEW — NOT FOR RELEASE` |
| 权限 | 发布资格 | 无任何发布权限 |

夹具执行那一行与发布闸门完全一致：

```python
subprocess.run(
    [sys.executable, "-I", fixture, "--go-bin", go_bin, "--bash-repo", bash_repo],
    cwd=tmp, timeout=240,
    env={**os.environ, "IDLELEO_PREVIEW_EVIDENCE": str(evidence / fid)},
)
```

## 3. 预览闸门的判定顺序

1. 打印 `PREVIEW — NOT FOR RELEASE`。
2. 读 `preview_contract.json`：ID 唯一、属于 F01–F28、`fixture` 文件必须存在。
3. 读 `feature_contracts.json`：必须仍是 28 项且全部 `PENDING_GO_IMPLEMENTATION`；否则 RED。
4. 运行前记录 `check_release_gate.py` 与 `feature_contracts.json` 的 SHA-256；运行结束再算一次，若中途被改则 RED。**不写死 hash**，避免以后正常维护被误伤。
5. 证据来源：`--container-evidence <id>` 或 `GITHUB_ACTIONS=true` + `GITHUB_SHA`；都没有则 RED。
6. `GITHUB_REF_TYPE=tag` 或 `GITHUB_EVENT_NAME=release` → RED。
7. `--go-bin` 必须存在、ELF magic、`e_machine` 与当前机器匹配。
8. 逐项执行夹具；每项打印 `Fxx PASS/FAIL`、耗时、`evidence=<dir>`。
9. 写 `preview_qualification.json`：banner、`releaseAuthority:false`、证据等级、go-bin sha、install.sh sha、每项结果。
10. 结尾固定打印 `PREVIEW FUNCTIONAL RESULT — release authority: NONE; feature_contracts.json unchanged (28 PENDING)`。

参数：`--go-bin`、`--bash-repo`、`--container-evidence`、`--evidence`、`--only`。
exit：全绿 0；缺夹具/夹具失败/契约被改 2；证据源缺失 3。

## 4. 预览契约

```json
{
  "schema_version": 1,
  "channel": "preview",
  "banner": "PREVIEW — NOT FOR RELEASE",
  "release_authority": false,
  "status_legend": ["PENDING_PREVIEW", "EXTERNAL_RESOURCE_REQUIRED", "EXTERNAL_RESOURCE_PARTIAL"],
  "scope_note": "通过不改变 release 账本，不授权发布；缺夹具即 RED。",
  "features": [
    {"id":"F01","fixture":"F01_test.py","evidence_level":"CONTAINER_VERIFIED",
     "status":"PENDING_PREVIEW","requires":["root","systemd","xray","network"],
     "scope":"Reality fresh install + real handshake",
     "not_verified":["真实 VPS","reality-nginx"]}
  ]
}
```

`status` 固定 `PENDING_PREVIEW`，闸门不回写。F02/F04/F12 以后追加时用 `EXTERNAL_RESOURCE_*`，不阻塞本批。

6 项范围：

| ID | 夹具断言 | 明确不验证 |
|---|---|---|
| F01 | 写前拒绝、Reality 安装、systemd active/enabled、User=xray、`xray -test`、真实客户端握手取回 HTTP | 真实 VPS、reality-nginx |
| F05 | relay 片段、`nginx -t`、真实 TCP 字节回显、不创建 Xray/UUID/证书 | 真实 VPS、逐字段差分 |
| F11 | status/restart/stop/start/logs、非法 unit、sandbox root 拒绝 | 真实 VPS、跨发行版 |
| F26 | `legacy-xtls-removed`、blocked、审计只读、prepare 拒绝且无 journal | 真实旧机器 |
| F27 | version/help 退出码、unknown → 2、sandbox uninstall/purge 语义 | backup/restore（未实现） |
| F28 | `show/status/share` 离线只读、字段断言、零写入 | 与 Bash 逐字段差分 |

## 5. 夹具模板（`fixture_support.py`）

- 标准库 only；`Fixture(fid)` 解析 `--go-bin`、`--bash-repo`、可选 `--xray-bin`。
- `run(cmd, timeout=60)`：真实子进程，记录命令/rc/stdout/stderr 到 `commands.log`；超时判 FAIL。
- `ok/bad/check`：逐条 `PASS/FAIL`；异常转 traceback + exit 1。
- `need_root/need_systemd/need_tool/xray_bin`：前置不满足打印 `UNSUPPORTED_ENVIRONMENT` 并 exit 2，不算通过。
- `finish()`：写 `fixture-result.json`；内部预算 200s，给闸门 240s 留余量。
- F01 的 origin 默认 `http://example.com/`，可用 `PREVIEW_ORIGIN_URL` 覆盖；3 次重试，每次 20s。

## 6. 六个夹具的关键断言

**F01**：清场 → 非法 serverName 安装 exit 2 且零落盘 → 正式安装 exit 0，JSON `mode/transport/validatorExit/serviceActive/serviceEnabled/configSha256` → systemctl、unit `User=xray`、进程属主、`xray -test` → `xray share` 生成客户端 → SOCKS 取 HTTP 200 且 body>0 → 清理。

**F05**：本地 TCP echo:19001 → `xray relay --target 127.0.0.1:19001 --listen-port 19443` → 片段含 listen/proxy_pass → 完整 stream 配置过 `nginx -t` → 启 nginx 发字节原样回显 → 断言未创建 `/etc/idleleo` 下 Xray/UUID/证书。

**F11**：真实 `xray.service` 探针（启动写 journal）→ status active → restart 后启动计数 +1 → stop inactive → start active → logs 含标记 → `sshd` exit 2 → `--root <sandbox>` status exit 2。

**F26**：临时 legacy 根（sandbox marker、install.sh、`tls=XTLS` 的 install_config、relay-stream.conf、entry 软链）→ 全树哈希 → `bridge audit --json` 得 `blocked` + `legacy-xtls-removed` → 哈希不变 → `bridge prepare --container` 非 0 且无 `var/lib/idleleo/bridge/journal.json`。

**F27**：`--version` 含 `0.2.0-phase04`；`--help` 与 `xray generate --help` exit 0 且不生成文件；未知命令 exit 2；`xray user add` 无 `--sandbox` exit 2；sandbox `uninstall --container` 保配置、删 binary/unit/metadata；再装后 `--purge` 删配置。

**F28**：临时根写 info 文件与 reality config → 全树哈希 → `show --json` 解析 info/inbounds/authority → `status --json` 不触网 → `xray share` 含 `security=reality/pbk/sid` → 哈希不变。

## 7. 容器与 workflow

`scripts/run_preview_container.sh`：
- `golang:1.24` 容器从当前工作树构建 linux/arm64|amd64 `idleleo`；
- 复用 `tests/go-parity/phase04/Dockerfile`（systemd + nginx + python3 + jq）；
- `ensure_xray_bin` 准备匹配架构 Xray；
- `--privileged --cgroupns=host` 启动，挂二进制、xray、整仓只读、可写 evidence；
- 容器内执行 `check_preview_gate.py --container-evidence "$IMAGE_ID"`，退出码透传。

`ci/go-preview-qualification.yml`：
- `permissions: contents: read`；只监听 `workflow_call` / `workflow_dispatch` / `pull_request`；
- 显式安装 nginx、下载 xray、构建 `./cmd/idleleo`，再跑闸门；
- 仅作模板留在 `ci/`，不复制到 `.github/workflows/`，无 tag/release/publish。

## 8. 验证

1. 容器全量：期望 6/6 PASS，首行/结尾 banner 正确。
2. 负向：缺夹具 RED；运行中改 `check_release_gate.py` RED；把账本任一项改 VERIFIED RED；破坏 F05 nginx RED。
3. `git diff --stat` 证明两个禁改文件零改动。

## 9. 提交（均不 push）

1. `preview(gate): add preview channel and F01 fixture`（契约、闸门、模板、F01、launcher）
2. `preview(fixtures): F05 relay byte forwarding`
3. `preview(fixtures): F11 service lifecycle`
4. `preview(fixtures): F26 XTLS-only refusal`
5. `preview(fixtures): F27 legacy CLI exit codes and uninstall`
6. `preview(fixtures): F28 offline status/show/share`
7. `docs(status): align parity ledgers with preview channel`（单独提交）

每完成一项立即汇报；第一项附模板结构、断言方式、超时处理、证据路径。
