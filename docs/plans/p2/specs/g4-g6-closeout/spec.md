# G-4 / G-5 / G-6 收尾规格（M8 ACME 双跑、C6 direct TLS、发布验收本地部分）

状态：待实施（Spec Mode，2026-11-17）。
G-4 目标级别 `CONTAINER_VERIFIED`；G-5 目标级别 `CONTAINER_VERIFIED`；G-6 只做可本地验证部分。

硬约束（全部适用）：

- 不 push、不合并 `main`、不打 tag/release、不碰真实 VPS、不使用公网 ACME CA。
- 不修改 `install.sh`；不为换绿改测试；不伪造证据、不空 `exit 0`。
- 不提交遗留文件：`check_evidence_hygiene.py` 的已有修改、带 ` 2` 后缀的文件、
  `docs/plans/p2/specs/f02-executor/`、`docs/plans/p2/specs/f07-executor/`。
- 未在真实 VPS 验收的能力只能记 `CONTAINER_VERIFIED`，不得写 `VERIFIED`。

## 1. 现状

### 1.1 G-4（M8 HARNESS-BLOCKED）

- `tests/e2e-diff/matrix.json` 的 `install[7]`（M8）是 `eligible:false`、`go.verified:false`；
  `go.argv` 写的是 `idleleo xray cert issue ...`，而 `drivers/go_install.sh` 固定执行
  `idleleo xray install "${GO_ARGS[@]}"`，两者拼接后必然失败，因此 M8 从未真正运行。
- `drivers/bash_install.sh` 对 `tls` profile 预置自签证书，走“保留已有证书”分支，
  永远不触发 ACME；且 e2e 镜像内没有 `idleleo`，Bash 的 `acme()` 无法调用
  `idleleo xray cert issue`。
- 仓库已有可复用的 Pebble 方案：`tests/go-parity/acme/run_acme_container.sh` +
  `tests/go-parity/acme/pebble-config.json`。镜像
  `ghcr.io/letsencrypt/pebble:latest` 自带 `/test/certs`，其中 `localhost/cert.pem`
  的 SAN 含 `DNS:pebble`；Pebble 在 `:15000` 管理端口暴露 `/roots/0`。
- `install.sh` 已支持 `IDLELEO_ACME_DIRECTORY` 注入且**禁止修改**；Go 侧
  `idleleo xray cert issue` 已有 `--directory`、`--ca-cert`、`--cert-out`、
  `--key-out`、`--webroot`、`--takeover`、`--force`。
- `xray install` 不做 ACME；M8 的 Go 侧必须“先 cert issue、再 install”，这与 Bash
  在 `install.sh` 内部签发证书是等价的两步。

### 1.2 G-5（C6 direct TLS 不可编辑）

- `internal/xraycfg/edit.go` 的 `editSpecFromRuntime` 对
  `streamSettings.security == "tls"` 返回 `direct TLS configs are not editable`。
- `internal/deploy/edit.go` 的 `EditConfig` 仍按 Nginx 前置模式做 TLS 对校验、
  续期计划与探针，direct TLS 没有 Nginx，走不到这些分支。
- 现有能力：`share.go` 的 `ShareConfig` 已能解析 `security:"tls"` 生成分享链接；
  `deploy/tls.go` 的 `probeLocalTLS` 可复用；`xray config edit` 的 CLI
  （`internal/cli/xrayedit.go`）已支持 `--domain/--cert/--cert-key/--listen/--port`。
- 设计权威仍是 `docs/plans/p2/spec-c6-direct-tls.md`（用户已选择“按 spec 实施 C6”）。

### 1.3 G-6（发布验收）

- `tests/go-parity/parity/scripts/check_release_gate.py` 无参数运行。
- 本地实测：28 个 feature 契约全部存在执行器测试文件，28 行 ledger 全部仍为
  `PENDING`，gate 输出 `RELEASE BLOCKED: pending 28; missing tests 0`，rc=2。
- 用户决定：G-6 只核对 28 行签收、记录本地/CI 同口径与 CI 结清步骤；**禁止**把
  ledger 改成 `VERIFIED_*` 来伪造通过。

## 2. G-4 设计

### 2.1 Pebble sidecar

新增函数（`run_p2_matrix.sh`）：

```text
prepare_pebble_assets()
  docker create ghcr.io/letsencrypt/pebble:latest
  docker cp <cid>:/test/. $WORK/pebble-test/
  docker rm <cid>

start_pebble(sid, net)
  docker run -d --name p2-pebble-$RUN_ID-$sid \
    --network "$net" --network-alias pebble \
    -v $WORK/pebble-test/certs:/test/certs:ro \
    -v $SUITE/../go-parity/acme/pebble-config.json:/conf/pebble-config.json:ro \
    -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_AUTHZREUSE=0 \
    --entrypoint /app ghcr.io/letsencrypt/pebble:latest \
    -config /conf/pebble-config.json -strict

wait_pebble(net)
  起一次性 curl 容器：curl -fsS --cacert /test/certs/pebble.minica.pem \
    https://pebble:14000/dir
  最多 30s；超时将本场景写成 HARNESS-BLOCKED.md 且失败原因可见，不静默跳过。
```

`pebble-config.json` 沿用现有文件（监听 `:14000`、管理 `:15000`、httpPort 5002、
tlsPort 5001）。Pebble 的实际签发根从管理端口取得；`SSL_CERT_FILE` /
`--ca-cert` 只需要信任目录 TLS 的 `pebble.minica.pem`。

### 2.2 容器与两侧驱动接线

1. `start_server()` 增加可选数组 `SERVER_EXTRA_ARGS`（默认空），仅 M8 在调用前置为
   `-v $WORK/pebble-test/certs:/test/certs:ro`，其余场景行为不变。
2. `l4_transports()` 增加 `M8) echo "ws"`。
3. `scenario_job()` 的 case 增加 `M8) profile=tls; bash_arg="-1"; bash_transport=1`；
   建网后 `start_pebble`，两侧跑完清理 pebble 容器。
4. `run_bash_round()` 对 M8 追加：
   `-e SSL_CERT_FILE=/test/certs/pebble.minica.pem`、
   `-e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir`、`-e E2E_ACME=1`。
5. `bash_install.sh`：当 `E2E_ACME=1` 时
   - 跳过 tls profile 的自签证书预置；
   - `install -m 0755 /seed/idleleo /usr/local/bin/idleleo`；
   - 记录 `acme_mode=pebble`，其余（Xray、helper、versions）不变。
6. Go 侧新增 `tests/e2e-diff/drivers/go_acme.sh`；`run_go_round()` 在
   `matrix_get $sid go.driver == "acme"` 时改调它。驱动内容：
   - 预置 systemd 就绪、`/usr/local/bin/idleleo`、`/usr/local/bin/xray`（与
     `go_install.sh` 相同的种子步骤）；
   - `idleleo xray cert issue --domain example.com --email e2e@example.com \
     --directory https://pebble:14000/dir --ca-cert /test/certs/pebble.minica.pem \
     --webroot /etc/idleleo --cert-out /etc/idleleo/cert/xray.crt \
     --key-out /etc/idleleo/cert/xray.key --takeover --force`；
   - 再执行 `idleleo xray install` + `go.argv`，并沿用现有 L0-L5 采集逻辑。
7. `matrix.json` 的 M8：
   - `go.argv` 改为完整 install argv（`--mode tls --transport ws --domain example.com
     --cert /etc/idleleo/cert/xray.crt --cert-key /etc/idleleo/cert/xray.key
     --port 9000 --public-port 443 --container`），与 M4 的端口分工一致；
   - 新增 `go.driver: "acme"` 与 `go.acme: {directory, caCert, webroot, email}`；
   - 跑通后才改 `eligible:true`、`go.verified:true`，并在 `notes` 写明证据路径。
8. 轮次语义不变：round 1 首次安装并签发证书；round 2 重装走“保留已有证书/配置”，
   不再访问 ACME，用于幂等验证。

### 2.3 验收

- `E2E_ONLY=M8 E2E_CONCURRENCY=1 bash tests/e2e-diff/run_p2_matrix.sh` 独立执行两次
  （不同 `E2E_RUN_ID`），每次都包含 round 1 + round 2。
- 通过标准：两侧 `rc=0`（round 1/2）、`nginx -t` 通过、`xray -test` 通过、
  L4 `ws` 有真实请求、`compare/verdict.json` 为 PASS，且证书 issuer 为 Pebble
  （在 evidence 里记录 `openssl x509 -issuer` 输出）。
- 证据提交到 `tests/e2e-diff/evidence/<run-id>/p2/M8/`，两次 run 都写进
  `docs/plans/p2/tasks.md` G-4 与 parity 文档。

### 2.4 失败兜底（不降低判定标准）

- 若 compare 把两侧 ACME 证书的序列号/指纹窗口判为差异：只在证书比较层按既有
  “SAN + 有效期窗口”归一，不放宽其他层。
- 若目录 TLS 通过但签发链校验失败：从 `https://pebble:15000/roots/0` 取根，与
  `pebble.minica.pem` 合并为 `/test/certs/ca-bundle.pem`，两端改用该 bundle。
- 任何一步无法在本机容器内闭环，就保持 `eligible:false`，把原因写进
  `HARNESS-BLOCKED.md` 并在 G-4 记录，不伪造 PASS。

## 3. G-5 设计（C6 direct TLS）

### 3.1 识别与模式

1. `internal/xraycfg` 新增常量 `ModeTLSDirect = "tls-direct"`（仅内部使用，
   不写入 metadata，避免 `tlsLabel` 拒绝）。
2. `internal/deploy/edit.go` 的 `editBase`：当没有受管 Nginx 配置，且运行配置
   第一个 inbound 的 `streamSettings.security == "tls"` 时，返回
   `Mode: xraycfg.ModeTLSDirect`，并从 `streamSettings.tlsSettings` 读取
   `serverName`（domain，可空）、`certificates[0].certificateFile/keyFile`、
   inbound 的 `listen/port`。
3. `xraycfg.EditRuntime` 在校验完 JSON 后、构造 `editSpecFromRuntime` 之前分流：
   `if base.Mode == ModeTLSDirect { return editDirectTLS(raw, req) }`。
   Nginx TLS 与 Reality 路径保持不变。

### 3.2 `PatchDirectTLS`（新文件 `internal/xraycfg/directtls.go`）

签名：

```go
type DirectTLSPatch struct {
    Config   []byte
    Changed  []string
    Domain   string
    Listen   string
    Port     int
    CertFile string
    KeyFile  string
}

func PatchDirectTLS(raw []byte, req EditRequest) (DirectTLSPatch, error)
```

规则：

1. 允许字段仅 `Domain`、`CertFile`、`CertKeyFile`、`Listen`、`Port`；其余
   `EditRequest` 字段非零即 `UsageError`：
   `direct TLS supports only --domain/--cert/--cert-key/--listen/--port`。
2. `--cert` 与 `--cert-key` 必须成对出现，单边报错。
3. 至少有一个 inbound 且 `streamSettings.security == "tls"`；否则报
   `config has no direct TLS inbound to edit`。TLS inbound 的
   `tlsSettings.certificates[0]` 必须同时含 `certificateFile` 与 `keyFile`，
   缺失即拒绝（不做猜测性写入）。
4. 证书变更应用到**所有** TLS inbound；`serverName` 仅在键已存在时更新
   （无 SNI 配置的直连配置不凭空新增结构）。
5. `listen/port` 仅当恰好一个 TLS inbound 时允许修改；多个 TLS inbound 报错并
   提示直接编辑配置文件，避免把多个端口改成同一值。
6. 窄断言（与新字段同款实现）：深拷贝原配置，把允许变更的叶子恢复为旧值，
   与补丁结果做 `reflect.DeepEqual`；不一致即报错，保证 routing/outbounds/
   其他 inbound 一个字节都不动。
7. `Changed` 使用既有字段名（`domain`、`cert-file`、`cert-key-file`、`listen`、
   `port`），供 preview/报告复用。

### 3.3 运行时结果

`editDirectTLS`：

- `Generated{Config: patch.Config, ShareURI: ...}`；分享链接用
  `ShareConfig(patch.Config, ShareOptions{Host: patch.Domain, PublicPort: patch.Port})`
  尽力生成，失败不阻塞编辑（不新增错误路径）。
- `EditResult{Mode: ModeTLSDirect, Transport: 第一个 inbound 的 network,
  Port/Listen/Domain/CertFile/KeyFile/Changed/Diff}`。
- `Disconnect: len(Changed) > 0`：direct TLS 的任何变更都需要重启 Xray。
- `NoChanges: len(Changed) == 0`。

### 3.4 `deploy.EditConfig`

1. TLS 对校验：`directTLS || (ModeTLS && tlsTouched)` 时校验证书对可读、
   与运行配置记录的路径一致、叶子可解析；失败在写入前返回。
2. 续期计划：direct TLS 不改 `schedule`，`Warnings` 追加
   `direct TLS 的证书续期不由本工具接管`。
3. 重启后探针：direct TLS 走 `probeLocalTLS`，地址 `127.0.0.1:<Port>`，
   `domain=res.Domain`、`leaf=pair.LeafDER`；失败沿用既有回滚 + 重启旧配置 +
   再次探针。
4. metadata：direct TLS 跳过 `updateMetadataAfterEdit`（无安装元数据可写，
   且不能让 `tlsLabel` 收到 `tls-direct`）。
5. 备份/回滚、`--no-restart`、`--no-probe`、`--dry-run`、`--json` 全部沿用。
6. 报告 `front` 记为 `direct-tls`，不引用 Nginx 目录。

### 3.5 测试（负例优先）

单元（`internal/xraycfg`，表驱动）：

1. 负例：只给 `--cert` 不给出 `--cert-key` → 报错；
2. 负例：`--transport ws` 等不支持字段 → 报错；
3. 负例：没有 TLS inbound / 缺 `certificates[0]` → 报错；
4. 负例：两个 TLS inbound 改 `--port` → 报错；
5. 正例：轮换证书对，只改 certificateFile/keyFile；
6. 正例：仅改 `--domain`，`serverName` 存在时更新；
7. 正例：单 inbound 改 `listen/port`；
8. 正例：请求值与现值相同 → `Changed` 为空；
9. 结构保持：routing、outbounds、其他 inbound 与输入完全一致（窄断言）。

部署（`internal/deploy`）：

1. 现有“security tls 不可编辑”的用例改为“direct TLS 可编辑”（`NoProbe`）；
2. 负例：证书对与运行配置不匹配 → 写入前失败，config sha 不变；
3. 正例：临时 `127.0.0.1` TLS 监听 + 探针通过，验证报告 `probe=verified`；
4. 负例：探针失败触发回滚，旧配置恢复。

E2E（`tests/go-parity/parity/features/C6_test.py`，运行在 `idleleo-e2e:24.04`）：

1. 负例先行：错误证书对 → rc=2，`config.json` sha256 不变；
2. 真实 direct TLS 配置 + 真实 xray 进程，执行 `idleleo xray config edit
   --cert ... --cert-key ... --yes`，断言证书叶子变化、routing 不变、探针通过；
3. `--dry-run --json` 不写文件；
4. 证据写 `tests/go-parity/evidence/c6-2026-11-17/`（`meta.txt`、`observed.json`、
   `baseline-compare.json`），hygiene 0 findings。

### 3.6 文档与提交

- `docs/plans/p2/gap-closeout.md`（或现有 C6 记录处）把 C6 标为
  `closed (CONTAINER_VERIFIED)` 并链接证据。
- `docs/plans/p2/tasks.md` G-5 勾选。
- 两次提交：`feat(C6): edit direct TLS configs with a narrow patch`、
  `test(C6): cover direct TLS edit, probe and rollback`。

## 4. G-6 设计（发布验收可本地验证部分）

新增证据目录 `tests/go-parity/evidence/g6-2026-11-17/`：

1. `release-gate.out`：本地原样执行
   `python3 tests/go-parity/parity/scripts/check_release_gate.py` 的输出与 rc；
   结论固定记录为 `rc=2, pending 28, missing tests 0`（除非当天仓库状态变化）。
2. `signoff-audit.md`：逐行列出 F01-F28 的 ledger `status`、执行器测试文件是否
   存在、最近证据目录、`FUNCTION_PARITY.md` 是否已有正式签收行；不修改 ledger。
3. `ci-closeout.md`：CI 结清步骤（见下），明确本地无法替代的部分。
4. `tasks.md` G-6：本地可验证子项勾选；CI 结清保持未勾选并注明阻塞原因。

CI 结清步骤（只记录，不执行 push）：

1. 在受保护分支上运行 `go-preview-qualification.yml` 与
   `go-release-qualification.yml` 的完整 job；
2. 仅在对应 feature 有 `CONTAINER_VERIFIED` 证据且经评审后，逐行把 ledger
   `PENDING` 改为 `VERIFIED_GO_PARITY` / `APPROVED_SAFE_DIVERGENCE`；
3. gate 的 CI 分支还要求 `GITHUB_ACTIONS=true` 与 `GITHUB_SHA`，因此最终 rc=0
   只能在 GitHub Actions 的发布提交上取得；
4. 禁止在本地伪造上述环境变量来宣称通过。

## 5. 不在范围

- 真实 VPS/公网 ACME、tag/release、push/merge。
- 为 `xray install` 增加内建 ACME（M8 Go 侧用两步等价流程）。
- direct TLS 的证书自动续期接管。
- base64 分享参数与既有关闭项的语义变更。

## 6. 完成定义

- G-4：M8 两次独立 E2E（各含两轮）PASS，证据与 matrix/docs 更新完成。
- G-5：单测 + C6 E2E 通过，C6 关闭为 `CONTAINER_VERIFIED`，两次提交完成。
- G-6：三份本地证据 + tasks.md 状态落盘，gate 结果与阻塞原因可复现；CI 结清
  仍为未完成项且未被伪造成通过。
- 全程 `install.sh` 零改动、ledger 状态零改动、无 push/merge/tag。
