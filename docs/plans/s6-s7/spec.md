# S6 / S7 执行规格（Spec）

- 日期：2026-11-12
- 分支：`develop/go-native`（直接推送，不开 PR）
- 计划来源：[S6_S7_PLAN_2026-11-11.md](../../go/S6_S7_PLAN_2026-11-11.md)
- 本文件替代“边读边改”的推进方式：先把改动面、判据、验证、失败注入定死，批准后按 tasks.md 顺序执行。

## 0. 不可协商的约束

| 约束 | 落法 |
|---|---|
| `tests/go-parity/parity/cases/feature_contracts.json` 一个字节不动 | 执行前后 `git diff --stat` 必须为空；任何签收状态变化都留给后续轮次 |
| `tests/go-parity/parity/scripts/check_release_gate.py` 不动 | 同上 |
| 28 项账本保持 `PENDING_GO_IMPLEMENTATION` | `check_preview_gate.py` 必须仍然通过 |
| F12 不签收 | 缺公网域名 + 公网 CA + DNS-01/EAB；本规格不含任何放宽判据的动作 |
| 负面测试必须真红 | 每个新增校验都要有“注入失败 → 断言非 0 退出”的用例；禁止只断言输出文本 |
| `acme.sh` 退役原子提交 | S7-4 的入口/签发/续签 cron/卸载/备份白名单改在同一个 commit |
| 证据归因 HEAD | 全部证据在收尾时于最终 HEAD 复跑，`repo_commit` 必须等于 `git rev-parse HEAD` |
| 本轮不删 `/root/.acme.sh` | 只停用入口并保留一个版本的 legacy 开关 |

## 1. 现状锚点（已核实）

| 对象 | 位置/事实 |
|---|---|
| 脚本版本 | [install.sh 286](../../../install.sh#L286) `shell_version="3.3.6"` |
| 版本元数据变量 | [install.sh 344-347](../../../install.sh#L344-L347) |
| 版本比较工具 | [install.sh 405-478](../../../install.sh#L405-L478)（`version_compare` / `version_gt` / `version_lt`） |
| 元数据拉取与缓存 | [install.sh 519-558](../../../install.sh#L519-L558)（`fetch_versions_json` / `load_versions`） |
| 元数据消费 | [install.sh 561-585](../../../install.sh#L561-L585) `load_shell_release_metadata`；[2483-2509](../../../install.sh#L2483-L2509) `check_version`/`check_version_silent`；[13347](../../../install.sh#L13347) `read_version` |
| helper 下载 | [1673](../../../install.sh#L1673) `download_script_file`；[1731-1743](../../../install.sh#L1731-L1743) `xray_stats`；[4318](../../../install.sh#L4318) `ensure_sub_script`；[7452](../../../install.sh#L7452) `auto_update` |
| TCP 入口 | [11023-11027](../../../install.sh#L11023-L11027) `bbr_boost_sh`；`-tcp`；菜单 28 |
| superspeed | [15707-15710](../../../install.sh#L15707-L15710)；菜单 33 |
| acme.sh | [339](../../../install.sh#L339)、[7475-7479](../../../install.sh#L7475-L7479)、[7888-7900](../../../install.sh#L7888-L7900)、[8745-8754](../../../install.sh#L8745-L8754)、[8860-8937](../../../install.sh#L8860-L8937)、[10073-10123](../../../install.sh#L10073-L10123)、[11241-11242](../../../install.sh#L11241-L11242)、[14024](../../../install.sh#L14024)、[14362](../../../install.sh#L14362) |
| Go TCP 实现 | [internal/cli/tcp.go](../../../internal/cli/tcp.go)、[internal/tcpcfg](../../../internal/tcpcfg)（`status/plan/apply/rollback`，sandbox gate） |
| Go CLI 注册点 | [internal/cli/cli.go](../../../internal/cli/cli.go) `dispatch` |
| manifest | [assets/go/manifest.json](../../../assets/go/manifest.json)（`go1.24.0` / `a1e00850…` / `0.2.0-phase04`，已过期） |
| 已有 Go 构建入口 | 容器 `golang:1.27.4`，`GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor` |
| 已有 Bash 测试范式 | [.github/test/test_version_loading.sh](../../../.github/test/test_version_loading.sh)：`_TEST_MODE=1` source install.sh，覆写 `curl`/`log_echo` |

S6-0 已核实完成：`git ls-files vendor` 812 个文件，无 `* 2.*` 副本；`gofmt`/`build`/`vet`/`go test`/卫生门禁全绿。

## 2. S6 规格

### S6-3 版本元数据 Ed25519 签名（先做，信任根）

**签名格式（唯一定义）**

```json
{ "...": "...", "metadata_signature": "ed25519:<base64(raw 64-byte signature)>" }
```

- 被签字节 = `jq -cS 'del(.metadata_signature)'` 的输出，**去掉结尾换行**（`printf '%s' "$(...)"` 语义）。
- 公钥固定为 install.sh 内嵌 PEM（Ed25519 SPKI），指纹见 §5。
- 唯一签名器：新增 `scripts/sign_versions_metadata.sh`（jq + openssl），发布流水线与测试共用。

**install.sh 改动**

1. 在 [install.sh 344](../../../install.sh#L344) 附近新增：
   - `shell_versions_pubkey_pem`（内嵌 PEM 常量）
   - `versions_signature_required_from="3.4.0"`
2. 在 `fetch_versions_json` 之后新增四个函数：
   - `versions_metadata_pubkey`：输出内嵌 PEM；仅当 `XRAY_QUALIFICATION_MODE=1` 且 `IDLELEO_VERSIONS_PUBKEY_FILE` 指向可读文件时改用后者（测试注入）。
   - `versions_metadata_canonical_file <json> <out>`：`printf '%s' "$json" | jq -cS 'del(.metadata_signature)' | tr -d '\n' > out`。
   - `openssl_supports_rawin`：`openssl pkeyutl -help 2>&1 | grep -q -- -rawin`。
   - `versions_metadata_trusted <json>`：返回 0 可信 / 1 拒绝；只在 stderr 输出诊断。
3. `versions_metadata_trusted` 判定表（顺序执行，命中即返回）：

   | 条件 | 结果 |
   |---|---|
   | 无 `metadata_signature` 且 `version_lt "$shell_version" "$versions_signature_required_from"` | **接受** + stderr 警告“兼容期未签名” |
   | 无 `metadata_signature` 且脚本版本 ≥ 3.4.0 | **拒绝**（`return 1`） |
   | 前缀不是 `ed25519:` | **拒绝** |
   | `openssl` 缺失或不支持 `-rawin` | **拒绝**（fail-closed，附诊断） |
   | base64 解码后不是 64 字节 | **拒绝** |
   | `openssl pkeyutl -verify -pubin -inkey … -rawin -in … -sigfile …` 非 0 | **拒绝** |
   | 其余 | **接受** |

4. `load_versions` 在 `jq -e 'type=="object"'` 通过后调用 `versions_metadata_trusted "${response}"`；失败则 `get_versions_all=""`、`return 1`（保持既有“元数据不可用”语义，不新增部分写入）。
5. 所有诊断走 stderr；`get_versions_all` 的 stdout 纯净性不变（`test_version_loading.sh` 的既有断言必须继续通过）。

**测试（新增）** `.github/test/test_versions_signature.sh`

- 用临时密钥对（`openssl genpkey -algorithm ed25519`）生成签名夹具，`XRAY_QUALIFICATION_MODE=1 IDLELEO_VERSIONS_PUBKEY_FILE=<pub>` 注入。
- 必须包含的注入失败用例，每条都断言 `read_version` / `load_versions` **非 0**：
  1. 改一个字段（如 `shell_release_sha256`）但保留原签名 → 拒绝。
  2. 签名 base64 翻一位 → 拒绝。
  3. 签名截断（32 字节）→ 拒绝。
  4. `shell_version` 强制 ≥ 3.4.0 时无签名 → 拒绝。
  5. `metadata_signature` 前缀写成 `rsa:` → 拒绝。
- 必须包含的通过用例：
  6. 正确签名 → 接受，且字段值与原始 JSON 一致。
  7. `shell_version=3.3.6` 且无签名 → 接受 + stderr 出现兼容期警告。

### S6-2 helper 下载 sha256 校验收敛

**改动**

1. `download_script_file <url> <dest>`：新增可选第三参数 `expected_sha256`；提供时下载完立即 `sha256sum` 比对，不符则删除临时文件并 `return 1`；未提供时行为不变（供非 helper 下载继续使用）。
2. `xray_stats`（1731-1743）：从版本元数据读取 `statsScriptSha256`，作为第三参数传入；缺失或非法（非 64 hex）时**拒绝安装该 helper**并给出明确诊断，不再静默安装未校验文件。
3. `ensure_sub_script`（4318）：同样接入期望值来源（元数据字段缺失时拒绝）。
4. 新增常量表 `helper_checksum_policy`（函数形式，返回 `name=field` 映射），把 6 个 helper 与元数据字段一一对应；未知 helper 直接拒绝（fail-closed），为后续扩展留唯一入口。

**测试（新增）** `.github/test/test_helper_checksum.sh`

- 覆写 `curl` 返回固定内容，注入错误 sha（翻转一位）→ 断言 `xray_stats` / `ensure_sub_script` **非 0** 且目标文件不存在。
- 注入正确 sha → 断言 0 且文件存在。
- 元数据缺 `statsScriptSha256` → 断言非 0。
- 版本未变不覆盖（mtime/内容不变）保持既有行为。

### S6-1 TCP 入口接线

**改动**

1. `bbr_boost_sh`（11023-11027）：改为三段
   - 默认：调用 `idleleo tcp status`（无则 `idleleo tcp plan`），**不发起任何网络请求**。
   - `--apply`：`idleleo tcp apply --profile bbr-fq --confirm`（root 真实路径需二次确认）。
   - `--legacy`：沿用旧 `tcp.sh` 下载执行，但必须交互输入 `legacy` 才继续。
2. `-tcp` 参数与菜单 28 都只调用 `bbr_boost_sh`，不各自实现分支。
3. 未安装 `idleleo` 时输出“请先安装 Go 版入口”，不自动回落到下载。

**测试（新增）** `.github/test/test_tcp_entry.sh`

- 用假 `idleleo`（记录 argv 后退出 0）证明默认分支调到 `tcp status|plan`。
- 覆写 `curl` 为“一旦被调用就写标记文件”，断言默认/`--apply` 分支**未创建标记**（无网络）。
- `idleleo` 不存在时返回非 0 且提示不下载。
- `--legacy` 未确认时返回非 0。

## 3. S7 规格

### S7-1 `idleleo speedtest`

**改动**

- 新增 `internal/speedtest/speedtest.go`：纯标准库实现，`Options{Server, Timeout, SizeBytes}`，默认对 `speed.cloudflare.com` 的 `/__down?bytes=N` 做 3 次采样；输出 `Result{Server, DownMbps, Samples, StartedAt, Duration}`；`context` 可取消。
- 新增 `internal/cli/speedtest.go`：`idleleo speedtest [--json] [--server URL] [--timeout 10s] [--bytes N]`，在 `cli.go` 的 `dispatch` 注册 `case "speedtest"`。
- 非 root 可运行；不写系统路径；不下载执行任何脚本。
- 测速失败（全部采样失败/超时）→ 非 0 退出。

**测试**

- `internal/speedtest/speedtest_test.go`：`httptest` 本地端点返回固定字节，断言吞吐计算与超时取消；端点返回 500 → 非 0。
- `internal/cli` 增加 `--json` schema 断言（字段稳定）。

### S7-2 `tcp.sh` 退役

- 删除 11023-11027 中的下载分支；`--legacy` 只保留“本地已存在 `/etc/idleleo/scripts/tcp.sh` 才执行”，不再下载。
- 菜单 28 与 `-tcp` 文案改为指向 `idleleo tcp`。
- 测试：`grep` 断言 install.sh 无 `tcp.sh` 远程 URL；`test_tcp_entry.sh` 增加“legacy 且本地缺失 → 非 0”。
- 依赖 S6-1。

### S7-3 `superspeed.sh` 退役

- 15707-15710 与菜单 33 改为 `idleleo speedtest`；`idleleo` 缺失时提示安装，不下载脚本。
- 测试：`grep` 断言无 `cdn.jsdelivr.net/gh/hello-yunshu/superspeed`；假 `idleleo` 断言菜单 33 调用 `speedtest`。
- 依赖 S7-1。

### S7-4 `acme.sh` 原子退役（单 commit）

- 入口 339 / 7475-7479 / 7888-7900 / 8745-8754 / 8860-8937 / 10073-10123 / 11241-11242 / 14024 / 14362 一并改：
  - 签发走 `idleleo xray cert issue`（`internal/acme`）。
  - 续签 cron 由 `idleleo schedule cert-renew` 接管；旧 `acme.sh --cron` 条目在升级时移除并记录。
  - 卸载与备份白名单移除 `acme.sh` 路径，但**保留磁盘上 `/root/.acme.sh`**（不删除用户数据）。
  - `IDLELEO_ACME_LEGACY=1` 保留一个版本，走旧路径并打印弃用警告。
- 判据：新装路径不再出现 `get.acme.sh` 下载；legacy 开关可回退；卸载不删 `/root/.acme.sh`。
- 测试（新增）`.github/test/test_acme_retire.sh`：grep 断言无 `get.acme.sh`；假 `idleleo` 断言签发/续签调用；断言卸载脚本不含 `rm -rf /root/.acme.sh`。
- 注：`schedule cert-renew` 目前只监控不签发，本任务需要在 `internal/schedule` 增加“到期触发 `xray cert renew`”的最小驱动，否则退役后无续签。

### S7-5 manifest 刷新与签名

- `assets/go/manifest.json` 由发布流水线产出，本任务只做**签名字段与校验**：
  - 新增 `internal/release/signature.go`：`CanonicalManifest([]byte) ([]byte, error)`（解析为 map、删 `signature`、`json.Encoder` 且 `SetEscapeHTML(false)`、键排序）+ `VerifyManifest([]byte, ed25519.PublicKey) error`。
  - `internal/release` 校验入口在签名存在时强制校验；`signature` 缺失时保持现状并返回可识别的 warning 类型。
  - 签名格式与 S6-3 相同：`"signature": "ed25519:<b64>"`；签名器复用 `scripts/sign_json_ed25519.sh`（S6-3 脚本泛化为 `sign_json_ed25519.sh <json> <key> <field>`）。
  - manifest 内容刷新（goVersion / sourceCommit / version）由 CI 生成，**本轮不手改字段值**，只在 `docs/go/DECISIONS.md` 记录“由流水线生成”。
- 测试：`internal/release/signature_test.go` 正/负各一组（改一字节 → 失败；缺字段 → 失败；正确 → 通过）。

## 4. 验证与证据

1. Go：`golang:1.27.4` 容器内 `GOPROXY=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor gofmt -l cmd internal`、`go build ./...`、`go vet ./...`、`go test ./...`。
2. Bash：仓库内新增测试脚本逐个执行，失败即非 0；`bash -n install.sh`。
3. 门禁：`check_evidence_hygiene.py tests/go-parity/evidence tests/go-parity/parity/evidence docs`；`check_preview_gate.py`（容器方式）；`git diff --stat` 证明两个受保护文件未变。
4. 证据目录：`tests/go-parity/evidence/s6-s7-2026-11-12/`，含 `run.log`（`repo_commit=$(git rev-parse HEAD)`）、各测试输出、门禁输出、`summary.json`。
5. 收尾：`docs/release/KNOWN_LIMITATIONS.md`、`docs/go/DECISIONS.md` 同步；报告里逐 job 归因 CI 红（runner apt DNS 单列）。

## 5. 信任锚（S6-3 / S7-5 共用）

| 项 | 值 |
|---|---|
| 算法 | Ed25519 |
| 公钥（SPKI PEM，内嵌） | `MCowBQYDK2VwAyEAUoalfNZ0sm8gFnuKlitv2fJP7Scfae3YHhCE3YMr7lc=` |
| SHA-256 指纹（DER） | `i9tgMeTyzckKNYJCpg1uiPlI1mHdPQl9H3SfXeOM6+E=` |
| 私钥位置（不入库） | GitHub Secret `IDLELEO_VERSIONS_ED25519_KEY`（Go manifest 用独立的 `IDLELEO_RELEASE_ED25519_KEY`） |
| 未登记 Secret 时 | 发布流水线 fail-closed（`exit 1`），不发布未签名 JSON；3.6.0 起 install.sh 拒绝未签名元数据 |

## 6. 未纳入本轮 / 明确不做

- S6-4 插件化：单独立项，本轮零改动。
- 删除 `/root/.acme.sh`：不做，只停用入口。
- `feature_contracts.json` 签收状态、`check_release_gate.py`：不动。
- manifest 的 `goVersion`/`sourceCommit` 手改：不做，交给流水线。
- F12：不签收（缺公网域名 + 公网 CA + DNS-01/EAB）。

## 7. 需要批准的决策

1. 版本元数据签名格式采用“JSON 内嵌 `metadata_signature` + jq 规范化”，而非 detached `.sig` 文件。
2. 签名校验依赖 OpenSSL ≥ 3（`pkeyutl -rawin`）；缺失即 fail-closed，并在 `KNOWN_LIMITATIONS.md` 记录（Debian 11 / Ubuntu 20.04 已 EOL）。
3. 兼容期以“运行中的 install.sh 自身版本”判定，切点 `3.4.0`。
4. 新建签名私钥存放于仓库外 `~/.idleleo-signing/`，不入库。
