# G-3 / F19 规格：备份恢复与重配置保留执行器

状态：**已实施（2026-11-16）**。执行器 `tests/go-parity/parity/features/F19_test.py`
容器内连跑两次均 136/136，证据 `tests/go-parity/evidence/f19-2026-11-16`。

## 0. 结论摘要

1. F19 的 Go 已实现面是 **metadata 单一真相的导入/导出/交还**，不是完整备份归档。
   `metadata import` 从既有 `install_config.json` 派生元数据且永不覆盖；
   `metadata export` 记录当时运行配置摘要，`bridge deactivate` 用它证明无漂移后归档元数据。
2. 执行器真实驱动 Go CLI，断言三条不变量：**源配置/运行配置/证书/入口/cron 逐字节不变**、
   **任何漂移或损坏都显式拒绝且零写盘**、**交还后元数据只归档不删除**。
3. Bash 的 `--backup`（含证书私钥与 ACME 账户私钥的归档）与 `--restore` 在 Go 侧尚未实现，
   执行器把这一差异写入证据 `bash-baseline.json`，不伪装成已对齐。
4. 证据等级 **CONTAINER_VERIFIED**；固定镜像 `idleleo-preview:latest`
   （digest `sha256:ba371758104034125c9519079ef15838d8d4faf9eb23a0a1721bc0789b1234de`），
   连跑两次全绿后才提交，且只提交执行器、证据与三处文档计数。

## 1. 现状事实（已读代码）

| 事实 | 证据 |
|---|---|
| `metadata import` 只接受 `--from install_config.json` 或根下该文件的绝对路径，否则 rc=2 | `internal/cli/metadata.go` L22-L29 |
| import 先取 `/run/lock/idleleo-update.lock`，已存在 `etc/idleleo/v1/metadata.json` 时 rc=3 且不覆盖 | `internal/legacybridge/metadata.go` L46-L66 |
| import 读取并哈希 `install_config.json`，写盘前再哈希一次；源文件只读 | 同上 L68-L123 |
| 元数据固定 `provenance=legacy`、`schemaVersion=1`，node 必须有运行配置摘要 | `buildMetadata`（`bridge.go` L474-L513） |
| 元数据落盘 0640；`store.LoadMetadata` 拒绝 UUID/privateKey/shortId 等密钥字段 | `metadata.go` L118、`store/metadata.go` `rejectSecrets` |
| `metadata export` 读元数据与运行配置，报告 `matchesMetadata`；`--out` 写 0600 | `metadata.go` L161-L202 |
| export 拒绝写到元数据本身、`etc/idleleo/conf`、证书目录、`etc/idleleo/info` | 同上 L226-L241 |
| `bridge deactivate` 要求导出文件，校验元数据摘要/运行摘要/导出时的 `matchesMetadata`，漂移 rc=6 | 同上 L267-L334 |
| 无 bridge journal 时只释放元数据：移到 `var/lib/idleleo/bridge/snapshot/metadata.deactivated.json`，不动入口/cron/运行配置/证书 | 同上 L336-L369 |
| 非 `/` 根写入必须有 `.idleleo-phase01-sandbox` = `I_ACCEPT_DISPOSABLE_SANDBOX` | `internal/host/gate.go` L40-L46 |
| Bash 基线提供 `--backup` / `--restore`；`--restore` 已显式拒绝 | `install.sh` L14191-L14192、L966-L969 |

## 2. 夹具布局（每个场景独立重建，不继承状态）

真实 legacy 根（reality-direct 风格）：

```
.idleleo-phase01-sandbox         I_ACCEPT_DISPOSABLE_SANDBOX
etc/idleleo/install.sh           legacy 恢复备份标记
etc/idleleo/conf/install_config.json   role=node, shell_mode=Reality, tls=Reality,
                                       port=9443, reality_add_nginx=off,
                                       shell_version=3.3.4, xray_version=26.10.31
etc/idleleo/conf/xray/config.json      Reality inbound + 自定义 dns/routing（保留证据）
etc/idleleo/cert/fullchain.pem
etc/idleleo/cert/privkey.pem
etc/systemd/system/xray.service
usr/bin/idleleo                 -> /etc/idleleo/install.sh（Bash 入口，根内）
var/spool/cron/crontabs/root    项目行 + 一条用户自己的行
```

relay 根：`role=relay`、`etc/idleleo/conf/nginx/relay-stream.conf`、install.sh、入口。
键值全部用合成数据（RFC 5737 地址、`example.invalid`、一次性 x25519 密钥），不联网。

## 3. 断言矩阵

### 3.1 import 成功（node）

命令：`idleleo --root ROOT --json metadata import`

- rc=0；报告 `schemaVersion=1`、`state=IMPORTED`、`provenance=legacy`、`role=node`、
  `tls=Reality`、`transport=raw`、`sourcePath` 指向根内 install_config、
  `sourceSha256` 等于实际文件摘要、`metadataPath=etc/idleleo/v1/metadata.json`、
  `metadataSha256` 等于落盘文件摘要、`runtimeSha256` 等于运行配置摘要。
- 元数据文件存在且 **0640**；JSON 断言 `activeEngine=xray`、`runtimeConfigPath`、
  `ownedResources` 含运行配置/`xray.service`/证书目录、`updatedAt` 非空。
- 元数据全文件不含 `uuid`/`privateKey`/`shortIds` 等密钥键（递归断言）。
- 源 install_config、运行配置、两张证书、cron、入口链接目标逐字节/逐项不变。

### 3.2 import 幂等拒绝

- 同根第二次 import：rc=3，stderr 含 `already exists`；元数据摘要、源文件摘要不变。
- `--from /tmp/anything.json`：rc=2，stderr 含 `only reads`；元数据不存在（新根）。
- `--from install_config.json` 在新根上：rc=0，证明合法别名可用。
- 未打 sandbox marker 的根：rc=2，stderr 含 `write access refused`，元数据不存在。

### 3.3 import 失败矩阵（全部零写盘）

| 场景 | 期望 rc | 断言 |
|---|---|---|
| 缺 `install_config.json` | 2 | 无元数据；根树摘要不变 |
| install_config 非 JSON | 2 | 无元数据；根树摘要不变 |
| node 但运行配置缺失 | 3 | 无元数据；根树摘要不变 |
| relay 根（合法） | 0 | `role=relay`、`tls=None`、`transport=stream`、`runtimeSha256=""`，`ownedResources` 含 relay 配置 |

### 3.4 export 只读与写入

- 无 `--out`：rc=0，JSON 报告 `matchesMetadata=true`、两个摘要等于实际值；
  元数据/运行配置摘要不变。
- `--out DIR/export.json`（根外）：rc=0，文件 **0600**，内容字段与报告一致；
  元数据/运行配置不变。
- `--out ROOT/etc/idleleo/conf/export.json`：rc=2，stderr 含 `refusing to export into managed path`，
  文件不存在。
- `--out ROOT/etc/idleleo/v1/metadata.json`：rc=2，stderr 含 `refusing to export over manager metadata`，
  元数据不变。

### 3.5 漂移与交还

1. 修改运行配置（追加一个换行，仍是合法 JSON）：export 报告 `matchesMetadata=false`
   且 `runtimeSha256 != metadataRuntimeSha256`。
2. 用漂移前导出的文件 `bridge deactivate --export OLD`：rc=6，stderr 含
   `runtime config changed since the export`；元数据仍在、入口/cron/证书不变。
3. 用漂移期间的新导出交还：rc=6，stderr 含 `metadata and the runtime config disagreed`。
4. 恢复运行配置原始字节 → 重新 export → `bridge deactivate`：rc=0，`state=RELEASED`、
   `metadataArchive=var/lib/idleleo/bridge/snapshot/metadata.deactivated.json`、
   `rillUnchanged=true`；原元数据路径消失，归档与交还前元数据逐字节相同；
   入口链接、cron、运行配置、证书不变。

### 3.6 Bash 基线差异（写入证据，不判 Go 失败）

静态读取 `--bash-repo/install.sh`：

- 断言存在 `--backup` 与 `--restore` 帮助行；
- 写 `bash-baseline.json`：`bash-backup-archive` = `not-implemented`
  （Go 只导出元数据，不归档证书/ACME 私钥）、`bash-restore-archive` = `not-implemented`
  （Bash 自身也拒绝重建运行配置）、`metadata-export/import` = `implemented`；
- 断言 Go 帮助文本含 `metadata import|export`，且不含 `--backup`/`--restore` 承诺。

## 4. 非目标

- 不实现 Bash 的完整备份/恢复归档；不新增 `backup`/`restore` 子命令。
- 不测试 bridge prepare/activate 事务（F06/F22 已覆盖），不接触真实 VPS、不联网。
- 不改变 `feature_contracts.json` 的 28 项状态，不写 tag/release。

## 5. 交付物与验证

1. 新增 `tests/go-parity/parity/features/F19_test.py`（复用 `fixture_support.py`，
   200 秒预算内，失败即 RED，缺环境 exit 2）。
2. 构建与运行：
   - `docker run --rm -v "$PWD":/src -w /src -v "$BUILD":/out -e CGO_ENABLED=0 golang:1.27.4 go build -trimpath -o /out/idleleo ./cmd/idleleo`
   - 固定 digest 镜像内以 `--privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock`
     挂载只读仓库/二进制与证据目录，执行 `python3 -I F19_test.py --go-bin ... --bash-repo ...`；
   - 连跑两次均全绿。
3. 证据目录 `tests/go-parity/evidence/f19-2026-11-16/`：`meta.txt`（commit、镜像 digest、
   命令、两次结果、`go_bin_sha256`、notes）、`commands.log`、`fixture-result.json`、
   `bash-baseline.json`；`check_evidence_hygiene.py` 通过。
4. 文档收口：`docs/go/FUNCTION_PARITY.md` F19 行、`docs/plans/p2/tasks.md` G-3
   计数 13 与 F19 子项、`tests/go-parity/parity/features/README.md` 执行器计数。
5. 单独提交：`test(parity): add F19 metadata executor`；不合并 main、不打 tag、不 push。

## 6. 审批点

需要用户确认：

- 以 **metadata 导入/导出/交还** 作为 F19 的 Go 已实现面，Bash 完整备份/恢复记为
  `not-implemented` 差异（而不是据此判 RED）；
- 接受“运行配置改一个换行”作为漂移故障注入，验证显式报告与零写盘；
- 同意在 G-3 计数中把 F19 记为第 13 个执行器。
