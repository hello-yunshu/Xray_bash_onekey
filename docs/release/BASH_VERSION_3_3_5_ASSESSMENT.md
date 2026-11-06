# Bash 3.3.5 升级影响面评估（P0-3）

- 评估时间：2026-11-07
- 触发问题：审计 P0-3 —— 分支内 Bridge-aware `install.sh` 版本仍为
  `3.3.4`，已发布 v3.3.4 资产不含迁移入口，真实用户执行 `-u` 永远看不到入口。
- 评估对象：`install.sh`、`CHANGELOG.md`、`scripts/check_shell_release_intent.py`、
  `.github/workflows/publish-shell-version.yml`、`.github/test/` 版本断言、
  `Xray_bash_onekey_api` 的 `shell_online_version` / `shell_release_sha256`、
  `scripts/auto_update.sh` 更新链、Phase 03 E2E 夹具。

## 结论

1. **能升。** `3.3.4 → 3.3.5` 是同一 minor 内的补丁版本，`--yes` 会自动确认；
   `publish-shell-version.yml` 只要求 `shell_version` 严格递增 + CHANGELOG 有对应条目，
   两者都可在本分支满足。
2. **但本轮只准备、不发布。** 升版提交落在 `develop/go-native`；发布工作流只在
   `main` push（`paths: install.sh`）时触发。本轮约束明确不合并 `main`、不打 tag、
   不发 Release，因此不会产生线上资产，也不会改动 API 双字段。
3. **发布时机 = P0-2 完成之后、获得 main 合并授权的同一批。** 理由：3.3.5 的
   唯一用户可见增量就是迁移入口；若在 `asset.json` 生产发布链之前上线，用户会看到
   “Go 迁移资产尚未发布”并跳过——不是故障，但没有交付价值。
4. **发布后必须实跑一条 `v3.3.4 → v3.3.5 → 看到入口` 的真实路径**，并把
   `shell_online_version=3.3.5`、`shell_release_sha256=<3.3.5 install.sh SHA>` 同步到
   API，才算 P0-3 真正关闭。本轮只能验证到“提交前所有本地检查通过 + 发布意图为 true”。

## 影响面逐项

### 1. CHANGELOG

- `.github/test/test_shell_version_consistency.sh` 要求 `CHANGELOG.md` 含
  `## ${version} `（注意版本号后有空格）。
- 处理：新增 `## 3.3.5 — 2026-11-07` 条目，说明 Bridge-aware Bash、迁移清单消费、
  真机门禁放行与 cron 保留策略；保留 `## 未发布 — Go 管理器迁移` 的候选说明。

### 2. 发布流程

- 触发条件：`main` 分支 push 且 `install.sh` 变化 → `release-intent` 读取
  `scripts/check_shell_release_intent.py <before-sha>`；版本递增输出 `publish=true`。
- 后续链路：`candidate`（固定候选 commit、canonical pin、bundle/统计脚本 SHA）→
  `qualify`（复用 `test-install.yml`）→ `release`（创建不可变 `v3.3.5` Release）→
  `promote`（API PR + CDN/raw 收敛校验）。
- 影响：升版提交本身会让 `release-intent` 输出 `publish=true`；只要不合并 `main`
  就不会触发。合并后若 `qualify` 失败，Release 不会创建，旧 v3.3.4 资产不受影响。

### 3. 资产哈希

- `install.sh` 版本号变更会改变其 SHA-256，进而改变：
  - Release `SHA256SUMS`、`release-manifest.json` 的 `installSha256`；
  - API `shell_release_sha256`；
  - 安装器更新时的 `shell_release_sha256` 强校验（3.2.3+ 契约）。
- 影响：必须由发布工作流一次性生成并发布，不能手工改 API 指向。旧 v3.3.4
  Release 资产保持不可变，回退仍可下载 `v3.3.4/install.sh`（SHA 不变）。
- 本仓库内固定基线 `PIN_SHA=0af8e8f2…` 是已发布 v3.3.4 资产的哈希，**不随升版改变**；
  Phase 01 C12 的“已发布资产未变”语义应继续以该 pin 为准（P1-2 处理）。

### 4. 自动更新链

- `scripts/auto_update.sh` → `install.sh -u auto_update` → 读取
  `xray_shell_versions.json` 的 `shell_online_version` → 下载
  `v<version>/install.sh` → 校验 `shell_release_sha256` → 替换。
- 升版本身不改变链路。风险点在“发布原子性”：
  - Release 未创建前，API 若先改到 3.3.5，所有更新会 404 失败（既有逻辑保留旧脚本，fail-closed）；
  - Release 已创建、API 未改，用户停留在 3.3.4，不会误升级；
  - CDN 未收敛时 `promote` 会红灯并打印手工步骤，不会静默。
- 现有工作流顺序（先 Release、后 API）是正确的；本轮不修改。
- 迁移入口只出现在**手动 TTY `-u`**（非 `auto_update`、非 `--yes`）；
  自动更新链即使升到 3.3.5 也不会触发 Bridge offer。

### 5. 测试与夹具版本耦合

| 位置 | 现有耦合 | 处理 |
|---|---|---|
| `.github/test/test_geodata_update_path.sh` | 文本替换 `3.3.4 → 3.3.3`、期望 `3.3.4` | 改为从 `install.sh` 动态取当前版本，再算上一个补丁版本 |
| `tests/go-parity/phase03/run_phase03.sh` | `release-managed.version` 与 `versions.json` 写死 `3.3.4` | 改为从 `/work/install.sh` 动态取值，保持“本地=在线=已托管”语义 |
| `tests/go-parity/phase01/run_phase01.sh` C12.4 | 断言 `shell_version == 3.3.4` | 属于 P1-2 的 C12 重构：C12.1/C12.2 校验已发布 pin；C12.4 改为校验已发布 pin 脚本可加载 |
| `tests/go-parity/phase03/run_phase03.sh` 的 M02/M14 | `shell_online_version=3.3.4` | 同上动态化 |

- 不改动历史文档中的 `3.3.4`（Phase 00/01 基线记录、fixture `install_config.json`
  `shell_version` 字段），它们描述的是既有基线，不是当前发布版本。

## 发布前检查清单（P0-2 完成后执行）

1. `python3 scripts/check_shell_release_intent.py <main-before-sha>` → `publish=true`。
2. `bash .github/test/test_shell_version_consistency.sh` → 0 失败。
3. `bash .github/test/test_geodata_update_path.sh` → 0 失败。
4. Phase 03 容器 E2E → 201/201。
5. 合并 `main` 后确认 workflow `Release Xray` 绿，`v3.3.5` Release 资产与
   `release-manifest.json` 的 `installSha256` 一致。
6. API PR 合并后确认 CDN/raw `shell_online_version=3.3.5`、
   `shell_release_sha256` 与 Release 资产一致。
7. 真实 v3.3.4 节点执行 `-u`：下载 3.3.5、TTY 下看到迁移入口；
   无资产清单时干净跳过（不下载、不改动）。

## 未决项

- 本轮不执行第 5–7 步（不合并 `main`、不发布、不碰真实 VPS）。
- 若 P0-2 迟迟不落地，3.3.5 不应合并 `main`；否则用户只会看到“资产尚未发布”，
  属于无效发布。
