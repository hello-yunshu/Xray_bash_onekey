# S4–S9 辅助脚本验收规格（网络可用，不把第三方下载当阻塞）

- 分支：`work/go-evolution-audit-20261118`
- 目标：把最终看板中 `S1–S9 = 9 NOT_RUN` 收敛为可追溯的 PASS / FAIL / BLOCKED，不再用“仓库无本体”当理由。
- 硬约束：
  1. 不伪造证据；需要真实域名 + 公网 CA 的环节明确记为 BLOCKED，并在文档写解除条件。
  2. 不修改 `feature_contracts.json` 状态，不 `git push`，不合并主干，不打正式 Release。
  3. 证据目录提交前必须通过 `check_evidence_hygiene.py`（0 findings）。
  4. 第三方脚本“能下载 + 能安装 + 能被调用”即算该脚本行通过；不要求容器内完成内核替换或真实 CA 签发。

## 1. 现状结论（已核实，写入文档的事实）

| 行 | 当前实现 | 仓库内是否有本体 | 下载源 |
|---|---|---|---|
| S4 | `scripts/auto_update.sh` | 有 | 版本元数据 CDN/GitHub Raw（可注入） |
| S5 | `scripts/ssl_update.sh` | 有 | 原生 `idleleo xray cert renew`，本地 Pebble 可跑 |
| S6 | `scripts/geo_update.sh` | 有 | `Loyalsoldier/v2ray-rules-dat` Release |
| S7 | acme.sh 仅 legacy 回退 | 无 | `https://get.acme.sh` |
| S8 | 默认走 `idleleo tcp`，legacy 需本地 tcp.sh | 无 | `https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh` |
| S9 | 默认走 `idleleo speedtest` | 无 | `https://cdn.jsdelivr.net/gh/hello-yunshu/superspeed@master/superspeed.sh` |

S1/S2/S3 为交互菜单脚本，能力由 OPS 双端行覆盖；本轮只补 S1 的既有 `bash_f2b.exp` 复跑（可选），不把交互脚本计入 S4–S9 的通过数。

## 2. 新增文件

### `tests/e2e-diff/run_s_scripts.sh`
单一入口，`set -uo pipefail`，结构复刻 `run_ops_sweep.sh`：
- 顶部变量：`ROOT`、`SUITE`、`RUN_ID`（默认 `s-$(date +%Y%m%d-%H%M)-<sha>`）、`EVID=$SUITE/evidence/$RUN_ID/s`、`WORK=/tmp/e2e-$RUN_ID`、`IMAGE_TAG=idleleo-e2e:24.04`、`GO_IMAGE=golang:1.27.4`。
- `source tests/go-parity/lib/docker_common.sh`，用 `docker_arch` / `ensure_xray_bin` / `cgroup_mount_args`。
- 构建 `idleleo`、`idleleo-recover`、`xray` 到 `$WORK/seed`；生成自签证书。
- 容器一律 `--privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock`，`-v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID:/out"`，挂**用户自定义 bridge 网络**以获得出网。
- `assert <0|1> <msg>` 写 `assertions.txt`；`log` 写 `run.log`。
- 每个 S 行单独函数，互不阻断；结尾打印 `PASS/FAIL` 并 `exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)`。
- `E2E_ONLY=S4,S5` 可裁剪；`E2E_KEEP=1` 保留容器。

### 场景 A：`run_s4_s6_s8_s9`（1 个容器，reality 安装 + 出网）
1. 用 `drivers/bash_install.sh` 做真实 Bash 安装（`E2E_SCENARIO=S4`、`E2E_PROFILE=reality`、`E2E_ARG=-2`、`E2E_DOMAIN=example.com`、`E2E_TARGET=www.cloudflare.com`），得到 `/etc/idleleo/install_config.json` 与 `/etc/idleleo/scripts/*`。
2. **S4**：
   - 正常：`bash /etc/idleleo/scripts/auto_update.sh`（真实 CDN 元数据）。断言 rc=0 且 `auto_update.log` 含 `Script is up to date` 与 `Xray is up to date`。
   - 重复：再跑一次，断言两条日志各出现 2 次（幂等）。
   - 失败：`XRAY_VERSIONS_FILE=/tmp/bad.json`（缺字段），断言 rc=0 且日志含 `skipping update checks`，且 `install_config.json` sha 不变（fail-safe，不误升级）。
3. **S6**：
   - 正常：`bash /etc/idleleo/scripts/geo_update.sh`，断言 rc=0、`/etc/idleleo/share/xray/geoip.dat` 与 `geosite.dat` 存在且非空、`conf/xray/geo_version.json` 两个 key 有值、`xray` 仍 active。
   - 重复：再跑，断言 rc=0 且日志含 `All GeoData files are current`；两文件 sha 与第一轮一致。
   - 失败：PATH 前置 stub 目录放 `curl` 返回 1，断言 rc≠0、两个 `.dat` sha 与上一轮一致（未破坏现网文件）。
4. **S8**：
   - `idleleo tcp plan --json` rc=0 且 JSON 可解析。
   - `idleleo tcp apply --profile bbr-fq --confirm` rc=0，`sysctl` drop-in 文件存在。
   - 重复 apply rc=0（幂等）；`idleleo tcp rollback --confirm` rc=0，drop-in 不存在。
   - Bash legacy fail-closed：`grep` 断言 `install.sh` 不含 `Linux-NetSpeed` 下载、`bbr_boost_sh --legacy` 分支在 `scripts_dir/tcp.sh` 缺失时报错并返回 1；另用 `curl` 下载一次历史 `tcp.sh`，记录 URL + sha256 + `bash -n` 语法检查（交互+换内核，不执行）。
5. **S9**：
   - `idleleo speedtest --bytes 1048576 --samples 1 --timeout 20s --json` rc=0 且 JSON 含 `downMbps`/`server`。
   - 重复执行一次，两次均 rc=0。
   - 失败：`--server 127.0.0.1:1 --timeout 2s` 断言 rc≠0 且无 panic。
   - 下载历史 `superspeed.sh`，记录 URL + sha256 + `bash -n`（交互脚本不执行）。

### 场景 B：`run_s5_ssl_update`（Pebble + Bash TLS ACME 安装）
- 复用 `run_p2_matrix.sh` 的 `prepare_pebble_assets` / `start_pebble` / `wait_pebble` 逻辑（抽成本脚本内三个函数，避免跨脚本 source）。
- 启动 Pebble（`PEBBLE_VA_ALWAYS_VALID=1`、`PEBBLE_VA_NOSLEEP=1`、`PEBBLE_AUTHZREUSE=0`），容器额外挂 `/test/certs`。
- Bash 安装：`E2E_PROFILE=tls E2E_ARG=-1 E2E_ACME=1 E2E_TRANSPORT=1`，env `SSL_CERT_FILE=/test/certs/pebble.minica.pem`、`IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir`。
- **正常**：`SSL_CERT_FILE=... IDLELEO_ACME_DIRECTORY=... bash /etc/idleleo/scripts/ssl_update.sh`，断言 rc=0、`/etc/idleleo/cert/xray.crt` 的 notBefore/指纹变化、`xray`+`nginx` 仍 active。
- **重复**：再跑一次 rc=0。
- **失败**：`docker stop <pebble>` 后再跑，断言 rc≠0、证书 sha 与上一轮一致、nginx/xray 仍 active（服务不因续期失败被留在停机状态）。
- 若 Pebble 镜像不可用：写 `evidence/.../S5/BLOCKED.md`，记录 `docker logs`，行判定 BLOCKED，不伪造 PASS。

### 场景 C：S7 acme.sh（download 即可，不阻塞）
- 在场景 A 容器内：
  - `curl -fsSL https://get.acme.sh -o /tmp/acme-install.sh`，记录 URL + sha256。
  - `sh /tmp/acme-install.sh email=e2e@example.com`，断言 rc=0 且 `$HOME/.acme.sh/acme.sh` 可执行。
  - `$HOME/.acme.sh/acme.sh --version` 与 `--help` rc=0，输出入证据。
  - legacy 续期 fail-closed：`IDLELEO_ACME_LEGACY=1 IDLELEO_ACME_HOME=/tmp/no-acme bash scripts/ssl_update.sh` 断言 rc≠0 且 stderr 含 `acme.sh not found`。
  - 断言本行 **不做真实签发**；`S7/BLOCKED-issuance.md` 写“需要真实域名 + 公网 CA”。

## 3. 文档更新（只改这三处）
1. `docs/go-evolution/01-parity-and-safety.md`：新增 “§6.2 S4–S9 辅助脚本实跑” 小节，表格列 `S4..S9 / 状态 / 证据路径 / 说明`，引用 `RUN_ID`。
2. `docs/go-evolution/03-final-qualification.md` §6.5：把 `S1–S9 = 9 NOT_RUN` 改为实际结果（如 `S4–S9 = 6 PASS / 0 FAIL`；`S1–S3` 保持“由 OPS 覆盖”，并注明 S7 签发、S5 真实 CA 的边界）。§7 阻断项同步删掉“仓库无本体”表述。
3. `docs/go-evolution/STATUS.md`：追加本轮 RUN_ID、命令、结论。
4. `feature_contracts.json` **不改**；文档写明 `check_release_gate.py rc=2` 的精确原因（28 行 pending + 仅 protected CI 可授权），以及若要翻转所需的 CI 产物清单。

## 4. 验证步骤（完成后执行）
```bash
bash tests/e2e-diff/run_s_scripts.sh            # 期望 rc=0，assertions.txt 无 FAIL
python3 tests/go-parity/parity/scripts/check_evidence_hygiene.py --mask tests/e2e-diff/evidence/<RUN_ID>
cd tests/go-parity/parity && python3 scripts/check_release_gate.py  # 仍 rc=2，记录输出
gofmt -l ./cmd ./internal; go vet ./...; go test ./...
git status --short
```
卫生检查若报公网 IP：在证据里做值级 mask（`collect/sanitize.py` 或直接替换为 `<ipv4>`），不改 allowlist 放水。

## 5. 明确不做
- 不执行 `tcp.sh` / `superspeed.sh` 交互菜单本体（会换内核 / 需要 tty 交互），只做下载 + 语法校验。
- 不做真实公网 CA 签发；S7 签发与 S5 真实 CA 场景记 BLOCKED。
- 不翻转 F01–F28 状态，不绕过 `GITHUB_ACTIONS` 检查。
