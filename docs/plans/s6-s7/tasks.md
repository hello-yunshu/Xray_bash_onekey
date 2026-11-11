# S6 / S7 任务清单（tasks）

> 规格见 [spec.md](./spec.md)。按顺序执行；每项完成即更新状态并在 S6 阶段单独报告。

## 前置（已完成）

- [x] S6-0 vendor 卫生核实：`git ls-files vendor` 812 个文件、无 `* 2.*` 副本；`gofmt/build/vet/test` + 卫生门禁全绿。

## S6（安全与流量）

- [ ] **S6-3 版本元数据 Ed25519 签名**
  - 文件：`install.sh`（344 附近常量、`fetch_versions_json` 后四个新函数、`load_versions` 调用点）、新增 `scripts/sign_json_ed25519.sh`、新增 `.github/test/test_versions_signature.sh`
  - 判据：注入篡改/截断/错前缀/强制 ≥3.4.0 无签名 → 全部非 0；正确签名与 3.3.6 兼容期 → 0
  - 验证：`bash -n install.sh`、新测试、`test_version_loading.sh` 回归
  - 依赖：无

- [ ] **S6-2 helper 下载 sha256 校验收敛**
  - 文件：`install.sh`（`download_script_file` 第三参数、`xray_stats`、`ensure_sub_script`、helper 策略函数）、新增 `.github/test/test_helper_checksum.sh`
  - 判据：错 sha / 缺期望值 → 非 0 且不落盘；正确 sha → 0
  - 验证：新测试 + `bash -n install.sh`
  - 依赖：S6-3（复用元数据字段读取）

- [ ] **S6-1 TCP 入口接线**
  - 文件：`install.sh`（`bbr_boost_sh`、`-tcp`、菜单 28）、新增 `.github/test/test_tcp_entry.sh`
  - 判据：默认分支零网络请求；`--legacy` 需显式确认；无 `idleleo` 时不下载
  - 验证：新测试 + `bash -n install.sh`
  - 依赖：S6-0

## S7（辅助工具）

- [ ] **S7-1 `idleleo speedtest`**
  - 文件：新增 `internal/speedtest/speedtest.go` + `_test.go`、`internal/cli/speedtest.go`、`internal/cli/cli.go` 注册
  - 判据：`--json` schema 稳定；超时/端点失败非 0；不下载脚本
  - 验证：`go test ./internal/speedtest ./internal/cli`
  - 依赖：无

- [ ] **S7-2 `tcp.sh` 退役**
  - 文件：`install.sh`（11023-11027 去下载、菜单 28 文案）、扩展 `.github/test/test_tcp_entry.sh`
  - 判据：无 `tcp.sh` 远程 URL；legacy 且本地缺失 → 非 0
  - 依赖：S6-1

- [ ] **S7-3 `superspeed.sh` 退役**
  - 文件：`install.sh`（15707-15710、菜单 33）、扩展 `.github/test/test_tcp_entry.sh`
  - 判据：无 superspeed 下载 URL；假 `idleleo` 证明改调 `speedtest`
  - 依赖：S7-1

- [ ] **S7-4 `acme.sh` 原子退役（单 commit）**
  - 文件：`install.sh`（339、7475-7479、7888-7900、8745-8754、8860-8937、10073-10123、11241-11242、14024、14362）、`internal/schedule`（cert-renew 驱动）、新增 `.github/test/test_acme_retire.sh`
  - 判据：新装无 `get.acme.sh`；`IDLELEO_ACME_LEGACY=1` 可回退；卸载保留 `/root/.acme.sh`
  - 依赖：S7-1

- [ ] **S7-5 manifest 签名与校验**
  - 文件：`internal/release/signature.go` + `_test.go`、`internal/release` 校验入口、`scripts/sign_json_ed25519.sh` 复用
  - 判据：篡改 manifest → 校验失败；无签名字段 → 可识别 warning；补签后通过
  - 依赖：S6-3（脚本与格式）

## 收尾

- [ ] HEAD 复跑全部证据（`repo_commit` == HEAD），写入 `tests/go-parity/evidence/s6-s7-2026-11-12/`
- [ ] 同步 `docs/release/KNOWN_LIMITATIONS.md`、`docs/go/DECISIONS.md`
- [ ] 确认 `feature_contracts.json` / `check_release_gate.py` 零 diff，28 项仍 PENDING
- [ ] 推送 `develop/go-native` 并报告（S6 逐项、S7 收尾一次性）
