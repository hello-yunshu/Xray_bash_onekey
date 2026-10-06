# Xray 阶段 3 修复与验证记录

日期：2026-10-06
分支：`fix/audit-xray-safety`
基线：`48513752f86e30d5890a261bf1013e0a746c6b7a`
Rill canonical 来源：`16112bb146c048dd8c3c3b3ce9a60001ae233af1`
canonical digest：`13cc1b48e231950ae598f5038303321e2ae59c0147e7a1da218c6765654de0a2`
bundle SHA-256：`2521a6ac90221ea96dea65e0138595bf42cc7bdddf444695a9f03f42336fb18c`

## XRA-06 — GeoData 事务更新

改动：`scripts/geo_update.sh` 将 latest 解析为单一 release tag，并从同一不可变 tag 获取 geoip、geosite 与各自 SHA256SUMS；校验文件名、SHA-256、真实 Xray 临时配置解析结果后才发布。更新时先保存两份旧资产和版本 metadata；任一 rename、重启或 active 检查失败都会恢复旧 generation 并返回非零，无法确认恢复时保留 recovery staging 并记录 RECOVERY REQUIRED。使用与 Xray 更新相同的 flock；inactive 服务保持 inactive。下载单文件上限 100 MiB、操作有 600 秒总时限。

`scripts/traffic_blocker.sh` 的手动和自动入口统一委托给事务更新程序，避免并行的旧写路径和重复重启。

回归：新增 `.github/test/test_geo_update_transaction.py`，9 项全部通过：mv 失败、第二个下载失败、非 DAT/HTML、checksum 错误、metadata rename 失败、重启失败回滚、tag 固定、inactive 状态和共享锁。失败桩通过生产 shell 入口执行。

可信边界：上游 SHA256SUMS 与 DAT 来自同一个 GitHub immutable release，并通过 HTTPS 获取；上游没有独立签名，因此这里只承诺 HTTPS 信任边界和 tag 绑定，不声称发布者签名验证。

## XRA-10 — Shell Release 准入

改动：`.github/workflows/publish-shell-version.yml` 先固定 dispatch candidate SHA 和 canonical pin，再调用 reusable `test-install.yml`。资格工作流必须在 exact candidate 上完成安全回归、安装模式矩阵、升级/回滚及 canonical payload 校验，gate 对比 candidate SHA、canonical commit/digest 和 bundle SHA。候选及资格工作流只有 contents:read；仅依赖二者成功的最终 release job 获得写权限/token。Release manifest 记录 candidate、installer/bundle SHA、canonical commit/digest 和 qualification run id；现有 Release 重跑校验资产摘要、manifest、资格 run/job 和 tag 目标 SHA。API metadata promotion 位于 Release 验证之后。

回归：`.github/test/test_release_automation.py` 10 项通过，覆盖 reusable exact-SHA 资格、最小权限、写入顺序及候选/资格 job 不持有发布凭证。`.github/test/test_convergence.py` 4 项通过。GitHub Actions `actionlint` 对发布与资格工作流通过。

准入状态：已按用户要求给三份保留的审计执行文档加入精确例外：`AUDIT_2026-10-05/00-启动修改.md`、`AUDIT_2026-10-05/01-Rill源头运行与升级安全.md`、`AUDIT_2026-10-05/02-Rill源头备份与隐私.md`。例外绑定仓库相对路径和 LF 规范化 SHA-256；改名、改内容或新增 prompt-like 文档仍由 hygiene gate 拦截。回归验证了三份原件获准，改名及追加内容均不获准。另修复 `scripts/run_python_tests.py` 未将仓库根目录加入 `PYTHONPATH` 的启动缺陷。现有 Rill 历史 hygiene、47 个 Python 测试模块、包校验和与 canonical manifest 检查均已通过。本地资格检查完整通过，但 GitHub hosted qualification workflow 尚未触发，因此仍没有真实 hosted run 记录。

## 交叉验证与测试环境

通过的 Xray 检查：

- `bash -n scripts/geo_update.sh scripts/traffic_blocker.sh`
- `python3 .github/test/test_geo_update_transaction.py -v`：9/9
- `python3 .github/test/test_release_automation.py`：10/10
- `python3 .github/test/test_convergence.py`：4/4
- `python3 scripts/verify_rill_host_contract.py --repo . --contract repository_files/rill_integration/HOST_CONTRACT.json`：通过。首次发现工作树中旧 host contract 摘要与 install.sh block 不符；以仓库自带 generator 更新合同后验证一致，digest `2508a96e79ce53b2354f345e2dded74774a7a2f1242af5a0628a703f09c0d8e4`。
- 使用 Rill `scripts/sync_xray_host_contract.py --xray ../Xray_bash_onekey --xray-sha 67aa108a35aad211a20dfb396f1a1f59c6d8cd20` 同步来源 provenance、配置与 bundle；来源锚点记录该 Xray commit 中的 install.sh Git blob。新增 `tests/test_host_contract_line_endings.py`，LF/CRLF 表面等价回归通过。
- 新增同步器完整 40 位 commit 校验与回归；`scripts/verify_xray_upstream_anchor.py` 从已推送 Xray commit 验证了 install.sh blob 和 host contract。短 SHA 首次写入被发现后已修正为完整 commit `67aa108a35aad211a20dfb396f1a1f59c6d8cd20`。
- canonical `verify_xray_payload.py`：65 个文件和 bundle 匹配；source manifest `--check` 与 no-build gate 通过。
- 在 WSL ext4 临时副本执行安装/卸载事务、Rill 集成和运行模式、Xray 更新回滚、Nginx 更新回滚测试：分别通过 17、19、22、22、51、28 项；运行目录为临时副本，清理仅作用于测试临时数据。

未执行/未通过：

- Rill WSL ext4、nobody 用户隔离资格运行通过：公共历史 hygiene gate、47 个 Python 测试模块、package sums 和 canonical manifest 检查通过。工作树包校验和检查另在原 Rill 工作树直接通过（325 项）。
- 完整的 hosted Release qualification 尚未执行；必须由 GitHub Actions 在精确候选 SHA 上运行后，才可认定发布资格完成。
- 真实 systemd/PID1、DAC 和发行版 hosted 安装矩阵未执行；需要 GitHub hosted qualification workflow。
- 未创建 Release、推送 API 版本或合并 PR。
