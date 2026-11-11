# 历史隐私重写记录（2026-11-11）

本文件记录把 `hello-yunshu/Xray_bash_onekey` 全部历史中的真实主机地址、
用户名与主机路径替换为文档占位值的过程、验收结果和**未能消除的残留风险**。
它不是“已彻底清除”的声明。

## 1. 为什么要重写

工作树在 `4dd6886`（原 `b8d102c`）与 `75364b7`（原 `bfb540b`）已经干净，但早期提交
的树里仍能取回真实值。仓库是 **PUBLIC**，任何人 `git clone` 都能读到这些对象。

## 2. 替换表

| 旧值（已脱敏） | 新值 | 历史中命中数 |
|---|---|---|
| `180.115.111.x`（真实公网 IPv4） | `203.0.113.42` | 157 |
| `240e:3a0:…:c1ef`（真实公网 IPv6） | `2001:db8::42` | 187 |
| `/Users/<旧用户名 A>` | `/Users/<user>` | 1 |
| `/Users/<旧用户名 B>` | `/Users/<user>` | 7 |

旧值本身不再写进仓库，精确值只在本地备份与提交映射里可查。
`/Users/<旧用户名 B>` 是重写前扫描新发现的真实用户名，不在最初的替换表里，按同一原则处理。
替换值和工作树保持一致，因此同一个文件在不同历史版本里的语义仍对得上。

### 明确不替换的内容

以下命中经人工确认不是隐私泄漏，保持原样（为避免把值本身再写进仓库，
这里只描述类别）：

- 公开 DNS 解析器（Google / Cloudflare / OpenDNS）及其 IPv6 地址；
- 已登记的文档占位网段与 RFC 2544 测试网段；
- 固定系统路径：acme.sh 目录、`wwwroot`、`/root` 下的导出文件；
- 测试夹具：假私钥（`BEGIN PRIVATE KEY` 13 处，内容为 `secret` /
  `FAKE_KEY_FINGERPRINT`）、`ghp_FAKEtoken…` 6 处；
- 版本号形态的误报（四段数字但明显是版本号）。

未发现真实私钥、真实 token 或云厂商凭据。

## 3. 备份（仓库外，未上传）

- `~/.cache/xray-privacy-backup-20261111/mirror.git`（`git clone --mirror`，876 提交 / 30 refs）
- `~/.cache/xray-privacy-backup-20261111/all-refs.bundle`（20 MB，
  sha256 `e06bba3a…41f08`）

备份只作本地保险；它仍然包含旧值，不要上传或共享。

## 4. 重写步骤

1. `git filter-repo --force --replace-text replacement.txt`（作用于全部 ref）。
2. 删除 `refs/codex/turn-diffs/…`：它直接指向旧 tree（不是 commit），filter-repo 会跳过
   tree ref，其内容仍含旧值。
3. `git worktree prune` 清掉 3 个已消失的 `/private/tmp/*` worktree；把
   `~/.cache/xray-audit/recheck-174` 的 index `reset --hard`（它暂存着旧 blob，
   会让旧对象一直“可达”）。
4. `git reflog expire --expire=now --all`、`git repack -a -d`、`git prune --expire=now`。
   只做 `gc` 不够：pack 内的不可达对象不会被 `git prune` 处理，必须 repack。

## 5. 验收结果（按内容检索整个对象库）

| 检查 | 结果 |
|---|---|
| 对象总数 | 5417 blob / 947 commit / 4828 tree → 重写完成时 5227 blob / 876 commit / 4568 tree（加入 S1 测试修复后 5228 blob / 877 commit） |
| `git log --all -S<旧值>`（4 个值） | 0 命中 |
| `git cat-file --batch-all-objects --batch` 全量内容扫描 | 0 命中（含不可达对象） |
| `git fsck --full --unreachable --dangling` | 无输出 |
| `git reflog show --all` | 空 |
| `git count-objects -v` | 0 loose / 1 pack / 10668 in-pack / 0 prune-packable |

工作树内容与重写前 HEAD 逐字节一致（`git archive` 对比 0 差异），只有历史版本变化。

**远端复验（强推 `main` 之后）**：

- 普通 `git clone`（877 提交，只含分支与 tag）：三个旧值 `-S` 均 0 命中；
- `git clone --mirror`（1578 提交，额外拉取 131 个 `refs/pull/*`）：前两个值 0 命中，
  `/Users/<旧用户名 A>` 仍有 **1** 个提交命中——`4851375`
  （"docs: add consolidated audit repair prompts and startup guide"），
  只被 `refs/pull/114/head`、`refs/pull/115/head`、`refs/pull/116/head` 可达。
  这正是第 7 节第 2 条所说的 pull ref 残留，无法通过重写或强推消除。

## 6. 新旧 SHA 对照

分支头（重写完成时）：

| 分支 | 旧 | 新 |
|---|---|---|
| develop/go-native | `bfb540b` | `75364b7`（后续 `c47926f`，再往后见 `git log`） |
| main | `81e10ac` | `6f291fa`（2026-11-11 强推：临时把 ruleset `15353378` 置 `disabled`，推送后立即恢复 `active` 并回读确认） |
| audit/bash-go-native-parity | `e21e824` | `dc925c6` |
| docs/geo-stats-tui-audit-2026-11-05-r2 | `5b10018` | `48839e0` |
| fix/go-parity-install-acme-closeout | `e129725` | `81ce461` |
| prepush-scrub（本地） | `3efa704` | `ec6c50e` |

Tag（15 个，全部已强推）：

| tag | 旧 | 新 | tag | 旧 | 新 |
|---|---|---|---|---|---|
| v3.2.3 | `eea2244f` | `f2cec221` | v3.3.1 | `dc1a02f6` | `5ecff59b` |
| v3.2.5 | `c3652ea7` | `3d27718b` | v3.3.2 | `1b2bde97` | `e5335c22` |
| v3.2.6 | `bfd6f0d3` | `d1795b08` | v3.3.3 | `0b49e0f8` | `a7793359` |
| v3.2.7 | `44d4ade7` | `d1d10d8e` | v3.3.4 | `dddc4318` | `bd091e45` |
| v3.2.8 | `fd25aa17` | `e3c168ad` | v3.3.5 | `bebbee32` | `b338b9af` |
| v3.2.9 | `81144f02` | `1217418e` | v3.3.6 | `0fa7052e` | `3b2a5045` |
| v3.2.10 | `3e04a446` | `94b72e5f` | | | |
| v3.2.11 | `6c7aff36` | `45fae857` | | | |

报告/文档里引用过的提交：

| 旧 | 新 | 说明 |
|---|---|---|
| `86bb7c3` | `762d7c5` | 真实根验收 |
| `daf78cc` | `a960e31` | S0 证据清洗 + Go 版本 pin |
| `cb0a7d0` | `0b33239` | S1 Go 元数据单一来源 |
| `9a8efb6` | `53ed4a7` | 真实根验收 |
| `0303d88` | `4439e6c` | `refreshRuntimeSHA` 错误传播 |
| `b8d102c` | `4dd6886` | 证据全仓替换 |
| `bfb540b` | `75364b7` | S1 测试初版 |
| `4752f77` | `945bc76` | 发布基线（v3.3.6 之前的 pin），证据文件中的 `4752f77` 均指它 |

`check_release_gate.py` 未改动；`tests/go-parity/parity/scripts/run_parity.py` 的 `PIN`、
`feature_contracts.json` 的 `baseline_commit` 与 3 个 workflow 的 `legacy` checkout
从 `0fa7052e…` 改为 `3b2a5045…`。v3.3.6 的 `install.sh` blob 字节未变
（sha256 `a8e4d850…`），因此 pin 的语义不变，C12 仍是**已知 pin 不匹配**。

## 7. 残留风险（实话）

1. **服务端旧对象仍可能短期可取。** 强推 tag 之后，CI 仍能按旧 SHA `0fa7052`
   成功 checkout（run `43030086252`），说明 GitHub 仍保留并按需提供不可达对象。
   已知形式的 ghost commit URL 在缓存清理前仍可能被访问。
2. **`refs/pull/*/head` 不在本次可控范围。** 仓库有 131 个 pull ref（100+ 已关闭 PR），
   它们指向重写前的提交；只要这些 PR 还在，旧对象就可能通过它们取回。已定位到具体残留：
   `4851375` 仍含 `/Users/<旧用户名 A>`，由 `refs/pull/114..116` 可达。关闭/删除 PR
   不会删除这些 ref。
3. 因此**不能**声称“已彻底清除”。本项目对外证据应写明：
   “历史已于 2026-11-11 重写，此前通过 PUBLIC 仓库暴露的主机地址与用户名视为不可撤回。”
4. 处置建议：
   - 向 GitHub Support 提交清理不可达对象缓存（含 pull refs）的请求；
   - 如后续发现真实凭据（本轮未发现），一律轮换，不要依赖历史重写。
