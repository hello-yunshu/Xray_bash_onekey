# S4 Reality 握手参数编辑（已批准）

## 0. 结论与范围

`publicKey` 是 `privateKey` 的派生值，服务端无法单独编辑；`fp`/`spx` 是客户端链接参数，
写进服务端配置没有意义。因此 S4 只做三件事：

1. `privateKey` 轮换（强确认 + 备份旧链接 + 真实握手验证 + 回滚探通）。
2. `shortIds` 增 / 删 / 列（追加 → 客户端切换 → 删除旧 id 的零断线路径）。
3. `fp`/`spx` 持久化为**链接偏好**，只影响分享链接，不影响服务端配置，不重启不 reload。

同时覆盖 `reality-balance` 的 `edit`：只改 Xray inbound 的 `realitySettings`，不碰 upstream 文件。

## 1. 已拍板的决策

| # | 决策 |
|---|---|
| D1 | `reality-balance` 可编辑；`frontDir=""`，不写/不 reload Nginx；改前改后 `hashTree(nginxDir)` 必须相同，不同即回滚报错 |
| D2 | `fp`/`spx` 存 metadata 的 `shareLinkOnly` 字段；字段名与输出文案都写明 `share link only; server config unchanged`；纯链接偏好编辑不写 runtime、不重启、不 reload，配置 SHA 不变 |
| D3 | shortId 接受 1–16 偶数 hex（含空串元素）；`--short-id ''` 是显式清空，`--short-id-auto` 才自动生成；`--short-id <id>` 追加，`--short-id-remove <id>` 删除，`--short-id-list` 只读列出每个 sid 的链接 |
| D4 | `privateKey` 轮换要求键入确认串 `rotate-reality-key`（非 TTY 用 `--confirm-reality-rotation`）；`--yes` 不够；轮换前打印旧链接并写入备份 `old-share-uri.txt`；输出明确说明断线窗口不可避免 |
| D5 | 轮换 / shortId 变更后必须用真实 xray 客户端拿新链接握手成功；失败自动回滚并记 `failurePoint: reality-handshake`；回滚后再用旧链接探通 |
| D6 | E7/E8 实跑 PASS 后才更新矩阵声明 |

## 2. 代码落点

### 2.1 `internal/xraycfg/xraycfg.go`
- `Spec` 新增 `ShortIDs []string`（nil=安装自动生成；非 nil 空=显式清空）、
  `LinkFingerprint`、`LinkSpiderX`（仅链接）。
- `buildConfig` 输出 `shortIds` 列表；`validShortID` 接受空串。
- `buildShareURI`：`fp=linkFingerprint(spec)`、`sid` 做 URL 编码、有值时输出 `spx=`。
- `buildClash`：`client-fingerprint` 与 `spider-x` 同步。

### 2.2 `internal/xraycfg/edit.go`
- `EditRequest`：`ShortIDSet/ShortID/ShortIDAuto/ShortIDRemove`、`LinkFingerprint/LinkFPChanged`、
  `LinkSpiderX/LinkSpiderXSet`、`RotatePrivateKey`、`ListShortIDs`。
- `EditRuntime`：先算旧链接（含 metadata 偏好）→ list-only 早返回 →
  `applyEditRequest` → 生成 → diff 白名单（Reality 凭据只允许
  `inbounds[0].streamSettings.realitySettings` 前缀）。
- `applyEditRequest`：三个 shortId 动作互斥；`NewRealityKeys()` 轮换；
  fp 白名单；spx 必须以 `/` 开头。
- `disconnectProne` 增加 `reality-private-key`、`short-id-remove`、`short-id-clear`。

### 2.3 `internal/deploy/edit.go`
- `EditSpec.RotationConfirmed`；`EditReport` 增加 shortIds/链接/旧链接/探针/failurePoint/upstream 哈希。
- 纯链接偏好：`LinkPrefsChanged && !runtimeChanged` → 只写 metadata，配置不写、服务不动。
- balance：`frontDir=""`，跳过 Nginx 写与 reload；`hashTree` 前后比对，变化即回滚。
- `failAt("reality-handshake")`：回滚后用 `OldShareURI` 再跑一次真实握手，写
  `RealityRollbackProbe`；失败则升级为“回滚失败”。
- 轮换时备份 `old-share-uri.txt` 并写 manifest。

### 2.4 `internal/deploy/reality_probe.go`
- `hashTree(dir)`：文件名排序 + sha256。
- `runRealityHandshake`：解析分享链接 → 临时 client JSON（socks + vless/reality）→
  隧道内 TLS 握手到 `example.com:443` → 再向 `example.com:80` 发 HTTP 请求并要求
  `Example Domain`。只做握手会被 Reality 回退欺骗（未认证流量同样能完成握手），
  HTTP 请求才证明 VLESS 层认证通过；失败带 stderr 尾部。
- `verifyRealityHandshake` 变量作为单测 seam。

### 2.5 `internal/store/metadata.go`
- `ShareLinkOnly *ShareLinkPrefs`：`fingerprint`、`spiderX`，注释明确仅链接装饰。

### 2.6 `internal/cli/xrayedit.go` / `flags.go`
- 新 flag 白名单；`flagPresent` 识别 `--short-id ''`。
- list-only 打印每个 sid 的链接。
- 轮换打印旧链接 + 断线警告 + 键入确认串。
- 报告输出 `short-ids=`、`link-preferences: ... (share link only; server config unchanged)`、
  `reality-probe:`、`reality-probe-rollback:`、`failurePoint=`、`upstream: sha256=... unchanged=...`。

## 3. 验证

### 3.1 单测
`internal/xraycfg/reality_edit_test.go`：
- 追加保留旧 sid，新链接用新 sid；
- `''` 清空；auto 8 hex；remove；
- fp/spx 不改 runtime 且链接含 `fp=firefox` / `spx=/`；
- 轮换保留 shortIds、新旧链接 pbk 正确；
- `validShortID` 空串 / 16 hex。

`internal/deploy/edit_test.go`：
- `TestEditRealityBalanceLeavesUpstreamTreeUntouched`：用 `Generate` 产出的
  balance primary 配置 + upstream 片段，编辑 shortId 前后 `hashTree` 相同，
  报告 `upstreamUnchanged=true` 且 SHA 等于编辑前。

### 3.2 E2E（证据先行）

**E7（shortId 零断线过渡，base M1）**
1. 旧链接（sid0）握手成功；
2. `--short-id-auto` → rc=0，`shortIds` 含 sid0+sid1，新链接 sid=sid1；
3. 旧链接、新链接都握手成功（旧链接不断）；
4. `--short-id-remove sid0` → rc=0；
5. 旧链接握手失败，新链接成功；
6. 记录两次编辑都触发 Xray 重启（重启语义，不是 reload）。

**E8（privateKey 轮换 + 回滚，base M1）**
1. `--rotate-reality-private-key` + 键入确认串 → 新链接握手成功、旧链接失效；
2. 备份目录含 `old-share-uri.txt`，内容等于轮换前链接；
3. 故障注入：systemd drop-in 让重启加载旧配置副本（重启成功但新凭据未生效）→
   真实握手失败 → `failurePoint=reality-handshake` → 自动回滚 →
   `reality-probe-rollback=ok`（旧链接探通）；
4. 清理 drop-in 后服务 active，L4 仍通。

### 3.3 通过标准
- E7/E8 的 `checks.json` 全 PASS、`allPassed=true` 才允许在 `tasks.md` 把 S4 标为已证。
- 失败只登记为失败证据，不改矩阵声明。

## 4. 文档
- `behavior-diff.md` 新增 G18：bash 强制 16 hex、Go 自动生成 8 hex；不对齐的原因
  （长度不参与安全，强制反而限制熵的可用空间）。
- 推荐流程写入 S4 文档/tasks：追加新 id → 客户端切换 → 删除旧 id。

## 5. 约束
- 不新开子命令，全部挂在 `xray config edit`。
- 不动 bash 脚本；bash 根继续拒绝编辑（G17 不变）。
- `--no-probe` / `--no-restart` 跳过探针时必须显式标 `skipped`，不能当通过。
