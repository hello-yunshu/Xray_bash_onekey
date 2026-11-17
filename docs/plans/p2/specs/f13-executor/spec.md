# F13 执行器与组件更新规格（`update xray|nginx`）

状态：待实施（Spec Mode，2026-11-17）。目标级别 CONTAINER_VERIFIED。
对应 Bash：`install.sh` 的 `xray_update()`（6026）、`health_check_xray_update()`（7386）、
`nginx_update()`（7491）、`rollback_nginx_update()`（7338）、`version_gt`。
Go 现有 `idleleo update` 只更新 Go 自身（`internal/release`），不等价。

## 1. 范围

新增 `idleleo update xray` / `idleleo update nginx`，用一个显式清单驱动组件升级：
哈希校验、拒绝降级、备份、健康检查、失败自动回滚。不实现 Bash 的交互确认、
多 CDN 探测与 package-manager 安装器，也不更新 `install.sh` 本身。

### 1.1 清单契约

`--manifest <path|http(s)://>` 指向 JSON：

```json
{
  "schemaVersion": 1,
  "component": "xray",
  "version": "1.8.24",
  "sha256": "<64 hex>",
  "sizeBytes": 123456,
  "url": "https://.../xray"
}
```

- `component` 必须是 `xray` 或 `nginx`，且与子命令一致。
- `version` 允许可选的 `v` 前缀，必须是纯数字点分版本（`^[vV]?[0-9]+(\.[0-9]+)*$`）。
- `sha256` 必填 64 hex；`sizeBytes` > 0 时同时校验长度；`url` 支持 http(s) 或
  绝对文件路径。下载上限 64 MiB，清单上限 1 MiB。
- nginx 的 `url` 指向真实 `.tar.gz`，包内根为 `nginx/`；复用
  `internal/nginx.Extract`（路径穿越防护）与 `internal/nginx.VerifyBinary`。

### 1.2 事务

`internal/componentupdate/update.go`：

1. 读取并校验清单；`component` 不匹配、JSON 损坏、字段缺失 → rc=3。
2. 读取已安装版本：xray 执行 `<root>/usr/local/bin/xray version`；nginx 执行
   `<root>/usr/local/nginx/sbin/nginx -v`（解析 `nginx version: nginx/X`）。
   已安装版本为空视为首次安装（`previousVersion=""`）。
3. 降级判定：新版本数值小于已安装版本 → rc=4，零写盘；相等 → `action=reinstall`
   允许。
4. 下载/读取资产到内存，校验 size 与 sha256；不符 → rc=5，零写盘。
5. 备份：
   - xray：复制现有二进制到
     `<root>/etc/idleleo/backup/xray-<installed>-<unixnano>`（保留 0755）；
   - nginx：`os.Rename(<root>/usr/local/nginx, backupDir)`；跨设备 rename 失败 →
     rc=13 且不动任何文件。
6. 激活：
   - xray：写入 `<root>/usr/local/bin/.xray.new`（0755）→ `os.Rename` 覆盖；
   - nginx：解包到 `<root>/usr/local/.nginx-new`，校验包内 `sbin/nginx` 可执行，
     `os.Rename` 到 `<root>/usr/local/nginx`。
7. 健康检查（激活后）：
   - xray：`version` 输出匹配期望版本；若运行配置存在，再执行
     `run -test -config <config>` 必须 race-free（不启动服务）；
   - nginx：`<bin> -t -p <root>/usr/local/nginx/ -c <root>/usr/local/nginx/conf/nginx.conf`。
   失败 → 恢复备份（xray 复制回原文件；nginx 删新目录、rename 备份回原位），
   返回 rc=6 且 `rolledBack=true`。恢复也失败 → rc=10。
8. 重启：仅当 `--root /` 且 `/run/systemd/system` 存在时
   `systemctl restart xray|nginx`；沙箱根跳过并写 warning（`restarted=false`），
   与 F10 一致。`--no-restart` 禁止真实重启。
9. 报告 JSON：`component/previousVersion/newVersion/action/sha256/sizeBytes/
   backupPath/verified/health/restarted/rolledBack/warnings`。

`internal/componentupdate/manifest.go`：`Manifest`、`LoadManifest(ctx, source)`、
`FetchAsset(ctx, m)`、`CompareVersions(a,b)`、错误值
`ErrManifest`、`ErrComponentMismatch`、`ErrDowngrade`、`ErrDigestMismatch`。

### 1.3 CLI 与退出码

- `internal/cli/update.go` 的 `updateCommand` 增加 `xray`、`nginx` 分支；
  新文件 `internal/cli/componentupdate.go` 解析 `--manifest`、`--json`、
  `--container`、`--no-restart`。
- `flags.go` 新增 `"update xray"`、`"update nginx"` 白名单。
- 退出码：0 成功；2 语法/未知旗标/缺 `--manifest`；3 清单不可读或不合法；
  4 降级拒绝；5 摘要/大小不符；6 健康失败但已回滚；10 回滚失败；13 IO/跨设备。
- 真实根写入门禁复用 `host.RequireSystemWrite`（`--container` + 环境令牌）。

## 2. 设计决定

- D1 清单必须自证 component 与摘要，不接受「版本号不同即更新」。
- D2 先备份后激活；任何健康失败自动回滚，不做交互询问。
- D3 同版本允许重装（Bash 同样允许），但仍校验摘要并重建备份。
- D4 降级显式 rc=4；Bash 打印警告后 rc=0 的分支记为 approved-difference。
- D5 nginx 只替换 `usr/local/nginx` 整目录；不复刻 Bash 的 `_backup_<ver>` 命名。
- D6 沙箱根不重启服务；真实重启只在真实 systemd 主机发生。

## 3. 分类

| 项 | 分类 | 说明 |
|---|---|---|
| 版本比较 | aligned | 与 Bash `version_gt` 的数值比较表一致 |
| 同版本重装 | aligned | 两侧都允许 |
| 降级 | approved-difference | Go rc=4 且零写盘；Bash 警告后 rc=0 |
| 摘要校验 | approved-difference | Go 强制 sha256/size；Bash 依赖上游安装器 |
| 健康失败 | approved-difference | Go 自动回滚 rc=6；Bash 交互层回滚 |
| 备份命名/位置 | new-go-behavior | `etc/idleleo/backup/<component>-<ver>-<ts>` |
| 重启行为 | approved-difference | Go 仅真实 systemd 重启；Bash 总是停/启 |

## 4. 场景（`tests/go-parity/parity/features/F13_test.py`）

- S1 xray 成功：旧脚本 `version` 1.8.20，环回 HTTP 清单与候选脚本 1.8.24；
  rc=0、文件字节等于候选、备份保存旧字节、`restarted=false` + warning。
- S2 同版本重装：`action=reinstall`，仍生成新备份。
- S3 降级 1.8.24 → 1.8.10：rc=4，二进制与备份目录零变化。
- S4 sha256 不符：rc=5，零写盘。
- S5 sizeBytes 不符：rc=5，零写盘。
- S6 健康失败：候选 `run -test` 退出 1 → rc=6、`rolledBack=true`、旧字节恢复。
- S7 nginx 成功：真实 nginx 树 + tar.gz 内的版本化 shim；
  `nginx -t` 通过，目录被替换、备份保留。
- S8 nginx 健康失败：shim `-t` 退出 1 → rc=6，整树摘要恢复。
- S9 清单门禁：缺 `--manifest`/坏 JSON/错 component/非点分版本 → rc=3 零写盘；
  未知旗标、缺值 → rc=2；真实根未确认 → rc=2。
- S10 Bash 基线：提取 `version_gt` 与 Go `CompareVersions` 跑同一版本表，
  断言结果一致；其余差异写入 `baseline-compare.json`。

## 5. 缺口

- 未在真实 VPS 上更新真实 Xray/Nginx，也未做 systemd 重启。
- nginx 资产只验证本 fixture 的 tar.gz 结构；真实 release manifest/签名不在本轮。
- 未覆盖 Bash 的交互确认、CDN 回退、测试版本回退层（Layer 2/3）。
- 跨设备目录 rename 只报 rc=13，不自动降级为复制。

## 6. 文件清单

新增：`internal/componentupdate/{manifest,update,manifest_test,update_test}.go`、
`internal/cli/componentupdate.go`、
`tests/go-parity/parity/features/F13_test.py`、本 spec 三件套。
修改：`internal/cli/update.go`、`internal/cli/flags.go`、`internal/i18n/i18n.go`、
`docs/go/FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md`、
`tests/go-parity/parity/features/README.md`。

## 7. 验收与审批

- 固定镜像双跑全绿；证据 `tests/go-parity/evidence/f13-2026-11-17`；
  hygiene 0 findings；单元测试 `go test ./internal/componentupdate ./internal/cli`。
- 需要用户批准：新增 `update xray|nginx` 命令面、清单格式、rc=4/5/6/10/13 语义。
