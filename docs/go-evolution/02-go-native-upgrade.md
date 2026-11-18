# 第二阶段：Go 原生能力升级

- 分支：`work/go-evolution-audit-20261118`
- 基线：`develop/go-native` = `d4858a1150d3f83202e95aa9dfea2244832c8b3e`
- 本轮实跑：2026-11-18，镜像 `idleleo-e2e:24.04`（image id `sha256:1e031bdf2d18…`），Xray `26.10.31`
- 代码状态：`d96deffe` + 本阶段工作区改动（提交见本阶段 commit）
- 证据目录：
  - `tests/e2e-diff/evidence/goevo-p2-20261118-p2/`（首次实跑，30 pass / 10 fail，用于暴露缺陷）
  - `tests/e2e-diff/evidence/goevo-p2-20261118-p2b/`（修复后，40 pass / 0 fail）

## 1. 结论

1. `doctor` 增加 `--deep`：状态扩展为 `ok/warn/fail/skip/unknown`，每条检查带 `method/evidence/cause/suggestion`。深度探测真实建立 TCP 连接；TLS 可握手时给 `tls-handshake`；Reality 无法在不持有客户端密钥的情况下证明，明确返回 `unknown`，不伪造成功。
2. `backup create/verify/restore` 具备 `manifest.json`（含 `sourceArch/sourceVersion/managedResources/restoreLimits`、逐文件 SHA-256）、`--dry-run` 差异（add/replace/unchanged）、重复条目/路径逃逸/大小上限拒绝、恢复前自动备份与暂存回滚。
3. `repair --dry-run/--fix-lock` 只处理可安全自愈的项（陈旧锁、权限），对损坏配置明确报告“not valid JSON”，不自动发明配置。
4. `update preflight --component xray|nginx --manifest …` 实现四层证据：`installable`、`config-parses` 真实执行；`service-starts`、`client-connects` 固定 `NOT_RUN` 并说明原因。新增退出码 `7`（构件不可安装 / 配置不兼容）与错误 `ErrArtifact`、`ErrConfig`。
5. 实机故障注入中发现并修复两个真实缺陷：备份归档在 gzip member 之后追加数据仍被 `verify` 接受；同一秒内连续恢复会因预恢复备份重名而失败。

## 2. 环境与真实性

| 项 | 事实 |
|---|---|
| 宿主机 | macOS arm64，无 Go 工具链 |
| 构建 | `golang:1.27.4`，`CGO_ENABLED=0 GOFLAGS='-mod=vendor -buildvcs=false'` |
| 实机 | `idleleo-e2e:24.04`，systemd、真实 Xray 26.10.31、nginx |
| 安装 | 容器内 `idleleo xray install --mode reality --binary /usr/local/bin/xray`，`systemctl is-active xray=active` |
| 网络 | 安装所需的 Xray 二进制由 seed 提供；本阶段不依赖公网 |
| 证据卫生 | `tests/go-parity/parity/scripts/check_evidence_hygiene.py`：0 findings；含私钥的备份归档与 `/bin/true` 副本已从证据中移除 |

证据只保留命令、退出码、脱敏后的 JSON 与断言，不包含私钥、UUID 明文、主机路径或公网地址。

## 3. 实现内容

### 3.1 doctor

- 新检查：`nginx`（配置 `-t`）、`connectivity`（仅 `--deep`）、证书 SAN 与到期。
- `--deep` 解析 inbound，最多探测 3 个端点（TCP 2s、TLS 3s）。关闭端口 → `fail`；Reality → `unknown` + `evidence=tcp-connect`。
- JSON 增加 `summary.unknown`，文本输出使用大写状态并附带建议。

### 3.2 backup / restore

- 清单写入架构、版本、受管资源、恢复限制；归档权限 `0600`。
- `verify` 拒绝重复条目、路径逃逸、超限文件，并消费完 gzip 流以校验尾部 CRC、拒绝尾随数据。
- `restore --dry-run` 比较现有文件与条目 SHA-256，输出 `add/replace/unchanged`，不写盘。
- 真实恢复先创建 `pre-restore-*.tar.gz`（同名冲突自动追加序号），再暂存替换；失败回滚。

### 3.3 repair

- 固定检查集（锁、权限、配置 JSON、二进制可执行、服务状态）。
- `--dry-run` 只报告 `actions/remaining`；`--fix-lock` 仅删除超过阈值的锁文件。

### 3.4 update preflight

| 证据层 | 实现 | 失败行为 |
|---|---|---|
| `installable` | 清单校验、size+SHA-256、ELF/tar.gz 格式、ELF 架构匹配、版本方向 | 降级 rc4、摘要 rc5、构件 rc7 |
| `config-parses` | 临时目录写入候选，执行 `xray -test -config <现有配置>`；nginx 解包后以候选二进制 `-t` 校验现有配置 | rc7，`compatible=false` |
| `service-starts` | 预检不替换构件、不重启服务 | 固定 `NOT_RUN` |
| `client-connects` | 需要已激活服务与真实客户端 | 固定 `NOT_RUN`，提示 `doctor --deep` |

预检全程不写入 root，也不创建备份；实机断言校验了已安装二进制哈希不变。

## 4. 实机证据

命令：

```bash
E2E_KEEP=1 E2E_RUN_ID=20261118-p2b bash tests/e2e-diff/run_p2_gonative.sh
```

| 步骤 | 注入/操作 | 断言结果 |
|---|---|---|
| E1 | 健康根运行 `doctor` | rc0、`healthy=true` |
| E2 | `doctor --deep` | rc0、`evidence=tcp-connect`、Reality 为 `unknown` |
| E3 | `backup create/verify` | rc0、清单含限制项、无 `PRIVATE KEY`、归档 `0600` |
| E4 | 配置漂移 + `restore --dry-run` | rc0、报告 `replace`、漂移文件哈希未变 |
| E5 | 真实 `restore` | rc0、恢复出归档哈希、生成预恢复备份 |
| E6 | 归档尾随垃圾 | `verify`/`restore` 均拒绝，配置未变 |
| E7 | 3 小时前陈旧锁 | `doctor` warn；`repair --dry-run` 报告且保留；`--fix-lock` 清除后健康 |
| E8 | 写入非法 JSON | `doctor` rc1；`repair` 报告“not valid JSON”；`restore` 恢复为合法 JSON |
| E9 | 用已安装二进制做候选 | rc0、`installable=pass`、`config-parses=pass`、服务/客户端 `NOT_RUN` |
| E10 | 非 ELF 候选 | rc7 |
| E11 | 摘要不匹配 | rc5 |
| E12 | 可安装但无法提供版本信息的 ELF 候选 | rc6、`rolledBack=true`、旧二进制哈希恢复、服务状态不变 |
| E13 | 全部故障后复查 | `doctor` rc0 |

汇总：`40 pass / 0 fail`（`…/p2b/summary.md`）。

## 5. 实跑发现的缺陷与修复

首次运行 `…/p2` 为 `30 pass / 10 fail`，根因如下：

1. **归档尾部篡改未被发现**：`tar.Reader` 在结束块即返回 EOF，`verify` 未继续读取 gzip 流，追加在 member 之后的数据被忽略。修复为读取剩余流，尾随数据或 CRC 错误均拒绝；新增 `TestVerifyRejectsTrailingGarbage`。
2. **同秒恢复预备份重名**：`pre-restore-<秒>.tar.gz` 使用 `O_EXCL` 创建，同一秒第二次恢复失败（E5 后紧接 E8）。修复为冲突时追加序号，最多 100 次；新增 `TestRestorePreBackupNamesAreUniqueWithinASecond`。
3. 驱动脚本把 `xray version` 第二行 `unified` 拼进版本号，导致清单 JSON 非法。属测试脚本缺陷，已改为只取首行；产品 `LoadManifest` 的拒绝行为正确。

## 6. 未覆盖与限制

- `service-starts` / `client-connects` 在预检中恒为 `NOT_RUN`：这是设计约束，真正的服务启动与客户端连接由 `update xray|nginx` 激活后的 `doctor --deep` 负责。
- nginx 候选的 `config-parses` 仅有单元测试（真实 tar.gz + 现有配置）；本轮实机只覆盖 xray。
- 预检不检查运行中流量无损；热变更属第三阶段。
- 未在公网主机执行；所有结论均来自一次性 Docker 实机。

## 7. 复现

```bash
# 单元与静态检查
docker run --rm -v "$PWD":/src -w /src -e GOFLAGS='-mod=vendor -buildvcs=false' \
  golang:1.27.4 sh -c 'go vet ./... && go test ./...'

# 实机（会创建并默认删除容器）
E2E_KEEP=1 E2E_RUN_ID=local-p2 bash tests/e2e-diff/run_p2_gonative.sh

# 证据卫生
python3 tests/go-parity/parity/scripts/check_evidence_hygiene.py \
  tests/e2e-diff/evidence/goevo-p2-*/
```
