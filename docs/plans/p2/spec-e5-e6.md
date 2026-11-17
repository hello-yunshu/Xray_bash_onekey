# S3 E2E 证据：E5 成功路径 / E6 回滚路径（规格）

状态：待批准（批准后才动代码与矩阵声明）
适用范围：`develop/go-native`，S3（TLS 域名/证书编辑）证据补齐

## 1. 已核实的现状

- E2E 编辑场景登记在 `tests/e2e-diff/matrix.json` 的 `edits`（E1–E4），由
  `tests/e2e-diff/run_p2_matrix.sh` 的 `edit_job` 执行：先跑 base 场景的真实安装，再调
  `drivers/go_edit.sh`，最后跑改后 L4。
- `run_edit_l4` 目前把 profile/transport 写死为 `reality`，M4（TLS/ws）base 不能直接复用。
- 托管 Nginx：`/usr/local/nginx`，fragment 目录 `/etc/idleleo/conf/nginx`（`00-xray.conf`、
  `01-xray-80.conf`、`02-xray-server.conf`），服务名 `nginx`，
  `ExecReload=/usr/local/nginx/sbin/nginx -s reload`（`internal/nginx/install.go:728-745`）。
- TLS 模式下 Xray inbound 是 `security=none`（TLS 在 Nginx 终止），所以域名/证书编辑
  **不产生 runtime diff**：`deploy.EditConfig` 用 `runtimeChanged := !bytes.Equal(raw, g.Config)`
  判断，前端字段变化时不写 config、不重启 Xray，只写 Nginx 并 reload
  （`internal/deploy/edit.go:210-291`）。
- 续期链路：`schedule.SetCertTarget` 只改 `jobs.json` 的
  `certDomain/certFile/certKeyFile`，不发任何 ACME 请求；`schedule install` 用
  `--cert-domain/--cert-out/--cert-key-out` 写初始值（`internal/cli/schedule.go:47-58`）。
- 本地握手探针：`probeLocalTLS` → `127.0.0.1:<publicPort>`，要求 peer leaf DER 等于新证书、
  SAN 覆盖域名、有效期内、协商 TLS 1.3；服务未监听只记 warning，证书不符则返回错误并触发
  `fail()` 回滚（`internal/deploy/tls.go:96-176`）。
- 回滚范围：runtime config、`jobs.json`、Nginx fragment 快照，随后重启 Xray（仅当 runtime
  变化）并 reload Nginx（`internal/deploy/edit.go:352-377`）。

## 2. 发现的实现缺口（必须先修，否则 E5 断言不成立）

`writeEditBackup` 的证书备份取的是 `res.CertFile/res.KeyFile`（**改后**的新路径），
不是改前正在服务的那一对（`internal/deploy/edit.go:219-222,583-625`）。因此：

- 「旧证书进备份目录」无法成立：备份里只是新证书的一份拷贝；
- E6 回滚后也无法从备份证明旧对被保留。

修复（最小改动，不改语义）：

1. `EditConfig` 里 `extras := editBackupExtras{CertFile: base.CertFile, KeyFile: base.KeyFile, ScheduleFile: schedulePath}`
   —— 备份改前实际生效的证书/私钥（`base` 来自 `editBase`，即改前快照）。
2. `writeEditBackup` 的 manifest 增记 `tlsNewCertFile/tlsNewKeyFile`（来自 `res`），
   保留 `tlsCertFile/tlsKeyFile` 表示「改前被备份的那一对」。
3. 仅 TLS 触达时写 extras（现有行为不变）。

## 3. E5：成功路径（真实 Nginx + 真证书替换）

### 场景定义（matrix.json `edits`）

```json
{
  "id": "E5",
  "name": "config-edit-tls-cert-success",
  "base": "M4",
  "method": "M4 安装（TLS/ws，Nginx 443，证书 /etc/idleleo/cert/xray.crt）-> schedule install 写入 cert-renew 目标 -> 生成同域名新自签对 -> xray config edit --cert/--cert-key -> 校验写入/reload/握手/jobs.json/备份/不重启 Xray -> 改后 L4",
  "go": {"argv": ["idleleo", "xray", "config", "edit", "--cert", "/etc/idleleo/cert/e5-new.crt", "--cert-key", "/etc/idleleo/cert/e5-new.key", "--yes", "--container", "--json"]},
  "l4Profile": "tls",
  "l4Transport": "ws",
  "checks": ["editRcZero", "probeOk", "tlsVersion13", "wireCertMatches", "fragmentUpdated", "backupHasOldCert", "backupHasOldKey", "scheduleUpdated", "runtimeUnchanged", "xrayNotRestarted", "servicesActive"],
  "notes": "M4 的证书/域名编辑是前端所有，runtime JSON 必须逐字节不变且 Xray 不重启；旧对被备份到 edit-<ts>/。"
}
```

### 驱动步骤（新增 `tests/e2e-diff/drivers/go_edit_tls.sh`，E5 分支）

1. `idleleo schedule install --interval 3600 --cert-domain example.com --cert-out /etc/idleleo/cert/xray.crt --cert-key-out /etc/idleleo/cert/xray.key --container --json`，失败直接记 HARNESS-ERROR。
2. 预状态：runtime config sha256、`jobs.json` sha256、`00-xray.conf` sha256、
   `old-cert sha`、`old-key sha`、`systemctl show xray -p MainPID,ActiveEnterTimestamp`、
   `systemctl is-active xray|nginx`、`openssl s_client -connect 127.0.0.1:443 -servername example.com` 导出的 leaf 指纹。
3. 生成新同域名自签对（新 serial，SAN=DNS:example.com）到
   `/etc/idleleo/cert/e5-new.crt|key`，mode 0640（与 M4 seed 一致），记录 sha/指纹。
4. 执行 matrix 里的 edit argv，捕获 rc、stdout(JSON)、stderr。
5. 后状态：重复步骤 2 的全部采集，另加 `edit-<ts>/` 备份目录清单与文件 sha、
   `openssl s_client` 重新导出的 leaf 指纹、`systemctl show nginx` 状态。
6. 断言写入 `$OUT/edit/checks.json`（driver 负责），L4 由 runner 的 `run_edit_l4`
   以 `tls/ws` 单独跑并落 `$OUT/edit/L4-after/`。

### 断言口径

- `editRcZero`：rc==0。
- `probeOk`：edit JSON `tlsProbe == "ok"` 且 `tlsServerName == "example.com"`。
- `tlsVersion13`：edit JSON `tlsVersion == "TLS 1.3"`。
- `wireCertMatches`：`openssl s_client` 拿到的 leaf SHA256 指纹 == 新证书指纹（独立于 CLI 自报）。
- `fragmentUpdated`：`00-xray.conf` 的 `ssl_certificate`/`ssl_certificate_key` 指向新路径。
- `backupHasOldCert/oldKey`：最新 `edit-<ts>/tls-cert.pem|tls-key.pem` 的 sha == 改前旧对。
- `scheduleUpdated`：`jobs.json` 的 `certFile`/`certKeyFile` 变为新路径（相对 root 表达），
  `certDomain == example.com`，其他字段逐字节不变（除这三个键）。
- `runtimeUnchanged`：runtime config sha 改前后一致。
- `xrayNotRestarted`：`MainPID` 与 `ActiveEnterTimestamp` 均未变。
- `servicesActive`：xray、nginx 均 active；`nginx -t` rc=0。

## 4. E6：回滚路径（握手失败 → 整体回滚）

E6 分两段，同一场景内顺序执行，各自落证据：

### E6a 前置拒写（SAN 不覆盖）

- 动作：`xray config edit --domain other.test --yes --container --json`（证书仍是
  SAN=example.com 的旧对）。
- 断言：rc!=0；stderr 含 `does not cover "other.test"`；runtime sha、`jobs.json` sha、
  `00-xray.conf` sha 全不变；`edit-*` 备份目录数量不增；xray/nginx 仍 active。
- 语义：这是「写入前交叉校验」的守卫证据，证明坏对**零落盘**，不是回滚。

### E6b 真实握手失败 → 回滚

- 触发方式：放一个合法新对（SAN 覆盖 example.com，通过写前校验），同时注入
  `/etc/systemd/system/nginx.service.d/e2e-noop-reload.conf`：
  `ExecReload=/bin/true`，让 `systemctl reload nginx` **静默不生效**
  （真实故障模式：reload 返回成功但旧 worker 配置仍在服务）。
- 预期链路：写 fragment → `nginx -t` 通过 → reload 返回 0 但未生效 → 更新 jobs.json →
  探针连 `127.0.0.1:443` 拿到旧证书 → `front ... serves a certificate that differs from the
  configured file` → `fail()` 回滚。
- 断言：
  - `rollbackRcNonZero`：rc!=0；
  - `probeFailureRecorded`：stderr 含上述证书不符文案，`edit.err` 原样入库，
    `checks.json.failurePoint = "tls-probe: served certificate mismatch"`；
  - `configRestored`：runtime sha == 改前；
  - `nginxRestored`：`00-xray.conf`/`01-xray-80.conf`/`02-xray-server.conf` sha 全 == 改前；
  - `scheduleRestored`：`jobs.json` sha == 改前；
  - `servedCertRestored`：探针重新握手拿到的 leaf 指纹 == 改前旧指纹（服务端实际行为恢复）；
  - `backupHasOldPair`：本次备份含旧对，可用于人工恢复；
  - `servicesActive`：xray/nginx active；
  - 清理 drop-in、`systemctl daemon-reload`，再做一次 reload 让 nginx 回到真实配置路径。
- 限制（写进 ops/checks 与 README）：E6b 的失败点由「reload 静默未生效」制造，
  并非 Nginx 自身报错；它验证的是**写入后探针兜底 + 全量回滚**，不是证书加载失败分支。

### matrix 条目

```json
{
  "id": "E6",
  "name": "config-edit-tls-rollback",
  "base": "M4",
  "method": "M4 安装 + schedule install -> (a) --domain other.test 触发写前拒写 -> (b) 合法新对 + nginx ExecReload 静默 no-op -> 探针发现证书不符 -> 全量回滚 -> 改后 L4",
  "go": {"argv": ["idleleo", "xray", "config", "edit", "--cert", "/etc/idleleo/cert/e6-new.crt", "--cert-key", "/etc/idleleo/cert/e6-new.key", "--yes", "--container", "--json"]},
  "l4Profile": "tls",
  "l4Transport": "ws",
  "checks": ["guardRejected", "guardZeroWrites", "rollbackRcNonZero", "probeFailureRecorded", "configRestored", "nginxRestored", "scheduleRestored", "servedCertRestored", "backupHasOldPair", "servicesActive"],
  "notes": "E6a 证明写前守卫零落盘；E6b 证明写入后握手失败会恢复 runtime/nginx/jobs.json 并使服务保持 active。"
}
```

## 5. runner 改动

- `run_edit_l4` 增加 profile/transport 入参；`edit_job` 用
  `edit_get "$eid" l4Profile`（缺省 `reality`）与 `edit_get "$eid" l4Transport`（缺省 `reality`）。
- `edit_job` 按场景选择驱动：E5/E6 → `drivers/go_edit_tls.sh`，其余 → `drivers/go_edit.sh`。
- `EIDS` 列表加入 `E5 E6`。

## 6. 执行与证据

```bash
E2E_ONLY=E5,E6 bash tests/e2e-diff/run_p2_matrix.sh
```

证据路径：`tests/e2e-diff/evidence/<run-id>/p2/E5/go/edit/` 与 `.../E6/go/edit/`
（`checks.json`、`edit.json`、`edit.err`、`pre-state.json`、`post-state.json`、
`served-cert-pre.pem`、`served-cert-post.pem`、`jobs-before.json`、`jobs-after.json`、
`backup/`、`L4-before|after/connectivity.json`）。

Go 侧回归：

```bash
docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-mod=vendor -e GOPROXY=off \
  -e GOTOOLCHAIN=local -e GOCACHE=/tmp/gocache golang:1.27.4 \
  sh -c "gofmt -l ./internal ./cmd && go vet ./... && go test ./..."
```

## 7. 声明顺序（不可颠倒）

1. 落代码（备份取旧对 + driver/runner/matrix 条目）。
2. 实跑 E5/E6，证据入库。
3. 证据 PASS 后，才更新 `docs/plans/p2/tasks.md` 的 S3 证据段（写 run-id 与 checks）。
4. 更新 `tests/e2e-diff/README.md` 场景表与 E6 限制说明。

## 8. 安全闸与边界

- 不改 `--rewrite-config`、不新增绕过探针的开关；`--no-probe` 语义不变。
- 不改 bash 链路；新增 E6 的 nginx drop-in 只存在于被测容器内，跑完清理。
- 不自动重签：E5/E6 只改目标，不触发 ACME。
- 若 E5/E6 实跑暴露实现缺陷，先停下报告，不修改断言迁就。
