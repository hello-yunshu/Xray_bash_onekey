# Spec：OPS-03 shortId 残留 & OPS-17b 超时的修复方案

- 日期：2026-11-24
- 候选版本：`5041511998575851eb5cb16533e9fe999d29d5a8`（冻结验收对象，产品代码自该提交后未变）
- 分支：`work/go-hardening-parity-20261119`
- 目标：把两条未闭合的验收行从「DIFF/BLOCKED」推进到「有真实证据的结论」，且不修改验收口径取绿、不伪造退出码、不自行批准差异。

---

## 1. 目标

| 行 | 现状 | 目标 |
| --- | --- | --- |
| OPS-03 | 删除用户后短 ID 残留：`bash=1 go=2 (baseline 1/1)`，写 `shortid-difference.json`，无 `ops.json` | 两侧都回到 baseline，并把「Go 需要额外一步」作为业务事实写进 details/账本 |
| OPS-17b | 判定器硬编码 `BLOCKED`，Bash `5>3` 30s 超时 `rc=124`，Go 用 `/nonexistent/manifest.json` 只证明 fail-closed | 两侧各自完成一次真实的 Nginx 更新（1.27.x → 包内 1.30.6），判定器按实际结果计算 PASS/FAIL |

## 2. 非目标

- 不修改 `tests/e2e-diff/ledger.json` 的验收 rank 规则。
- 不把 OPS-17a（脚本更新，依赖公网分发）一起放开；17a 维持 BLOCKED。
- 不改产品 CLI 语义（Plan A 下产品代码零改动，候选哈希不变）。
- 不扩大无关功能。

## 3. 已确认事实（证据锚点）

### OPS-03

- Go：`internal/xraycfg/users.go`
  - `AddUser` 接受可选 `spec.ShortID`，追加到 `realitySettings.shortIds`（293–309）。
  - `RemoveUser`（322–383）只删除 `settings.clients` 中匹配项，**不触碰 shortIds**。
  - `ShortIDRemovalNotice`（385–409）明确：shortId 是 inbound 级、无法归属到单个用户，默认保留，需用 `xray edit --short-id-remove <sid>` 显式删除。
- Go 已有显式删除能力，无需新增：
  - `internal/cli/xrayedit.go` 解析 `--short-id-remove`，并把它算作一个合法的 reality 编辑动作。
  - `internal/xraycfg/edit.go`（`case req.ShortIDRemove != "":`）校验 sid 必须存在于 accepted list，否则报 `shortId %q is not in the accepted list`，通过后移除并记录 `short-id-remove`。
- Bash：维护 `install_config.reality_clients` 的 email→shortId 映射，删用户时自动删其 sid。
- 驱动：`tests/e2e-diff/run_p2_matrix.sh`
  - `OPS_USER_SHORT_ID="${E2E_OPS_USER_SHORT_ID:-e2e0a1b2}"`（894）。
  - Go add 显式传 `--short-id "$OPS_USER_SHORT_ID"`（2605–2608）；Bash 走菜单 add。
  - Go remove（2614–2616）之后直接 `ops_snapshot removed`（2617）。
  - 判定（2528–2563）：`shortid_clean = all(obs[side]["removedSids"] == obs[side]["beforeSids"])`，不满足即写 `shortid-difference.json`。

结论：这是**真实的产品语义差异**，不是 Bug。Bash 有映射所以能自动删；Go 没有映射，自动删可能打断仍在复用该 sid 的其他客户端。任何「让 Go 自动删」的方案都必须先引入映射，风险与改动面都远超本行。

### OPS-17b

- 驱动：`run_p2_matrix.sh`
  - Bash：`ops_bash_pipe "$bserver" ... run 30 '5\n3\n\n'`（1881）。
  - Go：`... update nginx --manifest /nonexistent/manifest.json --json --container --no-restart`（1882）。
  - 判定：2088–2098 直接 `write("OPS-17b", "BLOCKED", [...])`，完全不读结果。
- Bash 超时根因（已由证据坐实）：
  - `menu_update` 选 3 → `menu_action 2` → `countdown` + `nginx_update` + `exec bash ${idleleo}`（install.sh 16174–16180）。
  - 本轮镜像内记录版本与离线包 build 相同，`nginx_update` 走到「已为最新版」（install.sh 7758–7759），没有触发保留配置的交互；第三个换行被重启后的主菜单读走，随后管道 EOF，主菜单 `read` 空转 → `timeout 30` 杀进程 → `rc=124`。
  - 证据：`evidence/round4-full-50415119/p2/OPS-17b/bash/run.rc=124`，`run.out` 含 `Nginx:[最新版]`，`run.err` 为空。
- Go 侧 `update nginx` 的「已安装版本」来自**执行二进制**，不读安装记录：`internal/componentupdate/update.go::installedVersion`（189–200）执行 `<root>/usr/local/nginx/sbin/nginx version` 并解析输出；升级后 `verifyVersion`（244–251）再次执行新二进制。因此 Go 侧只要把一个 1.27 的二进制放到该路径，就会发生真实升级。
- Bash 侧 `nginx_update` 的「当前版本」来自安装记录：`current_nginx_build_version=$(info_extraction nginx_build_version)`（7602），并与包 build 比较（7603）。安装记录文件是 `${idleleo_conf_dir}/install_config.json`（install.sh 334），键 `nginx_build_version`。因此 Bash 侧需要把该键改成旧值才会进入真实更新分支（7604 起），并会经过「是否保留原 Nginx 配置文件」提示（7680）。
- 现成夹具：`tests/e2e-diff/run_ops_realroot.sh`
  - 用 `nginx:1.27` 镜像的真实二进制搭最小树，再用本地可信 manifest 做 1.27 → 1.30.6 的真实更新，断言 previous/new/health/backup（79–110）。
  - 本地可信包：`/seed/nginx.tar.gz` + 生成的 `nginx-manifest.json`（`component/version/url/sha256/size`）。
- 矩阵内已有离线包：`seed_nginx_cache()`（200–255）生成 `$WORK/seed/nginx/{release-manifest.json, xray-nginx-custom-*.tar.gz, versions.json, nginx-cache.json}`，并通过 `NGINX_CACHE_ENVS`（171–179，601/643 注入）供 Bash 使用。该 manifest 是 Bash 的发布格式，**不是** Go `update nginx` 需要的 `component/version/url/sha256` 格式。
- e2e 镜像（`tests/e2e-diff/image/Dockerfile`，ubuntu:24.04）**不自带 nginx**，所以「旧版本二进制」必须从外部注入。

结论：OPS-17b 不是「更新能力缺失」，而是**驱动没有构造可更新的前置状态、两侧测的不是同一件事、判定器未读结果**。

---

## 4. 决策

### D1 — OPS-03：驱动按已文档化的两步流程执行（Plan A，推荐）

- 做法：Bash 保持「删除即清理」；Go 在 `user remove` 之后再执行一次 `xray config edit --short-id-remove "$OPS_USER_SHORT_ID" --yes`，然后两侧都拍 `cleaned` 快照，判定改为比较 `cleanedSids == beforeSids`。
- 为什么推荐：
  1. 产品代码零改动，冻结候选 `50415119` 不变，本轮证据仍属于同一候选；
  2. 与 `ShortIDRemovalNotice` 的既有契约一致，不是「为测试改产品」；
  3. 不引入 Go 侧缺失的 email→sid 映射，避免误删其他客户端的 sid；
  4. 差异不会被掩盖：`details` 里同时记录 `go.shortIdResidueAfterRemove=1` 和 `go.cleanupCommand`，账本/报告明确写「Go 需要显式第二步」。
- 备选 Plan B（仅在产品方明确要求「一步删除」时启用）：给 `user remove` 增加显式 `--short-id <sid>`。改动面与前置条件见 §7.1。启用 Plan B 会改变产品代码，必须重签候选哈希并重跑全量，**本轮不建议**。

### D2 — OPS-17b：两侧做同构的真实更新（推荐）

- 做法：
  1. 为 Bash/Go 各自准备「旧版本现场」：`/usr/local/nginx/sbin/nginx` 换成真实的 1.27 二进制（优先从 `nginx:1.27` 镜像 `docker cp`；失败则退化为只回答版本号的 stub，并在 details 标注 `previousBinarySource=stub`）。
  2. Bash 侧额外把 `install_config.json` 的 `nginx_build_version` 改成 `1.27.0`，让 `nginx_update` 进入真实更新分支。
  3. Bash 输入改为 `'5\n3\n\n0\n'`（5→3→保留配置默认→重启菜单退出），超时 `180s`。
  4. Go 侧改用本地可信 manifest（由 `seed_nginx_cache` 产物生成 Go 格式），去掉 `--no-restart`，让更新后自检/重载真实发生。
  5. 判定器改为读取两侧 rc、更新前后 `nginx -v`、备份目录、更新后健康，写业务 `details`；只有前置包真的缺失才允许 BLOCKED，并写明缺失路径与 rc。
- 为什么推荐：这是唯一能证明「更新管道真的替换了二进制并保持健康」的方案，且与已通过的 real-root 夹具同构。

---

## 5. 变更设计

### 5.1 OPS-03（`tests/e2e-diff/run_p2_matrix.sh`）

**A. `ops_users_job()`（2573–2626）**

Bash 分支（2590–2592 之后）：

```bash
ops_bash_user_menu "$bserver" "$bdir" remove
ops_snapshot "$bserver" "$bdir" removed
ops_health   "$bserver" "$bdir" removed
# Bash 的 remove 已自带 sid 清理；cleaned 只是再拍一次，用于两侧同构比较。
ops_snapshot "$bserver" "$bdir" cleaned
ops_health   "$bserver" "$bdir" cleaned
```

Go 分支（2614–2618）：

```bash
ops_go_cli "$gserver" "$gdir" remove xray user remove --sandbox / \
    --email "$OPS_USER_EMAIL" --validator /usr/local/bin/xray \
    --service /usr/local/bin/e2e-service-apply --container --json
ops_snapshot "$gserver" "$gdir" removed      # 保留残留现场
ops_health   "$gserver" "$gdir" removed
ops_go_cli "$gserver" "$gdir" 12-short-id-clean --root / xray config edit \
    --short-id-remove "$OPS_USER_SHORT_ID" \
    --path /etc/idleleo/conf/xray/config.json \
    --container --yes --json
ops_snapshot "$gserver" "$gdir" cleaned
ops_health   "$gserver" "$gdir" cleaned
```

要点：
- `config edit` 不认 `--sandbox`/`--root` 作为子命令参数（实跑报 `unknown flag`），必须把 `--root /` 放在 `xray` 之前（全局参数）；`ops_go_cli` 直接 `idleleo "$@"`，所以该形式可行。
- `--yes` 必需：删除 sid 会让使用该 sid 的客户端断连，`xrayedit.go` 在非 TTY 下要求显式确认。
- 两处 `ops_snapshot` 的 tag 必须与判定器新增 key 一致。

**B. 判定（2431–2465、2528–2563）**

`obs` 新增：

```python
"cleanedSids": snap(side, "cleaned", "short-ids"),
"cleanupRc": rc(os.path.join(base, side,
    "12-short-id-clean.rc" if side == "go" else "remove.rc")),
```

`details` 新增（不删除既有字段）：

```python
"shortIdResidueAfterRemove": len(obs[side]["removedSids"]) - len(obs[side]["beforeSids"]),
"cleanupCommand": ("xray config edit --short-id-remove" if side == "go"
                   else "none (user remove clears the sid on Bash)"),
"cleanupRc": obs[side]["cleanupRc"],
"cleanedShortIds": len(obs[side]["cleanedSids"]),
```

判定改为：

```python
shortid_clean = all(
    obs[side]["cleanupRc"] == 0
    and obs[side]["cleanedSids"] == obs[side]["beforeSids"]
    for side in ("bash", "go")
)
```

其余 reason 文案不变；`shortid-difference.json` 仅在真实未收敛时写出，record 增加
`"remediation": "xray config edit --short-id-remove $OPS_USER_SHORT_ID"`。

`healthy("cleaned")` 必须一并纳入（`healthy(tag)` 已按 side 读 `<tag>.xray-active.rc`）。

### 5.2 OPS-17b 驱动（`run_p2_matrix.sh`，observe job 内 1877–1882）

**A. 新增夹具函数（放在 `seed_nginx_cache()` 之后）**

```bash
# 把真实的 1.27 二进制放进已有 managed nginx 树，保留 conf。
seed_old_nginx_binary() { # <server> <outdir>
    local server=$1 out=$2 cid
    mkdir -p "$out"
    if cid=$(docker create "$E2E_NGINX_OLD_IMAGE" 2>/dev/null) \
       && docker cp "$cid:/usr/sbin/nginx" "$out/nginx-1.27" >/dev/null 2>&1; then
        docker rm "$cid" >/dev/null 2>&1
        docker cp "$out/nginx-1.27" "$server:/usr/local/nginx/sbin/nginx" >/dev/null 2>&1
        docker exec "$server" chmod 0755 /usr/local/nginx/sbin/nginx >/dev/null 2>&1
        if docker exec "$server" /usr/local/nginx/sbin/nginx -v 2>&1 | grep -q 'nginx/1\.27\.'; then
            echo real >"$out/previous-binary.txt"
            return 0
        fi
    else
        docker rm "$cid" >/dev/null 2>&1 || true
    fi
    # 退化：只回答版本号的 stub；只影响「更新前版本」这一事实，更新后仍是真二进制。
    docker exec "$server" sh -c 'printf "#!/bin/sh\n[ \"\$1\" = \"-t\" ] && exit 0\necho \"nginx version: nginx/1.27.0\" >&2\nexit 0\n" > /usr/local/nginx/sbin/nginx && chmod 0755 /usr/local/nginx/sbin/nginx'
    echo stub >"$out/previous-binary.txt"
}
```

Bash 专属：把安装记录改成旧 build，强制进入更新分支。

```bash
docker exec "$bserver" sh -c '
  f=/etc/idleleo/install_config.json
  jq --arg v "1.27.0" ".nginx_build_version=\$v" "$f" >"$f.tmp" && mv "$f.tmp" "$f"'
```

**B. Go 可信 manifest（新文件，生成到 `$WORK/seed/nginx/go-nginx-manifest.json`）**

以 `seed_nginx_cache` 写出的 `nginx-cache.json` / `release-manifest.json` 为源，生成 realroot 同款字段：

```json
{"component":"nginx","version":"<versions.nginx>","url":"/seed/nginx/<tarball 文件名>",
 "sha256":"<tarball sha256>","size":<字节数>}
```

**C. 调用替换（1881–1882）**

```bash
seed_old_nginx_binary "$bserver" "$EVID/OPS-17b/bash"
seed_old_nginx_binary "$gserver" "$EVID/OPS-17b/go"
docker exec "$bserver" sh -c 'cat /etc/idleleo/install_config.json' \
    >"$EVID/OPS-17b/bash/install-config-before.json" 2>/dev/null || true
docker exec "$bserver" /usr/local/nginx/sbin/nginx -v \
    >"$EVID/OPS-17b/bash/nginx-before.txt" 2>&1 || true
docker exec "$gserver" /usr/local/nginx/sbin/nginx -v \
    >"$EVID/OPS-17b/go/nginx-before.txt" 2>&1 || true

ops_bash_pipe "$bserver" "$EVID/OPS-17b/bash" run 180 '5\n3\n\n0\n'
ops_go_cli "$gserver" "$EVID/OPS-17b/go" 10-op update nginx \
    --manifest /seed/nginx/go-nginx-manifest.json --container --json

docker exec "$bserver" /usr/local/nginx/sbin/nginx -v \
    >"$EVID/OPS-17b/bash/nginx-after.txt" 2>&1 || true
docker exec "$gserver" /usr/local/nginx/sbin/nginx -v \
    >"$EVID/OPS-17b/go/nginx-after.txt" 2>&1 || true
docker exec "$bserver" sh -c 'ls -d /usr/local/nginx_backup_*' \
    >"$EVID/OPS-17b/bash/backup.txt" 2>&1 || true
ops_health "$bserver" "$EVID/OPS-17b/bash" updated
ops_health "$gserver" "$EVID/OPS-17b/go" updated
```

说明：
- Bash 在更新成功后执行 `safe_rm "${backup_nginx_dir}"` 删除备份目录，所以「有备份」不能靠事后 `ls` 判断；判定器把 `run.out` 里的 `备份旧版` 日志行作为等价证据，并用更新后的 `install_config.json::nginx_build_version` 证明记录已迁移到包 build。
- Go 保留备份目录（`/etc/idleleo/backup/nginx-*`），可直接 `ls`。
- Bash 的第三行空行回答「是否保留原 Nginx 配置文件」（默认保留），第四行 `0` 在 `exec` 重启后的主菜单退出；这样不会再出现 EOF 空转。
- Go 去掉 `--no-restart`，让 reload 与健康校验真实发生。若 harness 内 reload 失败，则保留 `--no-restart` 并显式 `systemctl restart nginx`，details 记 `restart=explicit`。
- 该 job 后续还有 OPS-18/23/24，更新后 nginx 为 1.30.6 且健康，不影响这些行；容器在本 job 结束时销毁。

**D. 判定（2088–2098，仅替换 17b 段落）**

```python
def nginx_ver(p):
    m = re.search(r"nginx/([0-9][0-9.]*)", text(p))
    return m.group(1) if m else ""

bash17 = {
    "rc": rc(os.path.join(evid, "OPS-17b", "bash", "run.rc")),
    "before": nginx_ver(os.path.join(evid, "OPS-17b", "bash", "nginx-before.txt")),
    "after":  nginx_ver(os.path.join(evid, "OPS-17b", "bash", "nginx-after.txt")),
    "backup": bool(text(os.path.join(evid, "OPS-17b", "bash", "backup.txt")).strip()),
    "health": rc(os.path.join(evid, "OPS-17b", "bash", "updated.xray-active.rc")),
    "previousBinary": text(os.path.join(evid, "OPS-17b", "bash", "previous-binary.txt")).strip(),
}
go17 = { ... 同构，rc 读 10-op.rc ... }
try:
    go_json = json.loads(text(os.path.join(evid, "OPS-17b", "go", "10-op.out")) or "{}")
except ValueError:
    go_json = {}

reasons = []
for name, d in (("bash", bash17), ("go", go17)):
    if d["rc"] != 0:
        reasons.append("%s update rc=%s" % (name, d["rc"]))
    if not d["before"].startswith("1.27"):
        reasons.append("%s previous nginx is %r, want 1.27.x" % (name, d["before"]))
    if d["after"] != EXPECTED_NGINX:
        reasons.append("%s installed nginx is %r, want %r" % (name, d["after"], EXPECTED_NGINX))
    if not d["backup"]:
        reasons.append("%s left no nginx backup" % name)
    if d["health"] != 0:
        reasons.append("%s nginx/xray unhealthy after update" % name)
if go_json.get("newVersion") not in ("", EXPECTED_NGINX):
    reasons.append("go newVersion=%r" % go_json.get("newVersion"))
if go_json and go_json.get("previousVersion") and not str(go_json["previousVersion"]).startswith("1.27"):
    reasons.append("go previousVersion=%r" % go_json.get("previousVersion"))

details = {"bash": bash17, "go": go17,
           "goReport": {k: go_json.get(k) for k in ("previousVersion", "newVersion", "verified", "health")},
           "expected": EXPECTED_NGINX}
if not reasons:
    write("OPS-17b", "PASS", [], bash17["rc"], go17["rc"], details=details)
elif bash17["rc"] == 127 or go17["rc"] == 127:   # 前置包/二进制缺失
    write("OPS-17b", "BLOCKED", ["fixed local package missing"], details=details)
else:
    write("OPS-17b", "FAIL", reasons, bash17["rc"], go17["rc"], details=details)
```

`EXPECTED_NGINX` 从 `seed_nginx_cache` 的 `release-manifest.json` 读取，避免硬编码。
`write()` 需支持 `details=` 关键字；若现有签名不同，直接写 `ops.json`（与其它行保持一致）。

### 5.3 账本与报告

- `tests/e2e-diff/ledger.json`：由既有账本生成器重建（`--allow-repo-write`），OPS-03/OPS-17b 状态来自新证据，不手改。
- 报告（`docs/go-migration/audit-remediation/FINAL_AUDIT_20261124.md` 或新的 round5 报告）必须写明：
  - OPS-03：PASS 的前提是 Go 执行了文档化的第二步；Bash 一步、Go 两步，属于**已记录的 UX 差异**，不是隐藏差异。
  - OPS-17b：两侧均完成真实二进制替换，列出 before/after、备份、健康结果；若用了 stub 旧二进制，必须显式标注。
- 不自行把 DIFF 改成 PASS；若实跑仍不收敛，按实际结果记 FAIL/BLOCKED 并保留现场。

---

## 6. 验证步骤

1. 语法检查：
   - `bash -n tests/e2e-diff/run_p2_matrix.sh`
   - 若抽取了 Python 片段，单独 `python3 -c 'compile(...)'`。
2. 新 run id 定向实跑（沿用脚本既有行过滤器，`E2E_RUN_ID` 必须是未使用值）：
   - 先单跑 OPS-03（users job）：确认 `cleaned.short-ids.txt` 两侧都等于 `before.short-ids.txt`，并人工检查 `12-short-id-clean.out` 无 `refusing to rewrite`。
   - 再单跑 OPS-17b（observe job）：确认 `run.rc=0`、`run.out` 出现 `Nginx 更新: v1.27.0 → v2026.10.15.7679`、`nginx-after.txt=1.30.6`、备份目录存在、`updated.xray-active.rc=0`。
3. 人工核对 Go JSON：`previousVersion=1.27.x`、`newVersion=1.30.6`、`verified/health=true`。
4. 确认证据目录结构：
   - `OPS-03/{bash,go}/{removed,cleaned}.short-ids.txt`、`12-short-id-clean.{out,rc}`。
   - `OPS-17b/{bash,go}/{nginx-before,nginx-after,backup,previous-binary}.txt`、`updated.*`。
5. 重建账本，核对目标行状态与总计数（DUAL/GO_ONLY/FAIL/BLOCKED/NOT_RUN）。
6. 更新报告/证据索引，提交并 push。

## 7. 验收标准

**OPS-03**
- `bash`/`go` 的 `cleaned.short-ids.txt` 都等于各自 `before.short-ids.txt`。
- 客户端集合、email、健康检查全部通过（沿用现有检查）。
- `details.go.shortIdResidueAfterRemove == 1` 且 `details.go.cleanupCommand` 非空（差异可见）。
- 账本状态为 PASS，且报告写明两步差异。

**OPS-17b**
- 两侧 rc=0。
- 两侧更新前 `nginx -v` 为 1.27.x，更新后为包内 1.30.6。
- 两侧都有备份目录，更新后健康 rc=0。
- Go JSON `previousVersion/newVersion` 与上述一致。
- 任一条件不满足 → FAIL，并保留原始输出；只有前置包缺失才 BLOCKED。

## 8. 风险与回滚

| 风险 | 应对 |
| --- | --- |
| `xray config edit` 在 e2e 容器里因 install state 缺失拒绝再生 | 先小步实跑；必要时在 edit 前补 `--path`/`--host`，或退回 Plan B |
| 1.27 二进制与 ubuntu 24.04 的 lib 不兼容 | 自动退化 stub，details 标注 `previousBinarySource=stub`，更新后仍是真 1.30.6 |
| Bash 更新后 conf 被替换导致健康失败 | 这是产品行为本身；失败即 FAIL 并保留 `run.out`，不做人工修补 |
| Go reload 在 systemd 容器内失败 | 保留 `--no-restart` + 显式 restart，details 记 `restart=explicit` |
| 磁盘/网络 | 所有包来自 `$WORK/seed`，不依赖公网 |

回滚：只回滚测试驱动改动（`run_p2_matrix.sh`），产品代码与候选哈希不变。

## 9. 待批准

1. **OPS-03 采用 Plan A**（驱动两步走 + 记录 UX 差异），而不是新增 `user remove --short-id`。若批准 Plan A，本轮产品代码零改动。
2. **OPS-17b 采用真实版本切换**（注入 1.27 旧二进制），并允许在二进制不兼容时退化 stub 且在报告中标注。
3. 允许用新 `E2E_RUN_ID` 重跑 OPS-03/OPS-17b、重建账本、更新报告并 push。

## 10. 附：Plan B（仅备查，本轮不实施）

若产品方要求「一步删除」：

- `internal/cli/xray.go` remove 分支：解析 `--short-id`（可选），未传时维持现状并输出 `ShortIDRemovalNotice`。
- `internal/xraycfg/users.go`：`RemoveUser` 增加 sid 参数，在同一个 clone 内从 `realitySettings.shortIds` 移除；sid 不存在则报错；不允许移除最后一个 sid。
- 复用 `validShortID` 与 `edit.go` 的校验语义，避免两套规则。
- 事务层保证 client 删除与 sid 删除共用一次备份/回滚。
- 需要新增单元测试与 CLI 测试，并重签候选哈希、全量重跑。
