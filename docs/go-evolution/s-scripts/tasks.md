# S4–S9 执行任务清单

- [x] T1 新建 `tests/e2e-diff/run_s_scripts.sh`
  - [x] T1.1 骨架：变量、`docker_common.sh`、构建 idleleo/xray、证书、`assert`/`log`、`E2E_ONLY`、`E2E_KEEP`
  - [x] T1.2 场景 A 容器：Bash reality 安装（复用 `drivers/bash_install.sh`）
  - [x] T1.3 S4 auto_update：正常 / 重复 / 坏元数据 fail-safe
  - [x] T1.4 S6 geo_update：正常 / 重复 / curl stub 失败且文件不变
  - [x] T1.5 S8 tcp：`plan/apply/apply/rollback` + legacy fail-closed + tcp.sh 下载与 `bash -n`
  - [x] T1.6 S9 speedtest：正常 / 重复 / 失败 + superspeed.sh 下载与 `bash -n`
  - [x] T1.7 S7 acme.sh：下载 installer / 安装 / `--version` / legacy 缺失 fail-closed；写 `BLOCKED-issuance.md`
  - [x] T1.8 场景 B Pebble + TLS ACME：S5 正常 / 重复 / 停 Pebble 失败恢复；Pebble 不可用则 BLOCKED.md
- [x] T2 实跑 `bash tests/e2e-diff/run_s_scripts.sh`，修正真实缺陷（不调低断言）
- [x] T3 证据卫生：`check_evidence_hygiene.py --mask tests/e2e-diff/evidence/s-20261119-full` 0 findings
- [x] T4 文档：`01-parity-and-safety.md` §6.2、`03-final-qualification.md` §6.5/§7、`STATUS.md`
- [x] T5 记录 `check_release_gate.py` 输出（保持 rc=2）与解除条件；不改 `feature_contracts.json`
- [x] T6 Go 侧回归：`gofmt -l`、`go vet ./...`、`go test ./...`
- [x] T7 提交证据 + 文档（不 push、不合并）

## 判定口径
- PASS：断言全部通过且证据可复现。
- FAIL：脚本行为与契约不符，必须修代码或如实记 FAIL。
- BLOCKED：仅限真实域名/公网 CA/内核替换这类物理或外部条件；需写文件说明与解除方式。

## 验收命令
```bash
bash tests/e2e-diff/run_s_scripts.sh
python3 tests/go-parity/parity/scripts/check_evidence_hygiene.py --mask tests/e2e-diff/evidence/<RUN_ID>
cd tests/go-parity/parity && python3 scripts/check_release_gate.py
gofmt -l ./cmd ./internal && go vet ./... && go test ./...
```
