# F18-QR 验收清单

## 行为

- [x] 默认 `xray share` 输出与现在逐字节一致（无 `qr:`、无 `█`、不提 qrencode）
- [x] `--qr` 在 `share:` 之后输出 `qr:` + 真实 qrencode UTF-8 矩阵，rc=0
- [x] `qr:` 之后的字节与 `printf %s "$uri" | qrencode -o - -t utf8` 完全一致
- [x] `--json --qr` rc=2，且不打印任何矩阵
- [x] 缺 qrencode：rc=1、stdout 为空、stderr 含 `qrencode` 与三平台安装提示
- [x] 未知旗标仍 rc=2；`--qr` 与其他 share 旗标可组合

## 基线

- [x] 真实 qrencode 4.1.1 的同一 URI 输出与 Go `--qr` 逐字节一致
- [x] `install.sh` 10 处 qrencode 调用点未变
- [x] `go.mod`/`go.sum`/`vendor/` 无变化，无新增依赖

## 证据与门槛

- [x] 固定镜像 `idleleo-e2e@sha256:3012978e...` 两个独立容器各跑一次
- [x] 两次 `failed=0` 且 `passed` 一致，`qr-compare.json` sha 记录完整
- [x] `check_evidence_hygiene.py` 0 findings；运行期不联网、无真实 VPS

## 文档与提交

- [x] `FUNCTION_PARITY.md` F18 行不再把二维码记作缺口
- [x] `docs/plans/p2/tasks.md` F18 条目更新，不再写「二维码仍未实现」
- [x] 两次单独提交，未包含遗留文件
