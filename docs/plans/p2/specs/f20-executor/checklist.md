# F20 执行器验收清单

对应规格：`docs/plans/p2/specs/f20-executor/spec.md`

## 覆盖

- [x] S1 首次 install 的 `jails`/`files`/`warnings`/`serviceRestarted` 与 manifest；
      4 个 jail 键值、`jail.local` 同 sha、incremental、2 个过滤器逐项断言
- [x] S1 二次 install 幂等（全树 sha 不变）
- [x] S2 Bash 基线真实执行 `mf_configure_fail2ban`，与 Go 产物逐字节 diff
- [x] S3 真实 `fail2ban-client -x start` 后 `status`/`banned`/`unban`（首次与 already-absent）
- [x] S4 `trust add|del` 的 ignoreip 运行态与 `zzz-idleleo-trust.local` 持久化（IPv4/IPv6）
- [x] S5 `jail disable|enable` 文件翻转；非托管 jail 拒绝
- [x] S6 `uninstall` 的 removed/preserved/needForce；保留 `user-custom.local`；
      二次 `rc=2`+needForce 零删除，`--force` 只清已知残留
- [x] S7 缺二进制零落盘、sandbox marker、`--root /` 无 `--container`、非法 IP/CIDR/未知 jail 的 rc
- [x] S8 `observed.json` 与 `baseline-compare.json` 完整记录，gap 未写成 aligned

## 证据与门槛

- [x] 固定 digest `idleleo-e2e@sha256:3012978e...`，fail2ban 1.0.2，
      Go 二进制 sha 记录在 `meta.txt`
- [x] 容器内连跑两次，两次 `failed=0` 且 `passed` 一致（110/110）
- [x] `check_evidence_hygiene.py` 0 findings（公网 IP、家目录）
- [x] 无网络依赖、无真实 VPS、无真实凭据
- [x] `install.sh`、`scripts/fail2ban_manager.sh` 字节未变

## 文档

- [x] `FUNCTION_PARITY.md` F20 行写入执行器结果、证据路径、gap
- [x] `docs/plans/p2/tasks.md` G-3 计数改为 22/28，剩余 F09/F10/F13/F17/F21/F24
- [x] `tests/go-parity/parity/features/README.md` 22 个执行器，剩余 6 项
- [x] 两次单独提交，未包含遗留文件
