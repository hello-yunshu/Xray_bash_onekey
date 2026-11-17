# F21 执行器验收清单

对应规格：`docs/plans/p2/specs/f21-executor/spec.md`

## 场景

- [x] S1 安装基线：`--mode none --transport ws --port 443`，`validatorExit=0`、
      `warnings=[]`、服务 active；入站与 outbounds 标签正确
- [x] S2 无状态 `status` 全 false；缺 `--yes` rc=2；dry-run rc=0 零写盘；
      非法 country/IP/kind 均 rc=1 且零写盘（缺写令牌 rc=1）
- [x] S3 首次 apply：7 条 owned 规则顺序与内容、`IPIfNonMatch`、sniffing
      `routeOnly`、drop-in 内容、backup 三文件、真实重启、TCP 探针 ok
- [x] S4 二次 apply 幂等（sha 不变、`oldSha256==newSha256`、drop-in 复用）；
      `status` 的 configured/applied/drift/开关/自定义/geodata 字段
- [x] S5 `off` 精确恢复安装 sha、`AsIs`、sniffing null、开关保留；二次 off 返回
      rc=1 且配置/开关零变化（事实 30）
- [x] S6 `zz`、用户吞流量、缺 geosite 三类失败：rc、零写盘、服务仍 active
- [x] S7 Bash `tb_build_block_rules` 5 条内置规则语义一致；custom 为已批准差异；
      legacy adoption 不重复且用户规则保留
- [x] S8 `observed.json` 与 `baseline-compare.json` 完整，gap 未写成 aligned

## 证据与门槛

- [x] 固定 systemd 镜像 `idleleo-realroot@sha256:d985e8ed...`，xray 26.11.9，
      Go 二进制与 geo 文件 sha 记录在 `meta.txt`
- [x] 两个独立容器各跑一次，`failed=0` 且 `passed` 一致（79/79、79/79）
- [x] `check_evidence_hygiene.py` 0 findings（公网 IP、家目录）
- [x] 运行期不联网；无真实 VPS、无真实凭据
- [x] `install.sh`、`scripts/traffic_blocker.sh` 字节未变

## 文档

- [x] `FUNCTION_PARITY.md` F21 行写入执行器结果、证据路径、gap
- [x] `docs/plans/p2/tasks.md` G-3 计数改为 23/28，剩余 F09/F10/F13/F17/F24
- [x] `tests/go-parity/parity/features/README.md` 23 个执行器，剩余 5 项
- [x] 两次单独提交，未包含遗留文件
