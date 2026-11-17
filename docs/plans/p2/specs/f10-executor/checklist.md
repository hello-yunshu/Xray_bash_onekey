# F10 验收清单

- [x] 命令只改托管 Nginx 的 TLS 版本，不碰 Xray 运行配置
- [x] Reality `1.2+` / `1.3` 与 Bash `tls_type` 产物逐字节一致
- [x] TLS `1.3` 与 Bash `tls_type` 产物逐字节一致
- [x] TLS 安装拒绝 `1.2+`，rc=1 且零写盘（h3/quic 理由）
- [x] 重复目标状态返回 `changed=false`，不重启、不写盘
- [x] `nginx -t` 失败与 reload 失败都还原原字节
- [x] 缺 metadata rc=3；无托管前端 rc=1；ws-only rc=1
- [x] 非法/缺失 `--version`、未知旗标 rc=2
- [x] 两个全新容器连跑两次，38/38 且 failed=0
- [x] `meta.txt` 记录镜像 digest、二进制/install.sh sha、场景与缺口
- [x] `baseline-compare.json` 分类 aligned / approved-difference / new-go-behavior
- [x] hygiene 0 findings；未 push / 未合并 / 未接触真实 VPS
