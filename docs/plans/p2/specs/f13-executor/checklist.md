# F13 验收清单

- [x] 清单 component/sha256/size/version 全部校验，坏清单一律 rc=3 零写盘
- [x] 摘要或大小不符 rc=5，二进制、目录、备份均无变化
- [x] 降级 rc=4 且零写盘（与 Bash 的 rc=0 警告差异已登记）
- [x] 同版本重装允许，`action=reinstall` 且备份更新
- [x] xray 健康失败 rc=6、`rolledBack=true`、旧字节逐字节恢复
- [x] nginx 健康失败 rc=6、整树摘要恢复；成功时目录被替换
- [x] 备份路径/权限可验证，沙箱根不重启服务并告警
- [x] 真实根未 `--container`/未设写令牌 rc=2
- [x] 未知旗标、缺 `--manifest` rc=2
- [x] Bash `version_gt` 与 Go 比较表逐项一致，其余差异分类记录
- [x] 两个全新容器连跑两次全绿、failed=0
- [x] `meta.txt` 记录镜像 digest、二进制/install.sh sha、场景与 gap
- [x] hygiene 0 findings；未 push / 未合并 / 未接触真实 VPS
