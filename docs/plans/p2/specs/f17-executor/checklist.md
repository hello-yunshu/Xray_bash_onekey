# F17 验收清单

- [x] `Classify` 对 IPv4/IPv6/空行/顺序的行为与 Bash 一致
- [x] 9 组双栈判定表 rc 与 mode/badA/badAAAA 与 Bash 逐项一致
- [x] 显式 ipv4 下错误 AAAA 仍 rc=2；显式 ipv6 对称
- [x] DNS 通过 fixture 内 UDP 服务真实解析 A 后 AAAA；NXDOMAIN rc=1
- [x] family 映射与 `managed_fw_families_for_mode` 一致（含 auto 工具探测）
- [x] apply 生成 `-C` 后 `-I INPUT/OUTPUT` 规则，端口集合与 state 正确
- [x] 443→8443 差分只动变化端口，不整表重写
- [x] ipv4→dual 补齐 v6 规则；dual→ipv6 删除 v4 受管规则
- [x] 中途失败 rc=1，规则文件与 state 恢复到事务前摘要
- [x] state 写失败触发反向回滚；逆操作失败 rc=10
- [x] `--dry-run` 零执行零写盘；`status` 只读；`revert` 幂等
- [x] dual 缺 ip6tables → rc=1 零变更
- [x] 非法端口/policy/family/未知旗标 rc=2；真实根门禁 rc=2
- [x] 两个全新容器连跑两次全绿、failed=0
- [x] `meta.txt` 记录镜像 digest、二进制/install.sh sha、场景与 gap
- [x] hygiene 0 findings；未 push / 未合并 / 未接触真实 VPS
