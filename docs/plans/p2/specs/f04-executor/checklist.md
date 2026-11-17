# F04 执行器检查清单

- [x] `F04_test.py` 真实执行 Go 二进制，未使用 stub/空断言
- [x] primary 断言入站 9443、front 8443、`0.0.0.0`、Reality 字段、分享/Clash 与 stream 骨架
- [x] primary 片段恰好 3 个（isolate）或 2 个（reject），内容逐字节符合 Baselines
- [x] `--backend` 多后端、同 host 不同端口拒绝、相同 host:port 去重、IPv6 后端均已断言
- [x] 角色缺失/非法、secondary+backend、多 serverNames、保留端口、非 raw 传输全部 `rc=2` 零写盘
- [x] `decoy` 缺口已登记，未伪造为通过
- [x] 保留 publicPort 缺陷已修复并有单测；secondary 的 publicPort 语义未被误改
- [x] Bash 基线真实执行 `apply_install_profile`/`modify_inbound_port`/Nginx 三个 add 函数/
      `write_isolate_site_config`/`nginx_reality_conf_add`，产出 `bash-result.json`
- [x] Bash 生成的 stream 配置与 Go 逐字节对比，两份都跑真实 `nginx -t`
- [x] 所有有效 Go 配置真实 `xray -test` 退出码落盘
- [x] 两次容器运行 `failed=0` 且 `passed` 一致（214/214）
- [x] `check_evidence_hygiene.py` 0 findings
- [x] 三处文档计数更新为 21/28、剩余 7
- [x] 两次单独提交只含本项文件，未 push/tag/merge
- [x] `meta.txt` 明确写 `CONTAINER_VERIFIED` 且注明双机 VPS 未验收
