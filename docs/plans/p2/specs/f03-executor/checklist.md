# F03 执行器检查清单

- [x] `F03_test.py` 真实执行 Go 二进制，未使用 stub/空断言
- [x] 默认 none+ws 断言入站 `security=none`、`listen=127.0.0.1`、`port=10086`、`path=/ray/`，且无 Nginx 产物
- [x] 非回环 `--listen` 未加 `--allow-non-loopback` 时 `rc=2` 且零写盘；加旗标后按值生成
- [x] `::1` 被接受且分享 authority 带方括号；`2001:db8::1` 默认拒绝
- [x] 非法 listen 格式的缺口已写入 `baseline-compare.json`，未伪造为通过（实测 `xray -test` 拒绝）
- [x] gRPC/xHTTP/multi 三种附加形态的字段、端口池与 warning 已断言
- [x] multi 钉选端口语义按实测断言（ws 用 `--port`，`--ws-port` 被忽略并登记）；冲突/越界 `rc=2` 零写盘
- [x] multi 显式非回环时三个入站监听地址一致（缺陷已修复并补单测）
- [x] `--public-port` 只改客户端视图，配置入站端口不变
- [x] Bash 基线真实执行 `modify_listen_address`/`modify_inbound_port`/`add_*_inbound` 并产出 `bash-result.json`
- [x] 两次容器运行 `failed=0` 且 `passed` 一致（159/159）；真实 `xray -test` 退出码落盘
- [x] `check_evidence_hygiene.py` 0 findings
- [x] 三处文档计数更新为 20/28、剩余 8
- [x] 单独提交只含本项文件，未 push/tag/merge（d591b55b）
