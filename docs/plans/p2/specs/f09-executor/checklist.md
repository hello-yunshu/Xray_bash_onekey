# F09 验收清单

- [x] `F09_test.py` 只用标准库与镜像内工具，无新增 Go 依赖
- [x] 真实 `xray generate` 产物初始化 Reality 与 TLS ws 两种安装形态
- [x] 真实 `nginx -t` 成功路径与失败回滚都被执行
- [x] add 文件字节与 Bash `fm_create_server_file` 完全一致
- [x] list 文本/JSON、排序、`changed/probed/warnings` 与实测一致
- [x] 重复、保留端口、非法 host、越界端口/权重、错端口删除、loopback 删除均被拒绝
- [x] Reality 安装拒绝 ws；TLS 安装拒绝 reality
- [x] 缺 metadata / 缺锚点 / 缺 nginx / 非沙箱根无 `--container` 均安全失败
- [x] 只读命令前后目录树摘要不变
- [x] 两个全新容器连跑两次，failed=0 且断言数一致
- [x] `meta.txt` 记录镜像 digest、二进制/install.sh sha、工具版本、场景与缺口
- [x] `baseline-compare.json` 区分 aligned / approved-difference / new-go-behavior
- [x] hygiene 0 findings；未提交遗留文件；未 push / 未合并 / 未接触真实 VPS
