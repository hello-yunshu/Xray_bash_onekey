# F24 验收清单

- [x] `container status` 只读，输出 `inContainer`/`mode`/pid/alive，且零写盘
- [x] `container up` 在无 systemd 时直接启动 xray 与 nginx，写 pid 与日志
- [x] `container up` 幂等：服务已运行时不重复启动
- [x] `container down` 停止进程、删 pid，二次调用 rc=0 且 stopped 为空
- [x] `--dry-run` 不建目录、不写 pid、不启动进程
- [x] 真实根未 `--container`/未设写令牌 rc=2；无 marker 沙箱 rc=2；未知旗标 rc=2
- [x] 镜像含 Go 二进制；entrypoint 的 Go 模式不调用 systemctl
- [x] Bash 基线 `_start_services`/`_stop_services` 真实执行，启停集合一致
- [x] `baseline-compare.json` 分类 aligned / approved-difference / new-go-behavior
- [x] 两个全新容器连跑两次全绿、failed=0
- [x] `meta.txt` 记录镜像 digest、二进制/entrypoint sha、场景与 gap
- [x] hygiene 0 findings；未 push / 未合并 / 未接触真实 VPS
- [x] 未改 `install.sh`，未把 fake-systemctl 当作 systemd
