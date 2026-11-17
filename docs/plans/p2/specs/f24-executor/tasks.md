# F24 任务

- [x] T1 新增 `internal/container/runtime.go`：DetectMode/Status/Up/Down/pid 与日志
- [x] T2 补 `runtime_test.go`：direct 启停、幂等、dry-run、缺配置、进程不存在、门禁
- [x] T3 接入 `container status|up|down`、`--json`、`--container`、`--dry-run` 与帮助文本
- [x] T4 更新 `docker/Dockerfile` 多阶段构建与 `/opt/idleleo/bin/idleleo`
- [x] T5 更新 `docker/docker-entrypoint.sh`：`_go_container` 分叉与 watchdog 状态源
- [x] T6 更新 `docker/DOCKER.md` 的容器模式、日志与 gap
- [x] T7 编写 `F24_test.py`：空根、真实 nginx + 假 xray 启停、幂等、down、门禁
- [x] T8 `F24_test.py` 静态交付契约 + 提取 entrypoint 函数跑 Bash 基线
- [x] T9 固定镜像连跑两次，写 `meta.txt`/`observed.json`/`baseline-compare.json`，
      hygiene 0 findings
- [x] T10 更新 `FUNCTION_PARITY.md`、`docs/plans/p2/tasks.md` G-3 计数、features README
- [x] T11 两次提交：`feat(F24): ...` 与 `test(F24): ...`
