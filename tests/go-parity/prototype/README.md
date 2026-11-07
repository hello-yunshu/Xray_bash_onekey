# Bridge v2（实验用 Go 原型）

仅操作显式授权的本地标记沙盒；不修改主机和真实代理配置。**禁止作为生产迁移程序使用**。

- `go test -race ./...`：23 个测试，包括阶段崩溃、第三方入口接管、候选假程序和篡改防护。
- `./run_trial.sh [OUTPUT_DIR]`：用 v4 原有样本模型生成 Reality/TLS/relay/XTLS 四组测试主机；真正执行旧合成 Bash 和 Go 候选；针对三组注入入口切换后中断并在独立进程恢复。另有一次 Go 成功提交演示。
- `-mode inspect/prepare/activate/recover/status`；准备时必须传 `-candidate-sha256`；测试可用 `-fault after-journal/after-config/after-activating/after-swap`。
- 自检协议为 `--bridge-self-check`；固定输出 schema 和 GOOS/GOARCH。注意不证明完整业务健康；与生产证书/系统服务没有关联。

示例：

```bash
go build -o /tmp/bridge-v2 .
/tmp/bridge-v2 --bridge-self-check
# 仅在由 testdata/make_v4_sandbox.py 生成的标记沙盒内运行其余命令
```
