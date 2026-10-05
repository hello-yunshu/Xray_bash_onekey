# 证据使用说明

日志记录审计基线结果，不能当修复后资格。repro_* 是定向复现，mock/注入点在源码中标明；请在临时隔离目录复现，不在真实服务上运行。

这些脚本最初在审计 workspace 的 work/ 中执行，有些路径引用审计工具目录或兄弟仓库。复制到这里为了留证；重跑时按脚本顶部 BASE/REPOS/工具路径调整到本机，或将它们整理为仓库正式测试。Python import grp/dirfd 桩仅允许 Windows 上孤立函数测试，不证明 Linux 权限或文件系统竞态正确。

cf-tests.json 的非零项含 Windows 工具/平台阻塞和未完成定位结果，不能机械地按失败个数报 bug；rill-script-tests.log 中 SBOM 编码是确定缺陷，resource import 为 Linux 环境限制。Git blob 检查绕过 Windows autocrlf 行尾转换，保留源码不变。
