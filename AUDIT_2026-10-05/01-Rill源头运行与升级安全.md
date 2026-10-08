# 阶段 1：Rill 源头运行与升级安全

你是负责实际修改代码的工程师。请在当前仓库完成本文件指定阶段，提交可验证的实现和回归测试，不要只输出建议或另写计划。

执行约束：

1. 先阅读本目录 00-审计报告与执行顺序.md，确认基线 SHA，再按本文的文件/函数定位。行号属于审计基线，代码变化后按函数定位。开始前记录 git status；保留用户已有修改，不执行 reset --hard/clean，不删除真实模型/配置/备份。
2. 先写能复现旧行为的回归，确认测试失败原因是本缺陷；再做最小必要修改。不得删除断言、提高资源上限、取消安全 gate 或将失败改为 success 来“通过”测试。
3. 逐项完成下面的修改和验收。复现脚本中的故障桩用于审计证据，不可直接变成生产实现。资源/时钟/IO 桩必须仍通过真实生产入口。
4. 网络、服务、特权测试放在隔离 Linux/OpenWrt 环境；不在真实用户主机停止代理/修改防火墙。允许按现有依赖管理获取工具，不擅自升级全仓库依赖。
5. 保持已有公共协议、快照、配置、权限和回滚契约。必要格式迁移写双向兼容说明与历史 fixture 测试；不能把所有旧状态删掉后“重新训练”。
6. 跑本文测试和触及模块的既有测试，记录命令、环境、返回码。缺环境写“未执行/阻塞”，不能写通过。发现与本文矛盾的证据，给出具体路径和测试结果再调整实现。
7. 结束提供修改文件、各问题修复方式、测试结果和残余风险。未经用户指令不 push/发布/部署。一个任务内按下面的工作顺序逐项完成；每个问题单独写回归、修改和检查点，全部完成再宣告任务结束。

## 合并后的执行方法

合并减少的是需要用户分别启动的任务数，原问题的修改步骤和失败验收全部保留。不要一次无测试地改遍整个仓库。

1. 建立本任务工作清单和修复分支，在下列顺序中一次处理一个问题：先回归、再实现、再验证。可为每个问题做本地提交，但无需让用户为每个问题重新开任务。
2. 复用共同的 IO/锁/时间/事务设施，避免多个问题各自实现不兼容的逻辑；公共 helper 改动后运行全部受影响测试。
3. 若达到上下文限制，在工作清单写清已完成 ID、当前提交、测试命令/结果、剩余事项和恢复入口，继续完成同一任务；不能只因任务合并而漏项。
4. 最终用 ID 对照表逐项交付；任何未完成、环境阻塞和兼容性风险单列。不要把只读验证、未知测量、损坏状态当成功。

工作顺序：XRA-01 → XRA-02 → XRA-03 → XRA-04 → XRA-05。

## 修改位置与职责

这套 Xray 三阶段任务只有一套实现，不要在两个仓库重复修。

- 阶段 1、2 在 `rill-xray-agent` canonical 源头仓库修改。Python 对应 `python/rill_xray_agent/`；宿主安装脚本对应 `integrations/xray_bash_onekey/repository_files/scripts/`。本文件的证据仍保留 Xray 审计时的路径，按此映射定位源代码。
- Xray 的 `rill_payload/`、相关宿主 scripts/systemd 和 bundle 是消费镜像。源头两个阶段测试通过并记录准确修复提交后，阶段 3 再用既有同步工具更新消费镜像、canonical pin/digest 和 bundle。
- Xray 自己负责 `install.sh` 的主机调用适配、`geo_update.sh` 及发布 workflow；源头 installer 的事务不能依赖外层恰好有备份。
- 当前 canonical 基线是 `48b19f585df2b89e49ecd99a0714f00f086bb12f`。保持 routeAssist/boundedAuto 的 released=false；升级或失败回滚都不能恢复旧自动执行授权。
- 如果只有一个仓库可访问，先拉取兄弟仓库；不要只修改生成镜像或手工篡改摘要让校验通过。

先落实下载/IPC 有界执行，再完成 Native 生命周期事务与真实摘要验证，最后给代理 payload 升级使用可恢复切换。升级保持 autoConfirmed=false；这里不更新 Xray 的消费 pin，源头阶段 2 完成后统一同步。

## XRA-01 · P1 · 完整 Runtime 探测忽略超时且响应行无界

定位：`rill_payload/python/rill_xray_agent/rillml_artifact.py:487–507、543–585`。

审计证据：已复现函数路径：timeout=.01 传入 _ipc_call，延迟 .2 秒的模拟 reader 仍返回成功。实现没有使用 timeout，直接 stdout.readline()，MAX_IPC_LINE_BYTES 在读完整行后才检查；stdin 写入也可阻塞。真实子进程不输出换行或持续填满 stderr 时可阻塞完整安装/升级探测。

### 必须实现

1. 为 handshake+health 的完整探测建立单调绝对 deadline；传给每次读写的是剩余预算，不能每一步重置整个 timeout。
2. 对 stdout 逐段有界读取，遇到换行/EOF/上限+1/超时立即结束；同时有界排空 stderr，防止 pipe 回压。处理 stdin 写入阻塞与 broken pipe。
3. 使用 Linux 适用 selectors/nonblocking 或受控 reader 线程，保证结束时 kill、wait、关闭所有 pipe，不能留下线程/子进程。
4. 检查 handshake 和 health 的 requestId、apiVersion、kind、版本与必要能力；health 不能接受旧请求响应。把 subprocess.TimeoutExpired 等统一转成 RillMLProbeError。
5. lightweight communicate(timeout) 路径也限制捕获输出和总预算。失败维持 portable fallback 和 previous-good；不得放宽签名/版本验证。

### 验收测试

- 真子进程不响应、无换行持续 stdout、填满 stderr、延迟 handshake/health、stdin 不读取：在配置总时限加小容限内返回错误，无残留子进程。
- 恰好 MAX_IPC_LINE_BYTES 与超过 1 字节；EOF、非法 JSON、错误 requestId/apiVersion、health=false 均拒绝。
- 合法已签名 Runtime 完整握手/健康探测成功，轻量路径兼容。
- 不用只有 sleep mock 的测试证明真实超时；本次 mock 只是复现参数未生效，验收需真实 pipes。

## XRA-02 · P1 · HTTP 下载在完整读取后才检查大小

定位：`rill_payload/python/rill_xray_agent/rillml_artifact.py:440–484`。

审计证据：已复现：响应 read 调用没有 size 参数，max_bytes=10 时仍先读取全部 100 字节再拒绝。index 在验签前发生无界读取；大 body 或持续响应可耗尽 root 安装进程内存。socket timeout 不是整个慢速传输的总时限。

### 必须实现

1. 将 _http_get 改为按块读取和实际计数，上限+1 即拒绝，Content-Length 只能提前拒绝，不能当可信长度。
2. index 有独立小预算，artifact 上限取 min(全局上限、已签名 size 的可接受预算)。下载大 artifact 到唯一 staging 临时文件，流式 hash、长度检查后才发布，避免整包 bytes 常驻内存。
3. 用单调时间约束整个 fetch/所有 retry 的总预算；slow trickle 不能无限延长。明确重试哪些 transient errors，超限/签名失败不反复下载巨量内容。
4. 保持 HTTPS 与最终 URL 校验，审查重定向每跳协议限制；不能签名校验失败仍使用缓存未验证 index。
5. 失败删除自己的临时文件，保持 current/rollback/state 不变。不得删除并发实例的 staging。

### 验收测试

- 没 Content-Length、错误偏小长度、chunked、大响应：最多消费上限+1 字节就拒绝。
- 恰好上限成功，超过 1 字节失败；签名 index 中 size 与实际不符失败。
- 慢速持续流、网络中断、redirect 到非 HTTPS、下载后 hash 错拒绝且无部分激活。
- 真实合法大 artifact 可用，内存使用不随全包大小线性增长；并发下载使用不同临时文件。

## XRA-03 · P1 · 原生 Runtime 激活和回滚缺少原子事务与互斥

定位：`rill_payload/python/rill_xray_agent/rillml_artifact.py:794–849，install/upgrade/reinstall`。

审计证据：已复现：在第二次 rename 注入 OSError，旧 current 已移动到 rollback，current 消失；方法没有恢复。state 写失败则新 binary 与旧 version 元数据并存。rollback 先 unlink current 再 move，同类窗口。没有 lifecycle lock。

### 必须实现

1. 所有 install/upgrade/reinstall/rollback 使用 root-owned 同一锁，从前置状态重读到提交一直覆盖；status 读取一致快照。先锁定再使用下载/探测结果，防止并发覆盖 staging。
2. 候选、原 current、原 rollback 和元数据组成事务；优先采用 immutable version dirs + 原子 current 指针/manifest 切换，或持久 journal。保证任一错误仍有原 current 可用，不能先移走唯一可用副本。
3. fsync 数据和父目录，记录 prepare/commit-intent/terminal；重启恢复以 journal 和实际摘要为准，拒绝混合 generation。
4. rollback 保留足够元数据（完整平台/API/sha/size/probe）且能回滚 rollback 操作本身失败；当前无 previous-good 时明确失败。
5. 启动/read-only status 不偷偷执行主机恢复；由 root 生命周期入口恢复，Runtime 只能报告 recovery-required/fallback。
6. 当前 released=false 的路由开关和 portable fallback 不得改变。

### 验收测试

- 第一/第二 rename、写 state、fsync、权限修复各点失败或崩溃；current/rollback/state 始终一致，原可用 binary 可恢复。
- 两个升级、升级与回滚并发：唯一提交，其余 busy/retry，永不混合文件。
- 重启 recover 两次幂等；正常升级保存一份 previous-good，回滚正确恢复平台/API/摘要。
- rollbackVersion 与二进制不符、candidate 被替换、symlink、损坏 journal 拒绝并保留诊断。

## XRA-04 · P1 · 损坏的 Runtime 二进制被标记 verified=true 并复用

定位：`rill_payload/python/rill_xray_agent/rillml_artifact.py:680–718、867–878、890–900`。

审计证据：已复现：current/rill-runtime 内容为 corrupted，state 仅记录 version=1.5.6，native_status 仍 active/verified=true；status 仅用 is_file，未存/校验签名索引对应 SHA/size。reinstall 遇 available 直接 reused，upgrade 相同版本直接 already-current。无需声称当前代理实际使用 Native 做推理即可成立。

### 必须实现

1. 本任务的激活记录保存已验证 index identity/key、artifact sha256/size、版本、平台/API 和完整 previous-good 对应信息。
2. 本地离线 status 只在安全普通文件、权限/祖先无不可信 symlink、长度摘要与记录一致时声明 verified/available；状态缺证据或摘要不符则 unavailable/recovery-required。
3. 同版本 upgrade/reinstall 仅可复用已验证 current；损坏时重新获取可信同版本资产并探测，不能仅比较 version 字符串。
4. 老 state 无摘要按未验证兼容处理，明确 root 重新验证/安装路径；不能给任意旧文件现算一个 hash 就视为已签名。
5. 避免 TOCTOU：验证的对象必须与激活/执行同一不可变对象或受锁控制。只读 Runtime 查询不得联网/下载/执行写操作。

### 验收测试

- current 改一个字节、截断、替成普通无效文件或 symlink：verified=false、available=false，不能 reused/already-current。
- 完整匹配 signed artifact 本地离线 verified=true；无网络 status 仍能工作。
- 老格式 state 无证据明确降级，previous-good 完整验证后可回滚。
- status 与 root lifecycle 并发读不得读到新文件旧 metadata。

## XRA-05 · P1 · 代理升级先删除旧 payload，失败后没有组件回滚

定位：`scripts/rill_xray_agent_install.sh:66–78、131–207；install.sh:10054–10110`。

审计证据：静态确认：--upgrade rm -rf 旧 PROVENANCE/bin/config/python/share/systemd，随后 cp -a 新 payload。set -e 让复制/服务重启/模式恢复/健康失败直接退出，无旧 payload journal 或恢复；rxa_reconcile_release 调用失败后只删除下载 tmp 并 return 1。未验证真实 systemd 升级失败恢复。

### 必须实现

1. 在删除/覆盖任何现用文件之前完成候选树解包、目录/权限/完整性、Python/shell 语法和 host compatibility 检查。完整 payload 在独立 staging 上核验，不在 live 树内边拷贝边修。
2. 持统一生命周期锁；备份旧组件树、manager scripts、unit files 和 service active/enabled 状态，保留 durable config/runtime/audit/transaction 树。
3. 用原子可恢复方式切组件版本；修改 units 后 daemon-reload，按旧模式恢复运行，再进行真实 socket/mode/health gate。只有全部通过才移除旧版本或更新 managed.version。
4. 任一失败恢复旧 payload/scripts/units/服务状态并验证；原始更新失败仍返回非零。恢复失败报告 recovery-required 并保留手动恢复材料。
5. 安全规则：升级必须撤销 autoConfirmed。回滚组件不能把旧 auto 授权重新启用；executionEpoch 应使旧 queued requests 作废。
6. standalone installer、bundle bootstrap、主脚本 release reconcile 使用同一事务，不依赖外层调用者恰好有备份。
7. DESTDIR 仅写前缀路径，不能碰本机 /etc、/opt 或 systemctl。

### 验收测试

- cp/磁盘满、unit install、daemon-reload、restart、socket timeout、模式恢复、health 各点故障：旧组件仍完整、模式恢复、返回非零。
- 三模式 normal/observe-only/safe-disabled 均覆盖；升级失败也保持 autoConfirmed=false，待执行旧计划失效。
- SIGTERM/kill -9 在 prepare/switch/health/commit 处，重启 root recover 幂等。
- 在临时 DESTDIR 运行并对所有未前缀绝对路径设置拒绝桩；确认没有主机变更。
- 真实 Linux PID1 qualification 执行 rill verify 和 install/uninstall transaction tests。

## 任务完成条件

为本文每个问题提交实现、回归和结果；输出“ID → 修改位置 → 正常/失败验证 → 未完成项”的清单。生产实现可独立复核、历史数据兼容、错误不假成功。新增本任务修复记录，保留审计证据原文。需要后续阶段时写出 exact commit 和下一份提示词文件名。

## 建议的实际验证入口

先在 rill-xray-agent canonical 根目录的隔离 Linux 环境执行新增行为回归，再执行源头资格：

```sh
python3 scripts/run_python_tests.py
python3 scripts/build_canonical_manifest.py --check
python3 scripts/verify_no_build_gate.py
```

按 sync/release_automation 工具实际 Usage 同步，不直接覆盖所有文件。随后在 Xray 根目录：

```sh
bash -n install.sh
python3 .github/test/test_release_automation.py
python3 .github/test/test_convergence.py
bash .github/test/test_rill_xray_agent.sh
bash .github/test/test_rill_xray_agent_operational_intelligence.sh
bash .github/test/test_rill_xray_agent_verify_modes.sh
bash .github/test/test_install_uninstall_transaction.sh
bash .github/test/test_xray_update_transaction.sh
bash .github/test/test_nginx_update_rollback.sh
```

使用修复后 canonical 的 manifest 跑 integrations/xray_bash_onekey/tools/verify_xray_payload.py，参数依次为 Xray 仓库路径、canonical manifest 路径与 --expected-canonical-digest。真实 PID1/DAC/安装升级/发行版矩阵按现有 CI 执行。所有 root/防火墙/ACME 操作在一次性 VM/容器，不能在用户生产机验证破坏路径。Shell Release 阶段的新增 gate 测试要用 gh/API 桩验证“零写调用”，随后真正 qualification 成功才允许用户决定发布。
