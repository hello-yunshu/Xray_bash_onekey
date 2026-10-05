# 阶段 2：Rill 源头备份与隐私

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

工作顺序：XRA-07 → XRA-08 → XRA-09。

## 修改位置与职责

这套 Xray 三阶段任务只有一套实现，不要在两个仓库重复修。

- 阶段 1、2 在 `rill-xray-agent` canonical 源头仓库修改。Python 对应 `python/rill_xray_agent/`；宿主安装脚本对应 `integrations/xray_bash_onekey/repository_files/scripts/`。本文件的证据仍保留 Xray 审计时的路径，按此映射定位源代码。
- Xray 的 `rill_payload/`、相关宿主 scripts/systemd 和 bundle 是消费镜像。源头两个阶段测试通过并记录准确修复提交后，阶段 3 再用既有同步工具更新消费镜像、canonical pin/digest 和 bundle。
- Xray 自己负责 `install.sh` 的主机调用适配、`geo_update.sh` 及发布 workflow；源头 installer 的事务不能依赖外层恰好有备份。
- 当前 canonical 基线是 `48b19f585df2b89e49ecd99a0714f00f086bb12f`。保持 routeAssist/boundedAuto 的 released=false；升级或失败回滚都不能恢复旧自动执行授权。
- 如果只有一个仓库可访问，先拉取兄弟仓库；不要只修改生成镜像或手工篡改摘要让校验通过。

先修完整写入，再修备份资源/schema 与隐私过滤。完成源头阶段 1/2 后运行完整 canonical 资格，并保留准确修复 commit/digest，交给 Xray 阶段 3 消费。

## XRA-07 · P2 · 安全文件写入未处理 short write

定位：`rill_payload/python/rill_xray_agent/safe_fs.py:16–28；backup.py restore_backup`。

审计证据：已复现 syscall 故障桩：要求写 6 字节的 os.write 返回 2，write_beneath 仍 fsync 并 replace 发布；只调用一次 write。真正 POSIX short write 可因资源/信号等出现，备份恢复可能静默得到截断文件。dirfd/no-follow 设计本身正确，应保留。

### 必须实现

1. 使用 memoryview 和偏移循环写到所有字节，处理 InterruptedError；返回 0 或负/异常立即失败，不能无限循环。
2. 只有完整写入、fsync 成功才 replace；所有异常清理自己创建的临时文件并关闭 FD，旧目标字节保持不变。
3. 使用不可预测唯一临时文件名和 O_EXCL；避免同 PID 重试被残留 temp 阻塞。清理使用父 dirfd，不经不可信路径重解析。
4. 保持 O_NOFOLLOW、逐层 dirfd、目录 fsync、mode 等安全属性，不能用 Path.write_bytes 取代整个安全路径实现。
5. backup restore 在发布目录前校验每个已落盘文件长度/hash。

### 验收测试

- mock write 依次返回 2/1/3，最终六字节正确；InterruptedError 后重试。
- 0 write、ENOSPC、fsync/replace 失败：旧文件不变、无临时文件泄漏、FD 全关闭。
- 真 Linux dirfd symlink race/no-follow 测试仍通过；正常空内容/大内容/嵌套目录正确。
- restore 后逐文件摘要与 manifest 相同。

## XRA-08 · P1 · 备份 MANIFEST 在资源和 schema 检查前无界解压

定位：`rill_payload/python/rill_xray_agent/backup.py:23–38`。

审计证据：已复现：MANIFEST.json 包含超过 MAX_MEMBER=16 MiB 的前导空白和 {"entries":[]}，verify_backup 接受；manifest 在 z.read 和 json.loads 后才遍历限制，且被 continue 排除。也接受无 schemaVersion/kind 等必要字段的 manifest。此处是备份库路径，不断言现有 CLI 暴露了相同命令。

### 必须实现

1. 在解压/JSON 前对所有 ZIP member（包括 MANIFEST）数量、类型、名字、声明大小/压缩比预检；manifest 独立更小合理预算，并有界流读取实际字节。
2. 严格验证 manifest schemaVersion/kind/platform/entries 的类型和必需字段；entries 唯一路径、size 为非负整数且不为 bool、SHA64、mode 只允许正常权限位，拒绝 special file/setuid 权限。
3. 预算包括 manifest 和所有实际解压字节；不要只按 file_size 判断，len/data mismatch 与 CRC 都检查。
4. restore 只允许已验证普通数据文件，拒绝 symlink/hardlink/路径穿越/重复条目。旧 schema 要有明确迁移而不是缺字段默认接收。
5. restore 的 stage->target 与 old removal 故障要保持可恢复；修本任务的 short write 后重新校验完整落盘内容再发布。

### 验收测试

- 当前 oversized manifest fixture 必须限额拒绝，实际读取 <=预算+1；少字段 {entries:[]} 必须 schema 拒绝。
- manifest 或数据 under-declared、总量超限、重复 entries/ZIP members、CRC 错、setuid/symlink、绝对/../ 路径拒绝。
- 合法历史 schema 的支持/不支持明确；正常 backup-create/verify/restore roundtrip 哈希一致。
- 故障发生在 rename target 前/后，保留原状态或可恢复 previous，不能半目录发布。

## XRA-09 · P2 · 备份隐私过滤仅检查前 2 MiB

定位：`rill_payload/python/rill_xray_agent/backup.py:6–17`。

审计证据：已复现：中性文件名 timeline.json 的前 2 MiB 是普通内容，后面有合成 vless://credential，safe_content 返回 true，会进入 create_backup payload。名称/关键字黑名单也不构成结构化隐私边界。未发现或读取用户真实 credentials。

### 必须实现

1. 确定备份允许的状态类别，优先使用 schema 字段白名单与脱敏投影，避免扫描任意 state_root 文件后按黑名单打包。
2. 如果保留内容扫描，必须覆盖整个允许大小内容，分块扫描保留跨块关键字尾部；遇到无法解析/未知格式默认排除并报告安全原因。禁止只扫描前缀。
3. 对秘密字段/URI/private key/token/authorization 等做递归拒绝或脱敏。UUID/email/域名等是否允许由现有隐私契约决定，文档清楚而非一概猜测。
4. create_backup 也执行成员/单文件/总量上限；不能先把任意大文件全部 read_bytes 到内存。输出不得含原始秘密或日志打印秘密。
5. 保持可恢复的必要非敏感 state；过滤结果给文件计数/类别，不能把用户密钥值放进报告。

### 验收测试

- 合成秘密分别在开头、2 MiB 边界前后、最后、跨扫描块位置；所有被拒绝/脱敏。
- JSON 嵌套 token/privateKey、PEM、URI、未知二进制格式与大文件都有明确结果。
- 正常安全状态可 roundtrip；脱敏不得形成不合法 JSON 或伪造可恢复语义。
- 解包最终 backup 并搜索合成秘密全文，不仅调用 safe_content 断言。

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
