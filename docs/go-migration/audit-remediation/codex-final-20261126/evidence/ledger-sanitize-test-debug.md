# 验收器/脱敏器测试调试记录

两次修正都发生在新增的测试代码，不是产品运行结果；原始失败已在交付日志之外的 Codex 命令输出中产生，本记录保留实际命令、rc 和原因。

1. 命令：`python3 -m unittest tests.e2e-diff.collect.test_build_ledger tests.e2e-diff.collect.test_sanitize_evidence -q`；rc=1。34 个验收器测试通过，但 sanitizer 测试导入失败：`ModuleNotFoundError: No module named 'sanitize_evidence'`。修复：测试显式将自身目录加入 `sys.path`。
2. 同一命令；rc=1。34 个验收器测试通过，新测试唯一断言失败：sanitizer 将测试用 home 路径的宿主前缀改成 `<workspace>`，并按契约保留后缀 `/.config`；修正测试期望，没有改产品脱敏行为。
3. 最终同一命令；35 tests，rc=0。完整输出见 `ledger-and-sanitize-tests.log`。
