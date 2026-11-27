# fix-20261120-p2e — invalid run (network)

Commit `102f52e1`.

Retry of OPS-32 at the final commit. The Bash side could not download Nginx:

```
98.4%curl: (18) Transferred a partial file
[错误]  Nginx 下载 失败
install_exit=124
```

OPS-32/ws is therefore `HARNESS-ERROR` (`bash: missing location.txt`), not a
product result. The run was stopped before the reality phase finished.

The same commit has a valid OPS-32 result in `fix-20261120-p2d`
(ws `PASS`, reality `BLOCKER` from the recovery-window assertion).
