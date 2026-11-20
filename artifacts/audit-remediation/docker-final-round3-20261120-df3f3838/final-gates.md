# 最终门禁（候选 `df3f3838`）

| 门禁 | 结果 | 关键证据 |
| --- | --- | --- |
| D1 静态/单测/race/Bash 语法 | PASS | `gate-final.log`、`race-final.log`（8 包 rc=0）、`bash-syntax.log` |
| D1 98 项矩阵 | PASS | 54 MATCH + 40 CORE + 4 REFUSED + 6 A1，0 GAP |
| D1 F28/F08/F18 | NOT_RERUN_AT_CANDIDATE | 最近绿证 57/0、129/0、178/0；候选未触及 share 路径 |
| D2 候选 SHA 关键项 | PARTIAL | A1/A3 红绿；A2 影响面复用；A4 非缺陷；A5 部分 |
| D3 CI | PASS | `aa4b9da9` 上 7 个 workflow 全 success（含 Test Install） |
| D4 Docker 必需项 | INCOMPLETE | B4 OPS/subscripts、C3、C4 soak 未完成 |
| 正式发布 | NO-GO / 未授权 | VPS_DEFERRED 与任务书禁止 |

## 已通过的真实执行

- M1–M10 双端 fresh + 幂等 + 真实客户端 L4；E1–E8 Go 侧编辑全满足。
- OPS-09/19/21/31/32 双端真实执行；OPS Go sweep 36 PASS；OPS-08/27 Go 命令 + 真实 `nginx -t`。
- 冷恢复 source 8/8、target 19/19；R1/R2/INJ 106 PASS / 0 FAIL；P3 xhttp 62/62。
- Pebble 真实 ACME（Go）；Bash 侧为 `BASH_DELEGATES_GO`，纯 `acme.sh` BLOCKED。
- A1 真实 root 证书清理；A3 pre-fix `enabled/isolate` → candidate `not-applicable`。
- A4 真实 Xray 26.10.31 四种路径交叉 200/301；父提交负例测试通过，判定非缺陷。

## 阻断项（Docker 候选 NO-GO 的原因）

1. 34 个 OPS 仅 5 个双端；17 个 Go sweep、2 个 Go 命令、10 个未执行。任务书明确禁止
   Go-only sweep 替代。
2. 9 个 subscripts 未逐项执行/确认真实路径。
3. 多版本 Xray/Bash 矩阵、第二发行版 smoke 未执行。
4. 30 分钟 + 两个调度周期 soak 未执行。
5. M8 纯 Bash ACME 未证明；A2/A3/E1–E8 的 Bash 侧交互未双端。
6. Test Install 在 `aa4b9da9` 通过，但历史“静默退出”的根因未定位，不能算已修复。

## 结论

- **Docker 开发候选：`NO_GO_FOR_DOCKER_QUALIFIED_CANDIDATE`**。安全整改与核心
  双端/真实客户端/迁移/故障注入已通过，但 B4/C3/C4 的容器必需项未完成，按 D4 只能 NO-GO。
- **正式发布：`NO_GO_NOT_AUTHORIZED`**。不合并不打 tag 不发版；VPS_DEFERRED 项
  需独立测试机与授权后另行验证。
