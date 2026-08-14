# Xray_bash_onekey：IPv4 / IPv6 双栈支持专项改造执行提示词

> 适用仓库：`hello-yunshu/Xray_bash_onekey`
>
> 任务性质：基于当前 `main` 最新源码进行专项审计、最小化设计、实现、测试与文档收口。
>
> **语言原则：中文是主要/权威文案源。其他语言由仓库现有自动翻译流程派生，不要人工逐语言翻译或重复维护。**

---

## 0. 总执行原则

你正在维护一个已经进入稳定阶段、具备升级/重配置/回滚/国际化机制的公开 Xray 一键安装项目。

本任务的目标不是“为了支持 IPv6 大改网络栈”，而是：

> **在不破坏现有 IPv4 用户、不破坏既有配置兼容性、不扩大不必要改动面的前提下，将当前“IPv4 或 IPv6 二选一”的半成品 IPv6 能力，补全为可靠、可检测、可降级、可测试的 IPv4 / IPv6 双栈能力。**

必须先审计当前最新源码，再实施；不能依据旧印象直接改代码。

优先遵循以下原则：

1. **最小改动优先**：只修改双栈真正需要修改的路径。
2. **向后兼容优先**：已有 IPv4、IPv6、手动 IP、TLS、Reality、None、XTLS 配置必须继续可用。
3. **不做伪双栈**：不能仅因为网卡存在 IPv6 地址就宣布双栈可用。
4. **不引入无关重构**：本任务不是清理全项目架构的机会。
5. **先证据后改动**：任何涉及 Xray/Nginx 监听行为、URI 格式、DNS 行为的修改，都必须有代码/官方行为/测试依据。
6. **中文为源**：新增用户可见文案优先中文，并接入现有 gettext/i18n 机制；不要手写英语、法语、俄语、韩语等翻译。
7. **自动翻译文件视仓库机制处理**：如果 CI/既有脚本会自动生成翻译产物，按既有流程生成；不要人工翻译。
8. **不能为了“看起来更现代”而改变成熟行为**。
9. **所有测试尽可能在 Docker/可重复环境中完成；真实 IPv6 条件无法稳定提供时，必须用确定性 mock 覆盖逻辑，并增加可选真实双栈 smoke test，而不是制造 flaky CI。**
10. 除非存在真正阻塞实现且无法从源码/测试推断，否则自行完成审计、实现、测试和复检，不要在中途停在“建议阶段”。

---

# 1. 已确认的当前基线——先验证，不要盲改

开始编码前，必须在最新 `main` 中重新确认以下事实。若最新源码已经变化，以最新源码为准，并在最终报告中说明差异。

## 1.1 Xray inbound 的 `0.0.0.0` 不应被误判为 IPv6 阻塞点

Xray-core 当前官方文档明确说明：

- `listen: "0.0.0.0"`
- `listen: "::"`

在 Xray 的默认行为下均可同时监听 IPv4 和 IPv6；
只有显式使用对应 `v6only` 行为时才限定 IPv6-only。

因此：

**禁止为了本任务把所有 Xray inbound 的 `0.0.0.0` 机械替换成 `::`。**

除非你通过当前版本 Xray 的实际测试证明某一特定入站存在例外，否则保留现有监听写法。

需要做的是：

- 测试实际 listener；
- 确认 IPv4/IPv6 都能到达；
- 不做没有收益的 listener 重构。

---

## 1.2 Nginx 当前已经具备 IPv4 + IPv6 listener

当前模板已有类似：

```nginx
listen 80;
listen [::]:80;

listen 443 ssl reuseport;
listen [::]:443 ssl reuseport;

listen 443 quic reuseport;
listen [::]:443 quic reuseport;
```

因此 Nginx 基本监听层不是本次主要问题。

要求：

- 保留现有双 listener；
- 对生成后的 Nginx 配置做语法检查；
- 不要重复增加 `[::]`；
- 不要因为双栈任务重新设计 Nginx 架构。

---

## 1.3 当前已有 IPv4 / IPv6 公网地址探测能力

当前 `get_public_ip()` 已经根据 family 使用：

- `curl -4`
- `curl -6`

因此不要另起一套重复的公网地址获取实现。

应在其基础上抽象“网络能力检测”：

```text
public_ipv4
public_ipv6
has_ipv4
has_ipv6
```

必要时再增加资格状态，但不要让全局变量失控。

---

## 1.4 当前已有 A/AAAA 解析帮助函数

仓库已经存在 `resolve_domain_ips()`，会解析域名 A/AAAA，并且 decoy 逻辑已经利用它与本机公网 IP 集合比对。

因此：

> **优先复用/扩展现有 DNS helper，不要为 TLS 域名检查再创建一套互相不一致的 resolver。**

如果需要区分 family，可以基于现有 resolver 增加：

```text
resolve_domain_ipv4s()
resolve_domain_ipv6s()
```

或统一返回后按 IP 类型分类。

核心要求是“一个 DNS 语义源”，而不是多个函数各自实现 dig/nslookup/ping。

---

# 2. 当前真正需要解决的问题

本次实现要围绕以下真实问题，而不是泛化“IPv6 支持”。

---

## 2.1 安装交互仍然是 IPv4 / IPv6 二选一

当前类似：

```text
1: IPv4（默认）
2: IPv6
3: 手动输入
```

以及 TLS 域名配置中：

```text
请选择公网IP(IPv4/IPv6)或手动输入域名
```

这使系统即使服务器同时具备可用 IPv4 和 IPv6，也只能选一个作为主状态。

### 目标

为**新安装**引入明确的自动网络能力判断，推荐语义：

```text
自动检测（推荐）
IPv4
IPv6
手动输入
```

“自动检测”逻辑：

```text
IPv4 可用 + IPv6 可用 -> dual
只有 IPv4 可用          -> ipv4
只有 IPv6 可用          -> ipv6
两者都不可用            -> 明确失败/要求手动输入
```

注意：

- 不要简单用“网卡上有地址”作为可用依据；
- 公网出口探测至少必须成功；
- 对 inbound 可达性，应通过生成配置后的 listener/本机 smoke test，以及域名模式下 DNS 资格检查共同保证；
- **已有安装重配置时不得静默从 IPv4 强行切换为 dual。**
- 如果用户选择“保留旧配置重新部署”，必须保留旧网络模式/旧 `host` 行为。
- 用户显式进入网络设置时，才允许重新自动检测或切换 family。

---

# 3. 配置模型：向后兼容地增加双栈状态

当前安装状态主要依赖：

```json
{
  "host": "...",
  "ip_version": "IPv4"
}
```

或者：

```json
{
  "host": "...",
  "ip_version": "IPv6"
}
```

甚至手动输入时 `ip_version` 可能保存自定义值。

**禁止直接删除或重新定义这两个字段。**

先全仓搜索：

```text
info_extraction host
info_extraction ip_version
.host
.ip_version
```

包括：

- `install.sh`
- `scripts/`
- `rill_payload/`
- Docker/测试代码
- 升级与重配置逻辑
- 分享链接
- Clash 输出
- Doctor/诊断
- 备份/恢复

确认消费方后，再增加最小新字段。

推荐兼容模型示例：

```json
{
  "host": "兼容旧逻辑的 canonical host",
  "ip_version": "兼容旧逻辑的 legacy value",

  "network_mode": "auto|ipv4|ipv6|dual|manual",
  "ipv4_address": "1.2.3.4",
  "ipv6_address": "2001:db8::1"
}
```

字段名可以根据仓库既有命名风格调整，但语义必须清晰。

### 兼容规则

#### TLS + 域名

```text
host = 用户域名
network_mode = 实际资格结果
ipv4_address = 可用时保存
ipv6_address = 可用时保存
```

分享链接继续使用域名，不需要为 A/AAAA 各生成一条链接。

#### Reality / None / XTLS 等直接 IP 模式

若双栈：

```text
host = 保留一个 canonical/legacy 地址用于老代码兼容
ipv4_address = IPv4
ipv6_address = IPv6
network_mode = dual
```

canonical `host` 的选择必须保守：

- 优先保持现有默认 IPv4 行为，除非用户显式选择 IPv6；
- 不要因为加 dual 就让老路径突然拿到 IPv6 literal；
- 新的双栈链接输出逻辑从 `ipv4_address` / `ipv6_address` 生成两份客户端入口。

#### 老配置

如果配置中没有新字段：

```text
ip_version == IPv4 -> 推断 ipv4
ip_version == IPv6 -> 推断 ipv6
其他旧手动值       -> manual
```

但：

- 不要求在每次读取时强制重写旧 JSON；
- 可以运行时兼容解析；
- 若重配置/重新保存，则补齐新字段；
- 必须保证升级、回滚、保留配置重新部署不失败。

---

# 4. TLS 域名资格检查必须从“单个 ping IP”升级为 A/AAAA 集合验证

当前 `domain_check()` 的关键问题是：

- 用户先选 IPv4 或 IPv6；
- 使用 `ping -4` / `ping -6` 提取一个地址；
- 将一个 `domain_ip` 与一个 `local_ip` 比较。

这是单栈逻辑。

### 新逻辑

TLS 模式下输入域名后，应自动解析：

```text
A records
AAAA records
```

同时探测：

```text
本机公网 IPv4
本机公网 IPv6
```

再按 family 独立校验。

建议形成结构化结果：

```text
IPv4:
  server available?
  A record exists?
  A matches server IPv4?

IPv6:
  server available?
  AAAA exists?
  AAAA matches server IPv6?
```

---

## 4.1 必须防止“坏 AAAA”或“坏 A”

这是双栈支持中非常重要的边界。

例如：

```text
服务器 IPv4 正常
A -> 当前服务器 IPv4

服务器 IPv6 不可用
AAAA -> 一个错误/旧 IPv6
```

不能仅因为 A 正确就简单判定“域名校验通过”。

原因：

> 双栈客户端可能选择 AAAA，最终出现一部分用户随机连接失败。

因此建议采用以下资格规则：

### 情况 A：只发布 A，且 A 正确

允许：

```text
network_mode = ipv4
```

提示中文：

```text
当前域名仅通过 IPv4 校验。
```

### 情况 B：只发布 AAAA，且 AAAA 正确

允许：

```text
network_mode = ipv6
```

### 情况 C：A + AAAA 都存在，且分别正确

允许：

```text
network_mode = dual
```

这是最佳状态。

### 情况 D：A 正确，但存在错误 AAAA

默认视为高风险配置：

- 明确中文警告；
- 不得宣称双栈通过；
- 推荐阻止继续，要求修正/删除错误 AAAA；
- 若仓库已有“高级用户强制继续”惯例，可沿用，但必须显式风险确认，不能默认继续。

### 情况 E：AAAA 正确，但存在错误 A

同理处理。

### 情况 F：A/AAAA 均不存在或都不匹配

失败。

---

## 4.2 不再依赖 `ping` 解析域名

DNS 资格检查不得依赖：

```bash
ping -4
ping -6
```

来取得首个地址。

必须复用仓库 DNS helper，以集合方式判断。

同时考虑：

- 多 A；
- 多 AAAA；
- DNS 返回顺序变化；
- CNAME；
- DNS 缓存；
- 某 family 缺失；
- DNS 服务不可达时的清晰错误。

---

# 5. IPv6 literal 分享链接必须专项修复

当前 VLESS 链接生成逻辑将 `host` 通过通用 URL quote 后直接放进：

```text
vless://UUID@HOST:PORT
```

对于 IPv6 literal，这类处理容易得到类似：

```text
2001%3Adb8%3A%3A1
```

但 URI authority 中 IPv6 literal 应使用：

```text
[2001:db8::1]
```

例如：

```text
vless://UUID@[2001:db8::1]:443?...
```

### 必须把“authority host 格式”和“query value 编码”拆开

不要再用一个 `quoted_host` 同时承担全部角色。

建议增加类似：

```bash
format_uri_authority_host()
urlencode_query_value()
urlencode_fragment_value()
```

其中：

### `format_uri_authority_host()`

输入：

```text
1.2.3.4
example.com
2001:db8::1
[2001:db8::1]
```

输出：

```text
1.2.3.4
example.com
[2001:db8::1]
[2001:db8::1]
```

要求：

- 不重复加括号；
- 只对 IPv6 literal 加 `[]`；
- 不要把 `:` percent-encode 后放在 authority 中。

### Query 参数

例如：

```text
host=
sni=
target=
path=
serviceName=
```

根据参数语义分别编码。

不要把 authority 所需的方括号误带入：

```text
host=
```

等业务字段中。

### Fragment / 节点名

继续单独安全 URL encode。

---

# 6. 双栈模式下的分享链接策略

## 6.1 TLS + 域名

域名已经同时有正确 A/AAAA 时：

**仍然生成一条域名链接。**

例如：

```text
vless://UUID@example.com:443...
```

客户端/系统自行通过 DNS 和网络栈选择 IPv4/IPv6。

不要生成：

```text
IPv4 域名链接
IPv6 域名链接
```

这种没有必要的重复项。

---

## 6.2 Reality / None / XTLS 等直接 IP

如果：

```text
network_mode = dual
```

并且没有域名作为客户端 server：

应分别生成：

```text
IPv4 分享链接
IPv6 分享链接
```

以及相应 QR（若当前产品交互适合）。

原因：

一条 URI 的 authority 只能是一个具体 host。

显示时使用中文明确区分：

```text
IPv4 分享链接
IPv6 分享链接
```

不要要求用户理解 `network_mode` 内部字段。

### 单栈时

保持现有输出行为。

---

# 7. Clash 配置需要检查 IPv6 literal，而不是假定能用

当前 Clash YAML 生成中存在类似：

```yaml
server: <host>
```

以及名称、Host header 等地方复用 `host`。

必须新增测试：

```text
IPv4 host
domain host
IPv6 literal host
```

要求：

- YAML 可被解析；
- IPv6 literal 不能因冒号造成错误；
- 必要时统一进行 YAML 安全 quoting；
- 不能把 URI authority 的 `[IPv6]` 格式机械复用到所有 YAML 字段；
- TLS 模式下 `server` 应继续使用域名；
- Reality/direct dual 模式下应能分别生成 IPv4/IPv6 客户端配置，若现有产品只展示一份 Clash 配置，则必须设计清楚如何暴露两个入口，不能悄悄丢弃 IPv6。

若 Clash 对项目某传输本来就不支持，继续保留原有“不支持提示”，不要借此任务扩大协议支持范围。

---

# 8. 不要把出站 Happy Eyeballs 混入本次任务

Xray-core 当前确实已经具备 Happy Eyeballs 等更成熟的 IPv4/IPv6 出站策略。

但本次用户需求是：

> 服务器端 IPv4 和 IPv6 能否同时支持。

这主要是：

- inbound 可达性；
- DNS；
- 客户端入口；
- 分享链接；
- 配置状态；

的问题。

因此：

**禁止因为看到 Xray 新版支持 Happy Eyeballs，就顺手修改全局 outbound `domainStrategy` / sockopt。**

除非当前仓库已有某一 outbound 配置明确因为双栈功能无法工作，并且有测试证明必须修改，否则将 Happy Eyeballs 留作独立后续优化项。

这可以在最终报告的“可选后续项”中说明，但不要加入本次核心 patch。

---

# 9. Rill Xray Agent / 诊断兼容审计

仓库已有 Rill 相关集成/载荷。

本次必须搜索：

```text
host
ip_version
public_ip
IPv4
IPv6
install_config.json
```

确认 Rill/Doctor/诊断代码是否假定：

```text
只能有一个 host
ip_version 只能是 IPv4/IPv6
```

如果会受新字段影响：

进行**最小兼容改造**。

建议网络事实可扩展为：

```text
network_mode
ipv4_address
ipv6_address
canonical_host
```

但：

- 不要借双栈任务扩建 Rill 的 AI 能力；
- 不要改模型协议；
- 不要改不相关 observation；
- 只保证诊断结果不会错误报告“IPv6 不存在”或把 dual 当成异常。

---

# 10. 中文/i18n 是本次明确约束

这是本次实现必须特别遵守的要求。

## 10.1 中文是主要文案源

新增用户可见文字，以中文编写，例如：

```text
自动检测（推荐）
已检测到 IPv4 和 IPv6 均可用，将启用双栈
当前仅 IPv4 可用
当前仅 IPv6 可用
域名 A 记录校验通过
域名 AAAA 记录校验通过
检测到错误的 AAAA 记录，可能导致部分客户端连接失败
IPv4 分享链接
IPv6 分享链接
```

根据现有 shell 风格用：

```bash
gettext "..."
```

包裹需要翻译的文本。

---

## 10.2 不要人工维护所有翻译

仓库已经存在自动翻译体系。

因此禁止：

- 手写同一新文案的英语版本；
- 手写法语/俄语/韩语/波斯语等版本；
- 在多个 README 语言副本里逐份人工复制修改；
- 因为“翻译完整性”扩大 commit。

正确做法：

1. 修改中文主文案；
2. 确保 gettext 提取链仍可识别；
3. 根据仓库现有 i18n workflow 更新必要的中文源/POT；
4. 如果仓库自动翻译 action 会生成其他语言，则让现有流程处理；
5. 若测试环境支持调用仓库已有自动翻译脚本，可以按原流程运行；
6. 不要自行翻译生成内容。

### 技术名词保持原样

以下内容无需强行翻译：

```text
IPv4
IPv6
Dual Stack
A
AAAA
VLESS
Reality
XTLS
Nginx
Xray
TLS
WebSocket
gRPC
xHTTP
Clash
```

中文句子中自然使用即可。

---

# 11. README / 文档修改范围

当前中文 README 的准备工作仍有类似：

```text
安装 TLS 版本：需准备域名并添加 A 记录
```

双栈支持完成后，应修改中文源文档，使实际行为一致。

建议语义：

```text
安装 TLS 版本：需准备域名，并根据服务器可用网络配置正确的 A 和/或 AAAA 记录；
双栈服务器建议同时配置正确的 A 与 AAAA。
```

同时简要增加：

```text
- 自动检测 IPv4 / IPv6
- 双栈可用时支持同时提供 IPv4 与 IPv6
- 直接 IP 节点在双栈模式下分别输出 IPv4/IPv6 分享入口
```

注意：

- 不要把 README 改成 IPv6 教程；
- 不需要大篇介绍协议；
- 文档必须与实际代码一致；
- 只修改中文主文档及现有流程要求的源文件；
- 其他语言交给自动翻译。

---

# 12. 证书/ACME 相关边界必须测试

TLS 双栈支持不能只停留在 DNS 比对。

需要确认现有 ACME HTTP-01/webroot 流程在以下情况下不会被新逻辑破坏：

```text
A only
AAAA only
A + AAAA
```

重点：

- Nginx 80 已监听 IPv4/IPv6；
- DNS 若发布 AAAA，IPv6 路径必须真实可达，否则 ACME/客户端可能失败；
- 新逻辑检测到“发布了错误 AAAA”时，应尽量在申请证书之前阻止，而不是等 ACME 报模糊错误；
- 保留现有证书申请/续签/回滚路径。

不要更换 ACME 工具，不要更换挑战类型，除非现有测试证明必须。

---

# 13. 手动 IP / 特殊服务器商域名兼容

当前存在“手动输入”以及服务器商仅提供域名/CNAME 的特殊路径。

这类路径不能因为双栈模型被删除。

要求：

- 保留 legacy manual 行为；
- 将 `network_mode=manual` 或等价状态与 IPv4/IPv6/dual 区分；
- 不对无法可靠判断 family 的自定义 hostname 强行标记为 dual；
- 分享链接仍正确；
- 旧 `ip_version` 中保存手动值的历史配置必须可读。

---

# 14. 实现时必须检查的关键消费路径

至少逐项搜索并检查：

```text
domain_check
ip_check
get_public_ip
resolve_domain_ips
ip_lists_overlap

install_config_tls_ws
install_config_reality
install_config_none
install_config_xtls

info_extraction host
info_extraction ip_version

generate_vless_link
vless_urlquote
generate_clash_config
install_link_image

旧配置读取
重新安装
模式切换
保留配置重新部署
备份
失败回滚
脚本升级

证书申请
证书续期
Nginx 配置
Reality + Nginx
ws/gRPC/xHTTP ONLY
XTLS ONLY

Docker
tests
scripts
rill_payload
Doctor/诊断
```

不能只改 `ip_check()` 就结束任务。

---

# 15. 推荐的新辅助函数边界

可根据现有代码风格调整，不要求机械采用以下名字，但职责应分离。

### 网络能力

```text
detect_public_network_capabilities
get_public_ipv4
get_public_ipv6
```

若现有 `get_public_ip family` 足够，就不重复封装。

### IP 类型判断

```text
is_ipv4_literal
is_ipv6_literal
```

避免使用“只要包含冒号就是 IPv6”这种过度粗糙判断，至少要兼容常见 IPv6 格式和已有 `[]`。

### DNS

```text
resolve_domain_ips
classify_resolved_ips
validate_domain_network_records
```

### 客户端 Host 编码

```text
format_uri_authority_host
urlencode_query_value
urlencode_fragment_value
yaml_quote_scalar
```

只添加确有必要的函数，不为了函数化而函数化。

---

# 16. 测试矩阵——必须覆盖

不能只跑 `bash -n`。

至少需要以下逻辑/集成测试。

---

## 16.1 公网能力检测

```text
IPv4 成功，IPv6 失败
IPv4 失败，IPv6 成功
IPv4 成功，IPv6 成功
IPv4/IPv6 都失败
curl 超时
返回空值
返回非法值
```

必要时 mock `curl`。

---

## 16.2 DNS

```text
A only，匹配
AAAA only，匹配
A + AAAA，都匹配

A 匹配 + AAAA 错误
AAAA 匹配 + A 错误

A 存在但服务器无 IPv4
AAAA 存在但服务器无 IPv6

多 A，其中一个匹配
多 AAAA，其中一个匹配

无记录
解析失败
CNAME 最终得到 A/AAAA
```

明确写断言，不要只看输出。

---

## 16.3 新旧配置兼容

至少构造：

```json
{"host":"1.2.3.4","ip_version":"IPv4"}
```

```json
{"host":"2001:db8::1","ip_version":"IPv6"}
```

```json
{"host":"custom.example","ip_version":"custom.example"}
```

以及新：

```json
{
  "host":"1.2.3.4",
  "ip_version":"IPv4",
  "network_mode":"dual",
  "ipv4_address":"1.2.3.4",
  "ipv6_address":"2001:db8::1"
}
```

验证：

- 读取；
- 展示；
- 重配置；
- 分享链接；
- 回滚；
- 不丢老字段。

---

## 16.4 VLESS URI

必须有精确断言。

IPv4：

```text
vless://UUID@1.2.3.4:443...
```

域名：

```text
vless://UUID@example.com:443...
```

IPv6：

```text
vless://UUID@[2001:db8::1]:443...
```

禁止生成：

```text
vless://UUID@2001%3Adb8%3A%3A1:443...
```

也禁止：

```text
vless://UUID@2001:db8::1:443...
```

测试：

- 已带 `[ ]` 的 IPv6 不重复加括号；
- fragment 正确编码；
- query 参数不错误使用 authority host。

覆盖：

```text
Reality
ws
ws_tls
grpc
grpc_tls
xhttp
xhttp_tls
xtls
```

对项目实际支持的模式逐项检查。

---

## 16.5 Clash YAML

对：

```text
IPv4
domain
IPv6
```

至少做 YAML parse 级验证。

检查：

```text
server
name
Host header
servername
```

不要仅 grep 文本。

---

## 16.6 listener

用当前 Xray 版本生成实际配置后，检查：

```text
IPv4 TCP connect
IPv6 TCP connect
```

如果 Docker runner 支持 IPv6：

运行真实 dual-stack smoke test。

如果 runner 不支持：

- unit/mocked 测试必须完整；
- listener 真实 IPv6 测试标记为可选环境测试；
- 不允许测试因为宿主未开启 IPv6 而随机失败。

---

## 16.7 安装/重配置行为

至少验证：

```text
新安装：仅 IPv4
新安装：仅 IPv6
新安装：dual

老 IPv4 配置 -> 保留配置重新部署
老 IPv6 配置 -> 保留配置重新部署
老配置 -> 标准模板重建
老配置 -> 模式切换

dual -> 服务器 IPv6 后续不可用
dual -> DNS AAAA 后续被删
dual -> DNS AAAA 后续指错
```

最后三项至少保证 Doctor/重配置时有清晰行为，不要求构建复杂后台监控。

---

# 17. Docker 测试要求

优先在仓库现有 Docker 测试体系内扩展。

若需要 Docker IPv6 网络：

可以创建独立 test network，例如：

```text
IPv4 subnet
IPv6 subnet
enable_ipv6
```

但必须：

- 检查 CI runner 支持程度；
- 不修改生产 Docker 默认网络要求；
- 不使普通 IPv4 CI 环境失败；
- 真实 IPv6 smoke test 与纯逻辑测试分层。

对于公网 `curl -6`：

CI 不应依赖外部 IPv6 必然存在。

应通过 mock/fixture 测试检测逻辑。

---

# 18. 禁止项

本任务明确禁止以下实现方式：

1. **禁止**全局把 Xray `0.0.0.0` 替换为 `::`。
2. **禁止**为了双栈顺手重做 Xray outbound。
3. **禁止**把 Happy Eyeballs 作为本任务的必选修改。
4. **禁止**只要 `ip -6 addr` 有地址就宣布 IPv6 可用。
5. **禁止**继续以 `ping` 返回的第一个 IP 作为域名唯一资格证据。
6. **禁止**删除 `host` / `ip_version` 导致旧配置失效。
7. **禁止**双栈模式只保存一个 IP，另一个靠运行时猜。
8. **禁止**用同一个 URL-encoded host 同时填 authority/query/fragment。
9. **禁止**把 IPv6 URI authority 写成 percent-encoded colon。
10. **禁止**手工翻译全部语言。
11. **禁止**修改所有语言 README 来追求“同步”。
12. **禁止**把自动翻译生成物当作中文源。
13. **禁止**无关代码格式化导致巨大 diff。
14. **禁止**在没有测试的情况下修改证书流程。
15. **禁止**因增加 dual 而改变已有用户的默认网络选择。
16. **禁止**把“IPv6 支持”写进 README 后却只完成出站探测。
17. **禁止**把错误 AAAA 当作无害警告后默认继续。
18. **禁止**没有验证就声称“完整支持双栈”。

---

# 19. 推荐实施顺序

严格按以下顺序推进。

## Phase A：最新源码专项审计

输出内部清单：

```text
双栈相关文件
host/ip_version 消费点
DNS 解析点
分享链接生成点
Clash 生成点
Rill/Doctor 消费点
测试覆盖现状
i18n 自动翻译工作流
```

确认与本提示词基线是否一致。

---

## Phase B：先写/补测试

先建立能复现以下问题的测试：

```text
IPv6 authority link 错误
单栈 domain_check
坏 AAAA
旧配置兼容
dual 地址选择
```

至少让关键问题在修改前可以被测试捕获。

---

## Phase C：实现网络能力与 DNS qualification

完成：

```text
IPv4/IPv6 自动检测
A/AAAA 集合校验
坏记录阻断
network_mode
兼容字段
```

---

## Phase D：分享链接 / Clash

完成：

```text
URI authority IPv6 bracket
query/fragment 独立编码
dual direct-IP 两份入口
Clash IPv6 YAML 验证
```

---

## Phase E：升级 / 重配置 / Rill 兼容

跑完整：

```text
旧配置
新配置
重配置
模式切换
失败回滚
诊断
```

仅修改真正受影响部分。

---

## Phase F：中文文档和 i18n

最后再修改：

```text
中文 README
中文 gettext 文案
POT/中文源（若现有流程需要）
```

不要人工翻译其他语言。

---

## Phase G：完整复检

至少执行仓库已有测试，加上本次新增专项：

```bash
bash -n install.sh
```

以及：

```text
shellcheck（若项目现有 CI 使用）
jq JSON 校验
Xray config test
Nginx config test
VLESS link test
Clash YAML parse
Docker tests
upgrade/reconfigure/rollback tests
dual-stack qualification tests
i18n extraction/check
```

如果某项环境无法运行：

明确说明原因，并给出已完成的替代验证；
不能直接写“应该没问题”。

---

# 20. 验收标准

只有全部满足，才能称为本次任务完成。

## IPv4

- 现有 IPv4-only 安装行为不回归；
- 默认老用户不会被强制切 dual；
- IPv4 分享链接不变或语义等价；
- TLS A-only 可正常通过。

## IPv6

- IPv6-only 能完成安装；
- IPv6 literal VLESS authority 使用 `[IPv6]`；
- Clash 输出可解析；
- AAAA-only TLS 路径通过资格检查；
- 不依赖错误的 `ping` 单地址逻辑。

## Dual Stack

- 新安装可识别 IPv4+IPv6；
- 配置中可同时持久化两个公网地址；
- TLS A+AAAA 正确时判定 dual；
- 直接-IP模式可分别输出 IPv4/IPv6 客户端入口；
- 坏 A/AAAA 不会被误判为健康双栈；
- listener 行为经测试验证；
- 不需要机械改写 `0.0.0.0`。

## 兼容性

- 老 `host/ip_version` 配置仍可读取；
- 保留配置重新部署正常；
- 模式切换正常；
- 回滚正常；
- 手动 IP/特殊域名路径仍存在；
- Rill/Doctor 不因新字段报错。

## i18n

- 新用户文案以中文为源；
- 需要翻译的 shell 文案进入 gettext；
- 没有人工维护所有语言；
- 自动翻译机制仍正常；
- 中文 README 与功能一致。

## 工程质量

- 无大面积无关 diff；
- 无无关依赖；
- 无新的静默错误；
- 关键 helper 有测试；
- Docker/CI 不因宿主 IPv6 能力差异变得 flaky。

---

# 21. 版本策略

不要擅自修改发布版本号。

本任务技术上适合作为一个明确的功能版本/小版本功能，但具体版本由项目维护者决定。

实现时：

- 不要因为提示词中讨论过 `1.1.0` 就自动改版本；
- 先完成代码与测试；
- 最终报告给出“建议版本范围”，由维护者决定是否发版。

---

# 22. 最终交付格式

完成后不要只说“已支持 IPv6”。

必须给出严谨交付报告：

## A. 审计结论

说明：

```text
原先真正的阻塞点是什么
哪些原先以为是问题、实际不是问题
为什么当前 Xray/Nginx listener 无需大改
```

## B. 修改文件

逐文件列出：

```text
文件
修改原因
关键行为变化
```

## C. 配置兼容性

明确说明：

```text
老配置如何读取
network_mode 如何推断
host/ip_version 是否保留
dual 如何持久化
```

## D. 用户行为

分别给出：

```text
IPv4-only
IPv6-only
Dual Stack
TLS domain
Reality/direct IP
手动输入
```

用户最终看到什么。

## E. 测试结果

逐项写：

```text
测试名称
环境
结果
```

不得只写“测试通过”。

## F. 未解决/非本次范围

例如：

```text
Xray outbound Happy Eyeballs
特定云厂商 IPv6 防火墙自动配置
NAT64/464XLAT
第三方客户端对 IPv6 literal 的历史兼容差异
```

如果没有实际证据，不要扩大描述。

## G. 风险评估

给出：

```text
阻断级
高
中
低
```

剩余风险以及是否影响合并。

---

# 23. 本次专项的核心判断

请始终围绕以下结论执行：

> 当前项目并不是“完全没有 IPv6”。它已经有 IPv6 公网探测、A/AAAA 解析以及 Nginx 双栈监听等基础能力。
>
> 真正需要完成的是：把产品状态从“IPv4 / IPv6 二选一”升级为可表达 dual 的网络模型；把 TLS 域名检查从单 IP/`ping` 比对升级为 A/AAAA 集合资格检查；正确处理 IPv6 literal 客户端 URI；并确保旧配置、重配置、回滚和自动翻译链不回归。
>
> 这应该是一次**范围受控的双栈补全工程**，而不是网络栈重写。

---

# 24. 开始执行

现在从最新 `main` 开始：

1. 拉取/确认最新代码；
2. 先做双栈相关专项审计；
3. 与以上基线逐项核对；
4. 发现基线与最新源码不一致时，以源码和可验证行为为准；
5. 建立回归测试；
6. 完成最小实现；
7. 完成 Docker/逻辑/配置/URI/DNS/兼容测试；
8. 更新中文主文案和中文 README；
9. 保留自动翻译流程，不人工逐语言翻译；
10. 最后进行一次独立复检，再提交完整结果。

不要停留在分析或 TODO；在没有真实阻断的情况下，推进到可交付状态。
