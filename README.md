## Xray 支持 Reality / VLESS WebSocket/gRPC+TLS 协议 + Nginx 的一键安装脚本
[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> 感谢 JetBrains 提供的非商业开源软件开发授权。

> Thanks for non-commercial open source development authorization by JetBrains。

### 使用说明
* 可以直接输入命令：`idleleo` 管理脚本。
* Reality 建议使用 Nginx 前置，在脚本中安装即可。
* 建议开启 fail2ban ，在脚本中安装即可。
* 使用来自 [@DuckSoft](https://github.com/DuckSoft) 的分享链接[提案](https://github.com/XTLS/Xray-core/issues/91) (beta)，支持 Qv2ray、V2rayN、V2rayNG。
* 使用来自 [XTLS](https://github.com/XTLS/Xray-core/issues/158) 项目的提案，遵循 [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) 标准，可以将自定义字符串映射至 VLESS UUID 。
* Reality 安装说明：[搭建 Xray Reality 协议服务器](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)。
* Reality 协议的风险：[Xray Reality 协议的风险](https://hey.run/archives/reality-xie-yi-de-feng-xian)。
* 利用 Reality 协议加速服务器：[利用 Reality 协议“漏洞”加速服务器](https://hey.run/archives/li-yong-reality-xie-yi-lou-dong-jia-su-fu-wu-qi)。
* 添加负载均衡配置，教程：[XRay进阶玩法 – 搭建后端服务器负载均衡](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)。
* 添加 gRPC 协议的支持，具体可见：[Xray进阶玩法 – 使用gRPC协议](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)。

### Telegram 群组
* Telegram 交流群：https://t.me/idleleo_chat

### 准备工作
* 准备一个服务器，在中国大陆境外运行、有公网ip。
* 安装 Reality 协议全，找好一个符合 Xray 要求的域名。
* 安装 TLS 版本的，准备一个域名，并将A记录添加好。
* 阅读[Xray官方说明](https://xtls.github.io)，大概了解 Reality TLS WebSocket gRPC 及 Xray 相关信息，了解 Reality target 的域名要求。
* **安装好 curl**，Centos用户运行：`yum install -y curl`；Debian/Ubuntu用户运行：`apt install -y curl`。

### 安装方式
复制运行：
```
bash <(curl -Ss https://www.idleleo.com/install.sh)
```

### 注意事项
* 如果你不了解脚本中各项设置的具体含义，除必填项外，请使用脚本提供的默认值 (全程回车到底)。
* Cloudflare 用户请安装完毕后再开启CDN功能。
* 使用本脚本需要你拥有 Linux 基础及使用经验，了解计算机网络部分知识，计算机基础操作。
* 目前支持 Debian 9+ / Ubuntu 18.04+ / Centos7+ ，部分 Centos 模板可能存在难以处理的编译问题，建议遇到编译问题时，请更换至其他系统模板。
* 作者仅提供有限的支持，应为太笨了。
* 分享链接为实验版本，不排除未来变动的可能，请自行确认客户端是否支持。
* 自定义字符串映射至 UUIDv5 需要客户端支持。

### 鸣谢
* 本脚本来源于 https://github.com/wulabing/V2Ray_ws-tls_bash_onekey 在此感谢 wulabing
* 本脚本中 TCP加速 脚本项目引用 https://github.com/ylx2016/Linux-NetSpeed 在此感谢 ylx2016

### 证书
如果你已经拥有了你所使用域名的证书文件，可以将 crt 和 key 文件命名为 xray.crt 和 xray.key 放在 /etc/idleleo/cert 目录下（若目录不存在请先建目录），请注意证书文件权限及证书有效期，自定义证书有效期过期后需自行续签。

脚本支持自动生成 Let's encrypted 证书，有效期3个月，理论上自动生成的证书支持自动续签。

### 查看客户端配置
`cat /etc/idleleo/xray_info.txt`

### Xray 简介

* Xray 是一个优秀的开源网络代理工具，可以帮助你畅爽体验互联网，目前已经全平台支持 Windows、Mac、Android、IOS、Linux 等操作系统的使用。
* 本脚本为一键完全配置脚本，在所有流程正常运行完毕后，直接按照输出结果设置客户端即可使用。
* 请注意：我们依然强烈建议你全方面的了解整个程序的工作流程及原理。

### 建议单服务器仅搭建单个代理
* 本脚本默认安装最新版本的 Xray core。
* 建议使用默认的 443 端口作为连接端口。
* 伪装内容可自行替换。

### 注意事项
* 推荐在纯净环境下使用本脚本，如果你是新手，请不要使用 Centos 系统。
* 在尝试本脚本确实可用之前，请不要将本程序应用于生产环境中。
* 该程序依赖 Nginx 实现相关功能，请使用 [LNMP](https://lnmp.org) 或其他类似携带 Nginx 脚本安装过 Nginx 的用户特别留意，使用本脚本可能会导致无法预知的错误。
* Centos 系统用户请预先在防火墙中放行程序相关端口（默认：80，443）。


### 启动方式

启动 Xray：`systemctl start xray`

停止 Xray：`systemctl stop xray`

启动 Nginx：`systemctl start nginx`

停止 Nginx：`systemctl stop nginx`

### 相关目录

Xray 服务端配置：`/etc/idleleo/conf/xray/config.json`

Nginx 目录： `/usr/local/nginx`

证书文件：`/etc/idleleo/cert/xray.key` 和 `/etc/idleleo/cert/xray.crt` 请注意证书权限设置

配置信息文件等：`/etc/idleleo`
