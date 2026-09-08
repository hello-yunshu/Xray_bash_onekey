# Xray 管理脚本 — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

Chinois simplifié |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## 功能特性

* entrer`idleleo` 打开 Xray 管理菜单，管理安装、服务、安全设置等
* 采用 Qwen-MT-Plus AI 实现多语言精准翻译
* 支持 Reality 协议，建议搭配 Nginx 前置（脚本内可安装）
* 支持 WebSocket、gRPC、xHTTP 传输，可选择单一传输或 `ws+gRPC+xHTTP`Activer les deux
* 支持 IPv4 / IPv6 双栈：安装时可自动检测公网出口能力，按域名 A/AAAA 记录独立校验并生成对应分享链接与 Clash 配置
* Protection fail2ban intégrée (installable dans le script)
* Statistiques de trafic Xray intégrées, blocage du trafic, mise à jour des règles GeoIP/GeoSite et mise à jour régulière
* Prend en charge les scripts, Xray, Nginx et les mises à jour de certificats, et fournit une sauvegarde et une restauration en cas d'échec pour les mises à jour critiques.
* 重新安装和模式切换前会自动备份当前运行配置，失败时恢复原配置
* La reconfiguration offre trois voies sûres : le redéploiement en préservant la configuration, la reconstruction du modèle standard et le changement de mode.
* 采用 [@DuckSoft](https://github.com/DuckSoft)le lien de partage[提案](https://github.com/XTLS/Xray-core/issues/91)（beta），兼容 Qv2ray、V2rayN、V2rayNG
* utiliser[XTLS](https://github.com/XTLS/Xray-core/issues/158)proposition, suivre[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)Standard, prend en charge le mappage de chaînes personnalisé vers VLESS UUID
* Prend en charge le protocole gRPC :[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Prend en charge l'équilibrage de charge Reality / ws/gRPC/xHTTP :
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Le mode Reality + Nginx est activé par défaut. SNI Guard : SNI inconnu, SNI vide et l'exception TLS n'entrera pas dans le backend Xray Reality. La stratégie d'isolement (ssl_reject_handshake) est adoptée par défaut. Les utilisateurs avancés peuvent passer au site de secours decoy créé par eux-mêmes ou directement à TCP refusé. Cette fonction est utilisée pour réduire l’exposition à la détection active et aux erreurs de configuration, et ne vise pas un camouflage parfait.

## Lectures complémentaires

* `idleleo`Histoire de dénomination :[迷雾后的真容](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality 安装指南：[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality 协议风险：[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality Serveur accéléré :[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## Telegram 群组

* 交流群：[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## 准备工作

* 一台境外服务器，具备公网 IP
* 安装 Reality 协议：需准备符合 Xray 要求的目标域名
* 安装 TLS 版本：需准备域名，并根据服务器可用网络正确配置 A 和/或 AAAA 记录；双栈环境建议同时配置正确的 A 与 AAAA。脚本支持自动检测 IPv4/IPv6 网络能力，双栈可用时可同时生成对应客户端入口
* 阅读 [Xray 官方文档](https://xtls.github.io)，了解 Reality、TLS、WebSocket、gRPC 及 Xray 相关概念
* **确保已安装 curl**：CentOS 用户执行 `yum install -y curl`；Debian/Ubuntu 用户执行 `apt install -y curl`

## 快速安装

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

## 安装模式

| 模式 | illustrer |
|------|------|
| Reality + Nginx | 推荐模式，可按需附加 ws/gRPC/xHTTP 简单协议用于负载均衡 |
| Nginx + TLS | 支持 ws/gRPC/xHTTP，自动申请并续期 Let's Encrypt 证书 |
| ws/gRPC/xHTTP ONLY | 无 TLS 的独立入站模式，主要用于后端或负载均衡场景 |
| XTLS ONLY | 仅用于流量中转等特定场景 |
| Docker | Xray, Nginx et le script principal sont préinstallés dans l'image |

安装 ws/gRPC/xHTTP 相关模式时，可选择 `ws`、`gRPC`、`xHTTP` 或 `ws+gRPC+xHTTP`。脚本会分别生成对应端口、路径、分享链接和二维码；Clash 目前不支持 xHTTP，脚本会在配置输出中提示。

## 重配置说明

已安装的环境再次运行安装时，脚本会自动备份当前运行配置，并提供三条重配置路径：

| 路径 | illustrer | 限制 |
|------|------|------|
| 保留配置重新部署 | 保留自定义 routing/outbounds/DNS 和多用户配置，仅修改用户选择的字段（端口、路径、UUID、Reality 参数等） | 不支持传输结构变更（如 ws → gRPC），需改传输组合请使用标准模板重建 |
| 标准模板重建 | 使用当前可复用参数生成标准模板配置，自定义 routing/outbounds/DNS 可能被移除 | 不强制要求用户数量不变 |
| 模式切换 | 切换到不同协议模式（如 Reality → TLS），默认只复用主用户 UUID/email | 其他用户不自动迁移，切换前会明确提示 |

重配置过程中任何步骤失败（配置写入、服务启动、健康检查等）都会自动回滚到备份的原配置。备份目录使用唯一时间戳，支持连续多次重配置互不冲突。

## Commandes courantes

| 操作 | 命令 |
|------|------|
| 打开管理菜单 | `idleleo` |
| 查看帮助 | `idleleo --help` |
| 安装 Reality 模式 | `idleleo --install-reality` |
| 安装 TLS 模式 | `idleleo --install-tls` |
| 安装 ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| 查看安装信息 | `idleleo --show` |
| 更新脚本 | `idleleo --update` |
| 更新 Xray | `idleleo --xray-update` |
| 更新 Nginx | `idleleo --nginx-update` |
| 设置 Fail2ban | `idleleo --set-fail2ban` |
| 设置流量阻断 | `idleleo --traffic-blocker` |
| 查看端口实时流量 | `idleleo --port-traffic` |

## RillML Xray AI 运维助手

RillML（简称 Rill）为 Xray 提供本地自适应智能运维能力。

内置本地 AI 运维助手，实时监控 Xray/Nginx 健康状态，自动诊断故障并给出处理建议，无需外部 API。主菜单输入 `9` 或执行 `idleleo --rill-agent` 进入。

**核心能力**

* 监控：实时观测 Xray/Nginx 服务与配置状态
* Diagnostic : localisez la cause profonde du défaut, avec des recommandations de confiance (preuves élevées/moyennes/faibles/insuffisantes)
* 判断：自动判断故障类型并给出处理建议，说明中明确标注允许自动处理或仅提供建议
* 模式：智能判断 / 仅观察 / 安全停用，未开启自动修改前不会更改系统

**常用命令**

| 操作 | Commande |
|------|------|
| 打开 AI 运维助手菜单 | `idleleo --rill-agent` |
| 安装或修复 AI 判断引擎 | `idleleo --rill-agent-install` |
| 查看 AI 判断状态 | `idleleo --rill-agent-status` |
| Exécutez le dépannage AI | `idleleo --rill-agent-diagnose` |
| 校验 AI 判断引擎 | `idleleo --rill-agent-verify` |
| Désactivation de la sécurité Jugement AI | `idleleo --rill-agent-safe-disable` |
| 卸载 Rill AI 引擎 | `idleleo --rill-agent-uninstall` |

AI Le moteur de jugement est encore en phase de test. Il est recommandé de se concentrer sur les suggestions de diagnostic. Le système ne sera pas automatiquement modifié par défaut.

## Docker Déploiement

支持使用 Docker 部署，镜像预装 Xray 和 Nginx，容器内可直接使用原脚本所有功能。详见 [Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill 部署

Prend en charge le déploiement automatique de Xray via les outils AI tels que Trae sans interaction manuelle. Voir les détails[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

La méthode traditionnelle nécessite que SSH accède au serveur, exécute le script d'installation et réponde aux questions interactives une par une ; la méthode Skill n'a besoin que d'indiquer à AI vos besoins, et AI générera automatiquement un script non interactif et l'exécutera, renvoyant directement le lien VLESS.

**Modes pris en charge** : Reality / TLS / ws ONLY / XTLS ONLY

**Comment l'utiliser** : dites simplement "Aidez-moi à créer Xray sur le serveur" dans l'outil AI qui prend en charge Skill, et AI collectera automatiquement des informations, générera des scripts, effectuera le déploiement et renverra les informations de connexion.

## Choses à noter

* Si vous ne comprenez pas la signification de chaque paramètre, veuillez utiliser la valeur par défaut, à l'exception des champs obligatoires (appuyez simplement sur Entrée)
* Cloudflare Les utilisateurs doivent ouvrir CDN une fois l'installation terminée.
* Ce script nécessite une connaissance de base de Linux et une connaissance des réseaux informatiques.
* Prend en charge Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+, certains modèles CentOS peuvent avoir des problèmes de compilation, il est recommandé de changer de système en cas de problèmes
* Il est recommandé qu'un seul serveur ne déploie qu'un seul agent et utilise le port par défaut 443.
* Le mappage de chaîne personnalisé vers UUIDv5 nécessite la prise en charge du client
* Il est recommandé de l'utiliser dans un environnement pur ; les novices ne devraient pas utiliser CentOS
* Ce programme dépend de Nginx, réussi[LNMP](https://lnmp.org)Les utilisateurs qui ont installé le script Nginx doivent être conscients des conflits potentiels.
* Le lien partagé xHTTP est destiné aux clients qui prennent en charge xHTTP ; La sortie de configuration Clash ignorera xHTTP
* 请勿在未验证可用性前将本脚本用于生产环境
* Auteur : Yun Shu, fournissant uniquement une assistance limitée

## 鸣谢

* basé sur[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey) 开发
* TCP script d'accélération cité de[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## 证书配置

**自定义证书**：将 crt 和 key 文件分别命名为 `xray.crt` 和 `xray.key`, mettre dedans`/etc/idleleo/cert` 目录（目录不存在则先创建）。请注意证书权限及有效期，自定义证书过期后需自行续签。

**自动证书**：脚本支持自动生成 Let's Encrypt 证书（有效期 3 个月），理论上支持自动续签。

## 查看客户端配置

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray 简介

* Xray 是一款优秀的开源网络代理工具，支持 Windows、macOS、Android、iOS、Linux 等全平台
* 本脚本为一键完整配置脚本，所有流程正常完成后，按输出结果设置客户端即可使用
* **强烈建议**全面了解程序的工作流程及原理

## 服务管理

| 操作 | Commande |
|------|------|
| 启动 Xray | `systemctl start xray` |
| 停止 Xray | `systemctl stop xray` |
| Début Nginx | `systemctl start nginx` |
| 停止 Nginx | `systemctl stop nginx` |

## 相关目录

| 内容 | 路径 |
|------|------|
| 主目录 | `/etc/idleleo` |
| Configuration Xray | `/etc/idleleo/conf/xray/config.json` |
| Nginx 配置 | `/etc/idleleo/conf/nginx/` |
| 安装信息 | `/etc/idleleo/conf/install_config.json` |
| 证书文件 | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| Répertoire des journaux | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Nginx 安装目录 | `/usr/local/nginx` |
| 管理命令 | `/usr/bin/idleleo` |
