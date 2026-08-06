# Xray Script de gestion — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

Chinois simplifié |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Caractéristiques

* entrer`idleleo`Ouvrez le menu de gestion Xray pour gérer l'installation, les services, les paramètres de sécurité, etc.
* Utilisez Qwen-MT-Plus AI pour obtenir une traduction précise dans plusieurs langues
* Prend en charge le protocole Reality, il est recommandé d'utiliser le préfixe Nginx (peut être installé dans le script)
* Prend en charge la transmission WebSocket, gRPC, xHTTP, vous pouvez choisir une transmission unique ou`ws+gRPC+xHTTP`Activer les deux
* Protection fail2ban intégrée (installable dans le script)
* Statistiques de trafic Xray intégrées, blocage du trafic, mise à jour des règles GeoIP/GeoSite et mise à jour régulière
* Prend en charge les scripts, Xray, Nginx et les mises à jour de certificats, et fournit une sauvegarde et une restauration en cas d'échec pour les mises à jour critiques.
* La configuration en cours d'exécution sera automatiquement sauvegardée avant la réinstallation et le changement de mode, et la configuration d'origine sera restaurée en cas de panne.
* La reconfiguration offre trois voies sûres : le redéploiement en préservant la configuration, la reconstruction du modèle standard et le changement de mode.
* utiliser[@DuckSoft](https://github.com/DuckSoft)le lien de partage[提案](https://github.com/XTLS/Xray-core/issues/91)(beta), compatible avec Qv2ray, V2rayN, V2rayNG
* utiliser[XTLS](https://github.com/XTLS/Xray-core/issues/158)proposition, suivre[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)Standard, prend en charge le mappage de chaînes personnalisé vers VLESS UUID
* Prend en charge le protocole gRPC :[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Prend en charge l'équilibrage de charge Reality / ws/gRPC/xHTTP :
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Le mode Reality + Nginx est activé par défaut. SNI Guard : SNI inconnu, SNI vide et l'exception TLS n'entrera pas dans le backend Xray Reality. La stratégie d'isolement (ssl_reject_handshake) est adoptée par défaut. Les utilisateurs avancés peuvent passer au site de secours decoy créé par eux-mêmes ou directement à TCP refusé. Cette fonction est utilisée pour réduire l’exposition à la détection active et aux erreurs de configuration, et ne vise pas un camouflage parfait.

## Lectures complémentaires

* `idleleo`Histoire de dénomination :[迷雾后的真容](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* RealityGuide d'installation :[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality Risque de protocole :[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality Serveur accéléré :[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## Groupe Telegram

* Groupe de communication :[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## Préparation

* Un serveur à l'étranger avec un réseau public IP
* Installez le protocole Reality : vous devez préparer un nom de domaine cible qui répond aux exigences de Xray.
* Installez la version TLS : préparez le nom de domaine et ajoutez l'enregistrement A
* lire[Xray 官方文档](https://xtls.github.io), comprendre les concepts liés à Reality, TLS, WebSocket, gRPC et Xray
* **Assurez-vous que curl est installé : exécution utilisateur CentOS`yum install -y curl`;Debian/Ubuntu Exécution utilisateur`apt install -y curl`

## Installation rapide

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Mode d'installation

| modèle | illustrer |
|------|------|
| Reality + Nginx | Mode recommandé, vous pouvez associer un protocole simple ws/gRPC/xHTTP selon vos besoins pour l'équilibrage de charge. |
| Nginx + TLS | Soutenir ws/gRPC/xHTTP, demander et renouveler automatiquement le certificat Let's Encrypt |
| ws/gRPC/xHTTP ONLY | Mode entrant indépendant sans TLS, principalement utilisé dans les scénarios backend ou d'équilibrage de charge |
| XTLS ONLY | Utilisé uniquement dans des scénarios spécifiques tels que le transfert de trafic |
| Docker | Xray, Nginx et le script principal sont préinstallés dans l'image |

Facultatif lors de l'installation des modes associés à ws/gRPC/xHTTP`ws`、`gRPC`、`xHTTP`ou`ws+gRPC+xHTTP`. Le script générera respectivement le port, le chemin, le lien de partage et le code QR correspondants ; Clash ne prend actuellement pas en charge xHTTP et le script vous demandera la sortie de configuration.

## Instructions de reconfiguration

Lorsque l'environnement installé est à nouveau installé, le script sauvegarde automatiquement la configuration en cours d'exécution et fournit trois chemins de reconfiguration :

| chemin | illustrer | limite |
|------|------|------|
| Préserver le redéploiement de la configuration | Conservez les configurations routing/outbounds/DNS et multi-utilisateurs personnalisées, modifiez uniquement les champs sélectionnés par l'utilisateur (ports, chemins, paramètres UUID, Reality, etc.) | Les modifications de la structure de transmission (telles que ws → gRPC) ne sont pas prises en charge. Si vous devez modifier la combinaison de transmission, veuillez utiliser le modèle standard pour la reconstruire. |
| Reconstruction de modèle standard | Générez une configuration de modèle standard à l'aide des paramètres réutilisables actuels, le routing/outbounds/DNS personnalisé peut être supprimé | Il n'est pas obligatoire que le nombre d'utilisateurs reste inchangé |
| Changement de mode | Passez à un autre mode de protocole (tel que Reality → TLS). Par défaut, seul l'utilisateur principal UUID/email est réutilisé. | Les autres utilisateurs ne seront pas automatiquement migrés et seront clairement invités avant de changer. |

Si une étape du processus de reconfiguration échoue (écriture de la configuration, démarrage du service, vérification de l'état, etc.), elle reviendra automatiquement à la configuration de sauvegarde d'origine. Le répertoire de sauvegarde utilise un horodatage unique pour prendre en charge plusieurs reconfigurations consécutives sans entrer en conflit les unes avec les autres.

## Commandes courantes

| fonctionner | Commande |
|------|------|
| Ouvrez le menu d'administration | `idleleo` |
| Afficher l'aide | `idleleo --help` |
| Installer le mode Reality | `idleleo --install-reality` |
| Installer le mode TLS | `idleleo --install-tls` |
| Installer ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Afficher les informations d'installation | `idleleo --show` |
| script de mise à jour | `idleleo --update` |
| Mettre à jour Xray | `idleleo --xray-update` |
| Mettre à jour Nginx | `idleleo --nginx-update` |
| Définir Fail2ban | `idleleo --set-fail2ban` |
| Configurer le blocage du trafic | `idleleo --traffic-blocker` |
| Visualisez le trafic portuaire en temps réel | `idleleo --port-traffic` |

## Docker Déploiement

Prend en charge le déploiement à l'aide de Docker, l'image est préinstallée avec Xray et Nginx et toutes les fonctions du script d'origine peuvent être utilisées directement dans le conteneur. Voir les détails[Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill Déploiement

Prend en charge le déploiement automatique de Xray via les outils AI tels que Trae sans interaction manuelle. Voir les détails[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

La méthode traditionnelle nécessite que SSH accède au serveur, exécute le script d'installation et réponde aux questions interactives une par une ; la méthode Skill n'a besoin que d'indiquer à AI vos besoins, et AI générera automatiquement un script non interactif et l'exécutera, renvoyant directement le lien VLESS.

**Modes pris en charge** : Reality / TLS / ws ONLY / XTLS ONLY

**Comment l'utiliser** : dites directement "Aidez-moi à créer Xray sur le serveur" dans l'outil AI qui prend en charge Skill, et AI collectera automatiquement des informations, générera des scripts, effectuera le déploiement et renverra les informations de connexion.

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
* N'utilisez pas ce script dans un environnement de production sans vérifier au préalable la disponibilité
* Auteur : Yun Shu, fournissant uniquement une assistance limitée

## Remerciements

* basé sur[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)développer
* TCP script d'accélération cité de[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Configuration du certificat

**Certificat personnalisé** : nommez respectivement les fichiers crt et key.`xray.crt`et`xray.key`, mettre dedans`/etc/idleleo/cert`Répertoire (si le répertoire n'existe pas, créez-le d'abord). Veuillez faire attention à l'autorité de certification et à la période de validité. Une fois le certificat personnalisé expiré, vous devez le renouveler vous-même.

**Certificat automatique** : le script prend en charge la génération automatique de certificats Let's Encrypt (valable 3 mois) et prend théoriquement en charge le renouvellement automatique.

## Afficher la configuration du client

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray Introduction

* Xray est un excellent outil proxy réseau open source qui prend en charge Windows, macOS, Android, iOS, Linux et d'autres plates-formes complètes.
* Ce script est un script de configuration complet en un clic. Une fois que tous les processus sont terminés normalement, le client peut être utilisé en fonction des résultats de sortie.
* **FORTEMENT RECOMMANDÉ** Une compréhension complète du flux de travail et des principes du programme

## Gestion des services

| fonctionner | Commande |
|------|------|
| Début Xray | `systemctl start xray` |
| Arrêter Xray | `systemctl stop xray` |
| Début Nginx | `systemctl start nginx` |
| Arrêter Nginx | `systemctl stop nginx` |

## Catalogue associé

| contenu | chemin |
|------|------|
| Répertoire personnel | `/etc/idleleo` |
| Configuration Xray | `/etc/idleleo/conf/xray/config.json` |
| Configuration Nginx | `/etc/idleleo/conf/nginx/` |
| Informations d'installation | `/etc/idleleo/conf/install_config.json` |
| fichier de certificat | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| Répertoire des journaux | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Répertoire d'installation Nginx | `/usr/local/nginx` |
| Commandes administratives | `/usr/bin/idleleo` |
