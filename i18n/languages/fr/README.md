# Script d'installation automatique Xray — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

[简体中文](/README.md) | [English](/i18n/languages/en/README.md) | Français | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Merci à JetBrains pour l'autorisation de développement open source non commercial

## Fonctionnalités

* Tapez `idleleo` pour gérer le script ([Voir l'histoire de `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/Le-Vrai-Visage-Derri%C3%A8re-la-Brume))
* Traduction multilingue précise propulsée par Qwen-MT-Plus AI
* Prend en charge le protocole Reality avec Nginx en frontal recommandé (installable via le script)
* Prend en charge les transports WebSocket, gRPC et xHTTP, avec un transport unique ou `ws+gRPC+xHTTP` activés ensemble
* Protection fail2ban intégrée (installable via le script)
* Fonctionnalités intégrées au script : statistiques de trafic Xray, blocage du trafic, mises à jour GeoIP/GeoSite et mises à jour planifiées
* Prend en charge les mises à jour automatiques du script, de Xray, de Nginx et des certificats, avec sauvegarde et restauration complètes
* Adopte la [proposition](https://github.com/XTLS/Xray-core/issues/91) de lien de partage de [@DuckSoft](https://github.com/DuckSoft) (beta), compatible avec Qv2ray, V2rayN, V2rayNG
* Adopte la proposition du projet [XTLS](https://github.com/XTLS/Xray-core/issues/158), conforme à la norme [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3), permettant le mappage de chaînes personnalisées vers un UUID VLESS
* Prend en charge le protocole gRPC : [Utiliser le protocole gRPC](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Prend en charge l'équilibrage de charge Reality / ws/gRPC/xHTTP :
  - [Déployer un équilibreur de charge Reality](https://hey.run/posts/bushu-reality-balance)
  - [Construire un équilibreur de charge backend](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## Pour aller plus loin

* Guide d'installation Reality : [Configurer un serveur Xray Reality](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Risques du protocole Reality : [Risques du protocole Xray Reality](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Accélérer le serveur avec Reality : [Accélérer le serveur via la « faille » du protocole Reality](https://hey.run/posts/use-reality)

## Groupe Telegram

* Groupe de discussion : [Cliquez pour rejoindre](https://t.me/+48VSqv7xIIFmZDZl)

## Prérequis

* Un serveur à l'étranger avec une adresse IP publique
* Pour le protocole Reality : préparez un domaine cible conforme aux exigences de Xray
* Pour le mode TLS : préparez un domaine et ajoutez un enregistrement A
* Lisez la [documentation officielle Xray](https://xtls.github.io) pour comprendre Reality, TLS, WebSocket, gRPC et les concepts liés à Xray
* **Assurez-vous que curl est installé** : utilisateurs CentOS, exécutez `yum install -y curl` ; utilisateurs Debian/Ubuntu, exécutez `apt install -y curl`

## Installation rapide

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Modes d'installation

| Mode | Description |
|------|-------------|
| Reality + Nginx | Mode recommandé, avec transports auxiliaires ws/gRPC/xHTTP optionnels pour l'équilibrage de charge |
| Nginx + TLS | Prend en charge ws/gRPC/xHTTP et émet puis renouvelle automatiquement les certificats Let's Encrypt |
| ws/gRPC/xHTTP ONLY | Mode entrant autonome sans TLS, surtout pour les scénarios de backend ou d'équilibrage de charge |
| XTLS ONLY | Réservé au relais de trafic et à certains scénarios spécifiques |
| Docker | Image avec Xray, Nginx et le script principal préinstallés |

Lors de l'installation des modes ws/gRPC/xHTTP, vous pouvez choisir `ws`, `gRPC`, `xHTTP` ou `ws+gRPC+xHTTP`. Le script génère les ports, chemins, liens de partage et QR codes correspondants. Clash ne prend actuellement pas en charge xHTTP ; le script le signale dans la sortie de configuration générée.

## Commandes courantes

| Action | Commande |
|--------|----------|
| Ouvrir le menu de gestion | `idleleo` |
| Afficher l'aide | `idleleo --help` |
| Installer le mode Reality | `idleleo --install-reality` |
| Installer le mode TLS | `idleleo --install-tls` |
| Installer ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Afficher les informations d'installation | `idleleo --show` |
| Mettre à jour le script | `idleleo --update` |
| Mettre à jour Xray | `idleleo --xray-update` |
| Mettre à jour Nginx | `idleleo --nginx-update` |
| Configurer Fail2ban | `idleleo --set-fail2ban` |
| Configurer le blocage de trafic | `idleleo --traffic-blocker` |
| Voir le trafic des ports en temps réel | `idleleo --port-traffic` |

## Déploiement Docker

Le déploiement Docker est pris en charge. L'image intègre Xray et Nginx préinstallés, et toutes les fonctionnalités du script original sont disponibles dans le conteneur. Consultez le [Guide de déploiement Docker](/i18n/languages/fr/DOCKER.md) pour plus de détails.

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## Déploiement AI Skill

Prend en charge le déploiement automatique de Xray via des outils IA (par ex. Trae) sans interaction manuelle. Consultez [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill) pour plus de détails.

L'approche traditionnelle nécessite de se connecter en SSH au serveur, d'exécuter le script d'installation et de répondre aux questions interactives une par une ; l'approche Skill vous suffit de dire à l'IA vos besoins, et elle génère automatiquement un script non interactif, l'exécute et renvoie directement le lien VLESS.

**Modes pris en charge** : Reality / TLS / ws ONLY / XTLS ONLY

**Utilisation** : Dans un outil IA prenant en charge les Skills, dites simplement « Aidez-moi à installer Xray sur mon serveur », et l'IA collectera automatiquement les informations, générera le script, exécutera le déploiement et renverra les informations de connexion.

## Remarques importantes

* Si vous n'êtes pas familier avec les paramètres, utilisez les valeurs par défaut pour les champs non obligatoires (appuyez simplement sur Entrée)
* Les utilisateurs Cloudflare doivent activer le CDN uniquement après l'installation
* Ce script nécessite des connaissances de base en Linux et en réseaux informatiques
* Compatible Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+ ; certains modèles CentOS peuvent rencontrer des problèmes de compilation — envisagez de changer de système si nécessaire
* Il est recommandé de ne déployer qu'un seul proxy par serveur et d'utiliser le port 443 par défaut
* Le mappage de chaînes personnalisées vers UUIDv5 nécessite la prise en charge du client
* Utilisez ce script dans un environnement propre ; les débutants doivent éviter CentOS
* Ce programme dépend de Nginx — les utilisateurs ayant installé Nginx via [LNMP](https://lnmp.org) ou des scripts similaires doivent être attentifs aux conflits potentiels
* Les liens de partage xHTTP sont destinés aux clients compatibles xHTTP ; la sortie de configuration Clash ignore xHTTP
* N'utilisez pas ce script en production avant d'avoir vérifié son bon fonctionnement
* L'auteur fournit un support limité (parce qu'il n'est pas très doué)

## Remerciements

* Basé sur [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)
* Script d'accélération TCP de [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Configuration des certificats

**Certificat personnalisé** : Renommez vos fichiers crt et key en `xray.crt` et `xray.key`, puis placez-les dans le répertoire `/etc/idleleo/cert` (créez-le s'il n'existe pas). Attention aux permissions et à la durée de validité — les certificats personnalisés doivent être renouvelés manuellement après expiration.

**Certificat automatique** : Le script prend en charge la génération automatique de certificats Let's Encrypt (valides 3 mois), avec prise en charge théorique du renouvellement automatique.

## Afficher la configuration client

```bash
cat /etc/idleleo/info/xray_info.inf
```

## À propos de Xray

* Xray est un excellent outil proxy réseau open source prenant en charge Windows, macOS, Android, iOS, Linux et plus encore
* Ce script offre une configuration complète en un clic — une fois tous les processus terminés, configurez simplement votre client à partir des résultats affichés
* **Il est fortement recommandé** de bien comprendre le fonctionnement et les principes du programme

## Gestion des services

| Action | Commande |
|--------|----------|
| Démarrer Xray | `systemctl start xray` |
| Arrêter Xray | `systemctl stop xray` |
| Démarrer Nginx | `systemctl start nginx` |
| Arrêter Nginx | `systemctl stop nginx` |

## Répertoires

| Élément | Chemin |
|---------|--------|
| Répertoire principal | `/etc/idleleo` |
| Configuration Xray | `/etc/idleleo/conf/xray/config.json` |
| Configuration Nginx | `/etc/idleleo/conf/nginx/` |
| Infos d'installation | `/etc/idleleo/conf/install_config.json` |
| Fichiers de certificat | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Répertoires de logs | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Répertoire Nginx | `/usr/local/nginx` |
| Commande de gestion | `/usr/bin/idleleo` |
