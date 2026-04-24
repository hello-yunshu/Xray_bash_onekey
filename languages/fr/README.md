# Script d'installation automatique Xray — Reality / VLESS WebSocket/gRPC+TLS + Nginx

[简体中文](/README.md) | [English](/languages/en/README.md) | Français | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Merci à JetBrains pour l'autorisation de développement open source non commercial

## Fonctionnalités

* Tapez `idleleo` pour gérer le script ([Voir l'histoire de `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/Le-Vrai-Visage-Derri%C3%A8re-la-Brume))
* Traduction multilingue précise propulsée par Qwen-MT-Plus AI
* Prend en charge le protocole Reality avec Nginx en frontal recommandé (installable via le script)
* Protection fail2ban intégrée (installable via le script)
* Adopte la [proposition](https://github.com/XTLS/Xray-core/issues/91) de lien de partage de [@DuckSoft](https://github.com/DuckSoft) (beta), compatible avec Qv2ray, V2rayN, V2rayNG
* Adopte la proposition du projet [XTLS](https://github.com/XTLS/Xray-core/issues/158), conforme à la norme [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3), permettant le mappage de chaînes personnalisées vers un UUID VLESS
* Prend en charge le protocole gRPC : [Utiliser le protocole gRPC](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Prend en charge l'équilibrage de charge Reality / ws/gRPC :
  - [Déployer un équilibreur de charge Reality](https://hey.run/archives/bushu-reality-balance)
  - [Construire un équilibreur de charge backend](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## Pour aller plus loin

* Guide d'installation Reality : [Configurer un serveur Xray Reality](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Risques du protocole Reality : [Risques du protocole Xray Reality](https://hey.run/archives/reality-xie-yi-de-feng-xian)
* Accélérer le serveur avec Reality : [Accélérer le serveur via la « faille » du protocole Reality](https://hey.run/archives/use-reality)

## Groupe Telegram

* Groupe de discussion : [Cliquez pour rejoindre](https://t.me/+48VSqv7xIIFmZDZl)

## Prérequis

* Un serveur à l'étranger avec une adresse IP publique
* Pour le protocole Reality : préparez un domaine cible conforme aux exigences de Xray
* Pour la version TLS : préparez un domaine et ajoutez un enregistrement A
* Lisez la [documentation officielle Xray](https://xtls.github.io) pour comprendre Reality, TLS, WebSocket, gRPC et les concepts liés à Xray
* **Assurez-vous que curl est installé** : utilisateurs CentOS, exécutez `yum install -y curl` ; utilisateurs Debian/Ubuntu, exécutez `apt install -y curl`

## Installation rapide

```bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Déploiement Docker

Le déploiement Docker est pris en charge. Consultez le [Guide de déploiement Docker](/languages/fr/DOCKER.md) pour plus de détails.

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## Remarques importantes

* Si vous n'êtes pas familier avec les paramètres, utilisez les valeurs par défaut pour les champs non obligatoires (appuyez simplement sur Entrée)
* Les utilisateurs Cloudflare doivent activer le CDN uniquement après l'installation
* Ce script nécessite des connaissances de base en Linux et en réseaux informatiques
* Compatible Debian 12+ / Ubuntu 24.04+ / CentOS Stream 8+ ; certains modèles CentOS peuvent rencontrer des problèmes de compilation — envisagez de changer de système si nécessaire
* Il est recommandé de ne déployer qu'un seul proxy par serveur et d'utiliser le port 443 par défaut
* Le mappage de chaînes personnalisées vers UUIDv5 nécessite la prise en charge du client
* Utilisez ce script dans un environnement propre ; les débutants doivent éviter CentOS
* Ce programme dépend de Nginx — les utilisateurs ayant installé Nginx via [LNMP](https://lnmp.org) ou des scripts similaires doivent être attentifs aux conflits potentiels
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
| Config serveur Xray | `/etc/idleleo/conf/xray/config.json` |
| Répertoire Nginx | `/usr/local/nginx` |
| Fichiers de certificat | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Infos de config etc. | `/etc/idleleo` |
