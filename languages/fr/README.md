# Xray prend en charge Reality / VLESS WebSocket/gRPC+TLS avec Nginx - Script d'installation automatique

[简体中文](/README.md) | [English](/languages/en/README.md) | Français | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | [한국어](/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Merci à JetBrains pour l'autorisation de développement open source non commercial

## Instructions d'utilisation

* Vous pouvez simplement entrer la commande : `idleleo` pour gérer le script. ( [Voir l'histoire de `idleleo`](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/Backstory#la-voie-immortelle-didleleo) )
* Traduction multilingue précise réalisée avec l'IA Qwen-MT-Plus.
* Il est recommandé d'utiliser Nginx devant Reality, vous pouvez l'installer directement via le script.
* Il est conseillé d'activer fail2ban, vous pouvez l'installer via le script.
* Utilisation de la proposition de lien de partage de [@DuckSoft](https://github.com/DuckSoft) (beta), compatible avec Qv2ray, V2rayN, V2rayNG.
* Utilisation de la proposition du projet [XTLS](https://github.com/XTLS/Xray-core/issues/158), conforme à la norme [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3), permettant de mapper une chaîne personnalisée vers un UUID VLESS.
* Instructions d'installation de Reality : [Configurer un serveur Xray avec le protocole Reality](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi).
* Risques liés au protocole Reality : [Risques associés au protocole Reality](https://hey.run/archives/reality-xie-yi-de-feng-xian).
* Accélérer le serveur grâce au protocole Reality : [Accélérer le serveur en utilisant un "bug" du protocole Reality](https://hey.run/archives/use-reality).
* Ajout de la configuration d'équilibrage de charge, tutoriel : [Avancées avec XRay – Configurer un équilibrage de charge backend](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng).
* Ajout de la prise en charge du protocole gRPC, voir : [Avancées avec XRay – Utiliser le protocole gRPC](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi).

## Groupe Telegram

* Groupe de discussion Telegram : [Cliquez sur le lien](https://t.me/+48VSqv7xIIFmZDZl)

## Préparation

* Préparez un serveur, qui fonctionnera à l'étranger et aura une adresse IP publique.
* Pour l'installation de Reality, trouver un domaine conforme aux exigences de Xray.
* Pour l'installation avec TLS, préparer un domaine et configurer correctement son enregistrement A.
* Lire la documentation officielle de [Xray](https://xtls.github.io), pour comprendre les protocoles Reality, TLS, WebSocket, gRPC ainsi que les exigences sur le domaine utilisé pour Reality.
* **Installer curl**, les utilisateurs de Centos doivent exécuter : `yum install -y curl` ; les utilisateurs Debian/Ubuntu doivent exécuter : `apt install -y curl`.

## Méthode d'installation

Copier et exécuter la commande suivante :

``` bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## Remarques importantes

* Si vous ne comprenez pas les paramètres proposés par le script, sauf pour les champs obligatoires, utilisez les valeurs par défaut proposées (tapez Entrée à chaque fois).
* Les utilisateurs de Cloudflare doivent activer la fonction CDN après l'installation.
* Ce script nécessite des bases en Linux, une expérience de son utilisation, ainsi qu'une compréhension des réseaux informatiques et des opérations basiques.
* Actuellement, il supporte Debian 9+ / Ubuntu 18.04+ / Centos7+ ; certains modèles Centos peuvent rencontrer des problèmes de compilation, il est donc recommandé de changer de modèle système en cas de difficultés.
* L'auteur fournit un support limité, car il estime ne pas être très compétent.
* Les liens de partage sont en version expérimentale, des changements futurs sont possibles, veuillez vérifier si votre client les supporte.
* Le mappage d'une chaîne personnalisée vers UUIDv5 nécessite que le client le prenne en charge.

## Remerciements

* Ce script s'inspire de <https://github.com/wulabing/V2Ray_ws-tls_bash_onekey>, merci à wulabing.
* Le script d'accélération TCP provient du projet <https://github.com/ylx2016/Linux-NetSpeed>, merci à ylx2016.

## Certificats

Si vous possédez déjà les fichiers de certificat pour le domaine utilisé, veuillez nommer les fichiers crt et key en xray.crt et xray.key, puis les placer dans le répertoire `/etc/idleleo/cert` (créez le répertoire si nécessaire). Vérifiez les permissions des certificats ainsi que leur date d'expiration. Les certificats personnalisés expirés doivent être renouvelés manuellement.

Le script prend en charge la génération automatique de certificats Let's Encrypt, valables 3 mois, et théoriquement capables de se renouveler automatiquement.

## Afficher la configuration client

`cat /etc/idleleo/xray_info.txt`

## Présentation de Xray

* Xray est un excellent outil de proxy réseau open source qui vous permet de naviguer sur Internet sans restriction. Il est désormais compatible avec tous les systèmes : Windows, Mac, Android, iOS, Linux, etc.
* Ce script configure automatiquement Xray en un seul clic. Une fois l'installation terminée correctement, il vous suffit de configurer votre client en fonction des résultats affichés pour l'utiliser.
* Veuillez noter : nous vous recommandons fortement de bien comprendre le fonctionnement et les principes de ce programme.

## Recommandation d'installation unique par serveur

* Ce script installe par défaut la dernière version du noyau Xray.
* Il est recommandé d'utiliser le port 443 par défaut comme port de connexion.
* Le contenu de brouillage peut être remplacé manuellement.

## Autres remarques

* Il est recommandé d'utiliser ce script dans un environnement propre. Si vous êtes débutant, évitez d'utiliser le système Centos.
* Avant de confirmer que ce script fonctionne correctement, veuillez ne pas l'utiliser dans un environnement de production.
* Ce programme dépend de Nginx pour fonctionner. Les utilisateurs ayant installé Nginx via [LNMP](https://lnmp.org) ou d'autres scripts similaires doivent faire attention, car l'utilisation de ce script pourrait entraîner des erreurs imprévues.
* Les utilisateurs de Centos doivent ouvrir les ports nécessaires (par défaut : 80, 443) dans le pare-feu.

## Démarrage

Démarrer Xray : `systemctl start xray`

Arrêter Xray : `systemctl stop xray`

Démarrer Nginx : `systemctl start nginx`

Arrêter Nginx : `systemctl stop nginx`

## Répertoires importants

Fichier de configuration Xray serveur : `/etc/idleleo/conf/xray/config.json`

Répertoire Nginx : `/usr/local/nginx`

Fichiers de certificat : `/etc/idleleo/cert/xray.key` et `/etc/idleleo/cert/xray.crt` — veuillez vérifier les permissions des certificats

Fichiers de configuration, etc. : `/etc/idleleo`