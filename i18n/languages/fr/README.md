# Xray Script de gestion — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

Version actuelle : **3.3.1**

Chinois simplifié |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## Caractéristiques fonctionnelles

* Entrée`idleleo`Ouvrez le menu d’administration Xray pour gérer les installations, les services, les paramètres de sécurité, etc.
* Utilisez Qwen-MT-Plus AI pour réaliser une traduction multilingue précise.
* Prend en charge le protocole Reality ; il est recommandé d’associer un préfixe Nginx (installable depuis le script).
* Prend en charge les transmissions WebSocket, gRPC et xHTTP, avec la possibilité de choisir une transmission unique ou`ws+gRPC+xHTTP`Activer simultanément
* Prise en charge du double stack IPv4 / IPv6 : lors de l’installation, la capacité de sortie vers Internet est détectée automatiquement ; les noms de domaine sont enregistrés et vérifiés individuellement via A/AAAA, et les liens de partage correspondants ainsi que la configuration Clash sont générés.
* Protection fail2ban intégrée (peut être installée dans le script)
* Statistiques du trafic Xray intégrées, blocage du trafic, mise à jour des règles GeoIP/GeoSite et mises à jour programmées
* Prend en charge les scripts, Xray, Nginx et les mises à jour des certificats, et offre une sauvegarde ainsi qu’un retour à la version précédente en cas d’échec pour les mises à jour critiques.
* Avant une réinstallation ou un changement de mode, la configuration en cours est automatiquement sauvegardée ; en cas d’échec, la configuration d’origine est restaurée.
* La reconfiguration offre trois voies de sécurité : redéploiement de la configuration conservée, reconstruction à partir d’un modèle standard et basculement de mode.
* Adopter[@DuckSoft](https://github.com/DuckSoft)Le lien de partage de[Proposition](https://github.com/XTLS/Xray-core/issues/91)(beta) est compatible avec Qv2ray, V2rayN et V2rayNG.
* Adopter[XTLS](https://github.com/XTLS/Xray-core/issues/158)Proposition, conformément à[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)Standard, prise en charge du mappage de chaînes personnalisées vers VLESS et UUID.
* Prend en charge le protocole gRPC:[Utiliser le protocole gRPC](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Prise en charge de l’équilibrage de charge Reality / ws/gRPC/xHTTP :
  - [Déployer l'équilibrage de charge Reality](https://hey.run/posts/bushu-reality-balance)
  - [Mise en place d'un équilibrage de charge côté serveur](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Dans le mode Reality + Nginx, SNI Guard est activé par défaut : les SNI inconnus, les SNI vides et les anomalies TLS ne pénètrent pas dans le backend Xray Reality et sont traités par défaut selon une stratégie de confinement (ssl_reject_handshake). Les utilisateurs avancés peuvent basculer vers un site decoy personnalisé ou vers un refus direct en TCP. Cette fonction permet de réduire les sondages actifs et les fuites dues aux mauvaises configurations, sans viser une dissimulation parfaite.

## Lecture complémentaire

* `idleleo`Histoire derrière le nom :[La véritable apparence derrière le brouillard](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality Guide d'installation :[Déployer le serveur Xray Reality](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Risques liés au Reality :[Les risques du contrat Xray Reality](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality Serveur d'accélération :[Accélérer le serveur en exploitant la « vulnérabilité » du protocole Reality](https://hey.run/posts/use-reality)

## Groupe Telegram

* Groupe de discussion :[Cliquez pour rejoindre](https://t.me/+48VSqv7xIIFmZDZl)

## préparation

* Un serveur situé à l’étranger, doté d’une adresse IP publique.
* Installer le protocole Reality: il est nécessaire de préparer un nom de domaine cible conforme aux exigences de Xray.
* Installation de la version TLS: il est nécessaire de préparer un nom de domaine et de configurer correctement les enregistrements A et/ou AAAA en fonction du réseau disponible sur le serveur; dans un environnement à double pile, il est recommandé de configurer simultanément les enregistrements A et AAAA appropriés. Le script prend en charge la détection automatique des capacités réseau de IPv4/IPv6 et peut générer simultanément les points d’accès clients correspondants lorsque la double pile est disponible.
* Lecture[Xray Documentation officielle](https://xtls.github.io)Comprendre les concepts liés à Reality, TLS, WebSocket, gRPC et Xray.
* **Assurez-vous que curl est installé** : les utilisateurs de CentOS doivent exécuter`yum install -y curl`L’utilisateur exécute Debian/Ubuntu`apt install -y curl`

## Installation rapide

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

## Mode d'installation

| Mode | Explication |
|------|------|
| Reality + Nginx | En mode recommandé, le protocole simple ws/gRPC/xHTTP peut être ajouté selon les besoins pour la mise en charge. |
| Nginx + TLS | Prend en charge ws/gRPC/xHTTP et l’application ainsi que le renouvellement automatiques des certificats Let's Encrypt |
| ws/gRPC/xHTTP ONLY | Mode d’entrée indépendant sans TLS , principalement utilisé dans les scénarios de backend ou de répartition de charge. |
| Nœud de transit | Rôle de serveur dédié : utilise uniquement Nginx et Stream pour la redirection vers une seule destination TCP, sans installer Xray. |
| Docker | L’image contient préinstallés Xray, Nginx ainsi que le script principal. |

Lors de l’installation des modèles associés à ws/gRPC/xHTTP, vous pouvez choisir.`ws`、`gRPC`、`xHTTP`Ou`ws+gRPC+xHTTP`Le script génère séparément les ports, les chemins d’accès, les liens de partage et les codes QR correspondants ; Clash ne prend actuellement pas en charge xHTTP, et le script en informera dans la sortie de configuration.

## Instructions de reconfiguration

Lorsque l’environnement déjà installé est réinstallé, le script sauvegarde automatiquement la configuration en cours et propose trois options de reconfiguration :

| Chemin | Explication | Restriction |
|------|------|------|
| Réimplémentation avec conservation des configurations | Conserver les configurations personnalisées de routing/outbounds/DNS et multi-utilisateurs, en ne modifiant que les champs sélectionnés par l’utilisateur (port, chemin d’accès, paramètres UUID, Reality, etc.). | Les modifications de la structure de transfert (par exemple, ws → gRPC) ne sont pas prises en charge ; pour modifier la combinaison de transfert, veuillez reconstruire à l’aide du modèle standard. |
| Reconstruction du modèle standard | Générer la configuration du modèle standard à l’aide des paramètres réutilisables actuels ; la valeur personnalisée de routing/outbounds/DNS pourrait être supprimée. | Le nombre d’utilisateurs n’est pas obligatoirement maintenu constant. |
| Changement de mode | Basculer vers un mode de protocole différent (par exemple Reality → TLS), par défaut seul l’utilisateur principal UUID/email est réutilisé. | Les autres utilisateurs ne sont pas migrés automatiquement ; un message explicite sera affiché avant le basculement. |

Toute étape du processus de reconfiguration qui échoue (écriture de la configuration, démarrage des services, vérification de l’état de santé, etc.) entraîne automatiquement un retour à la configuration d’origine sauvegardée. Le répertoire de sauvegarde utilise un horodatage unique, ce qui permet d’effectuer plusieurs reconfigurations successives sans conflit.

## Commandes couramment utilisées

| Opération | Commande |
|------|------|
| Ouvrir le menu d'administration | `idleleo` |
| Afficher l’aide | `idleleo --help` |
| Installer le mode Reality | `idleleo --install-reality` |
| Installer le mode TLS | `idleleo --install-tls` |
| Installer ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Installer le nœud de transit | `idleleo --install-relay` |
| Script de désinstallation avec Xray/Nginx | `idleleo --purge` |
| Afficher les informations d'installation | `idleleo --show` |
| Script de mise à jour | `idleleo --update` |
| Mise à jour de Xray | `idleleo --xray-update` |
| Mise à jour de Nginx | `idleleo --nginx-update` |
| Configurer Fail2ban | `idleleo --set-fail2ban` |
| Configurer le blocage du trafic | `idleleo --traffic-blocker` |
| Afficher le trafic en temps réel des ports | `idleleo --port-traffic` |

## Instructions de mise à jour

### 3.2.9 / 3.2.10 / 3.2.11 → 3.3.x

Les mises à jour automatiques de l’ancien Shell ne seront pas transférées vers minor ;`idleleo --update auto_update`Sera clairement ignoré et conservé
Ancienne version, et aucune notification de réussite en mode silencieux ne sera envoyée. Veuillez utiliser la mise à niveau interactive en deux étapes :

```bash
bash /etc/idleleo/install.sh --update          # 交互终端，选择 Y
bash /etc/idleleo/install.sh --xray-update     # 再更新 Xray
```

L’environnement automatisé doit être explicitement confirmé :

```bash
bash /etc/idleleo/install.sh --update --yes                  # 同一 minor
bash /etc/idleleo/install.sh --update --yes --allow-major    # 跨 minor
```

`--yes`Seules les mises à jour du même minor sont automatiquement confirmées ; pour les mises à jour entre minor, une confirmation explicite est encore requise.`--allow-major`。
`--allow-major`Seule la restriction inter-minor est levée ; cela ne remplace pas la confirmation de Y/N (dans les scénarios non interactifs, celle-ci reste requise).
Donner simultanément à`--yes`). Il est recommandé d’exécuter d’abord avant la mise à niveau.`idleleo --backup`3.3.1 Autorisations du fichier de sauvegarde initiale
Égal à 0600.

### 3.3.0 → 3.3.1

Mettez à jour dans le menu d’administration « Assistant de mise à jour → Script de mise à jour », ou exécutez :

```bash
bash /etc/idleleo/install.sh --update
```

3.3.1 Correction des résidus de désinstallation hors ligne, des permissions de sauvegarde/journaux, correction de l’absence de Xray, enregistrement des échecs d’authentification installer et autres.
Protection contre la rétrogradation des métadonnées de Shell. La mise à jour n’altérera pas la configuration Xray existante ; REALITY`minClientVer`Compléter comme précédemment
Exécution des règles de la version 3.3.0.

3.3.1 La réémission conserve le numéro de version inchangé. Les nœuds ayant déjà installé l’ancienne version 3.3.1 ne seront pas mis à jour par`-u`Obtenir automatiquement le nouvel installateur
(La même version est considérée comme la plus récente) ;`-x`Seul le noyau Xray est mis à jour, les scripts Shell ne le sont pas. Lorsque de nouveaux paquets sont nécessaires,
Veuillez réinstaller ou effectuer une mise à jour manuelle.`/etc/idleleo/install.sh`。

### Mode XTLS de l’ancienne version

À partir de la version 3.3.0, l’ancien mode XTLS a été supprimé. Les services XTLS existants peuvent continuer à fonctionner après la mise à niveau, mais ne peuvent plus être réinstallés via script.
Basculer le mode ; si vous devez poursuivre la gestion, veuillez d’abord effectuer une sauvegarde et désinstaller, puis redéployer le mode de transit Reality/TLS/.

### Mise à jour automatique

La mise à jour automatique ne met automatiquement à niveau Shell que dans le même minor ; pour les mises à niveau entre minor, il est nécessaire d’effectuer manuellement les deux étapes susmentionnées. Xray et
La mise à jour automatique de Nginx continue d’être exécutée selon les métadonnées de API et est enregistrée en cas d’échec.`{组件, 目标版本, installer, 时间}`。

## RillML Xray AI Assistant d'exploitation et de maintenance

RillML (abréviation de Rill) fournit à Xray des capacités locales d’exploitation et de maintenance intelligentes et adaptatives.

Intégré à l’assistant d’exploitation et de maintenance local AI , il surveille en temps réel l’état de santé de Xray/Nginx, diagnostique automatiquement les pannes et propose des recommandations de résolution, sans nécessiter de API externe. Saisissez dans le menu principal.`9`Ou exécuter`idleleo --rill-agent`Entrer.

**Compétences clés**

* Surveillance : observation en temps réel de l’état des services et des configurations de Xray/Nginx
* Diagnostic : localisation de la cause racine du défaut, avec recommandation concernant le niveau de confiance (élevé / moyen / faible / preuves insuffisantes)
* Diagnostic : détermination automatique du type de panne avec recommandations de résolution, les explications indiquant clairement si le traitement peut être automatisé ou s’il ne s’agit que de conseils.
* Mode : Détection intelligente / Surveillance uniquement / Désactivation sécurisée. Le système ne sera pas modifié tant que la modification automatique n’aura pas été activée.

**Commandes couramment utilisées**

| Opération | Commande |
|------|------|
| Ouvrir le menu de l’assistant d’exploitation et de maintenance AI | `idleleo --rill-agent` |
| Installer ou réparer le moteur de décision AI | `idleleo --rill-agent-install` |
| Afficher l’état de la condition AI | `idleleo --rill-agent-status` |
| Exécuter le diagnostic des défauts de AI | `idleleo --rill-agent-diagnose` |
| Moteur de validation des règles AI | `idleleo --rill-agent-verify` |
| Évaluation de l’arrêt en toute sécurité de AI | `idleleo --rill-agent-safe-disable` |
| Désinstaller le moteur Rill AI | `idleleo --rill-agent-uninstall` |

Le moteur de jugement par AI est actuellement encore en phase de test ; il est recommandé de se fier principalement aux recommandations diagnostiques, et par défaut, le système ne sera pas modifié automatiquement.

## Déploiement de Docker

Prise en charge du déploiement via Docker ; l’image contient préinstallés Xray et Nginx, et toutes les fonctionnalités du script d’origine sont directement utilisables à l’intérieur du conteneur. Voir les détails.[Docker Guide de déploiement](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## Déploiement de AI Skill

Prend en charge le déploiement automatique de Xray via des outils AI (tels que Trae), sans intervention manuelle. Pour plus de détails, voir[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

La méthode traditionnelle exige de se connecter au serveur via SSH, d’exécuter un script d’installation et de répondre à chaque question de manière interactive ; avec la méthode Skill, il suffit de communiquer vos besoins à l’AI, qui génère automatiquement un script non interactif et l’exécute, puis vous renvoie directement le lien VLESS.

**Modes pris en charge** : Reality / TLS / ws / ONLY / Nœud de transit

**Mode d’utilisation** : Dans un outil AI prenant en charge Skill, il suffit de dire « Aide-moi à déployer Xray sur le serveur », et AI collectera automatiquement les informations, générera le script, exécutera le déploiement et renverra les informations de connexion.

## Remarques importantes

* Si vous ne connaissez pas la signification des différentes options, utilisez les valeurs par défaut pour les champs non obligatoires (appuyez simplement sur Entrée tout au long de la procédure).
* Les utilisateurs de Cloudflare, veuillez activer le CDN uniquement après l’installation.
* Ce script nécessite des connaissances de base en Linux ainsi que des notions élémentaires en réseaux informatiques.
* Prend en charge Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+, certains modèles de CentOS peuvent présenter des problèmes de compilation ; il est recommandé de changer de système si vous rencontrez des difficultés.
* Il est recommandé de ne déployer qu’un seul agent par serveur, en utilisant le port 443 par défaut.
* Le mappage d’une chaîne personnalisée vers UUIDv5 nécessite la prise en charge du client.
* Il est recommandé de l’utiliser dans un environnement propre ; les débutants sont priés de ne pas utiliser CentOS
* Ce programme dépend de Nginx, qui a été validé.[LNMP](https://lnmp.org)Les utilisateurs ayant déjà installé Nginx via un script sont priés de faire attention aux conflits potentiels.
* Les liens de partage xHTTP sont destinés aux clients prenant en charge xHTTP ; la sortie de configuration Clash ignorera xHTTP.
* Veuillez ne pas utiliser ce script en environnement de production avant d’en avoir vérifié la fonctionnalité.
* Auteur : Yunshu, assistance limitée uniquement.

## Remerciements

* Basé sur[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)Développer
* TCP Script d'accélération référencé à partir de[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## Configuration du certificat

**Certificat personnalisé** : Renommez respectivement les fichiers crt et key en`xray.crt`Et`xray.key`, mettre dans`/etc/idleleo/cert`Répertoire (créé si le répertoire n’existe pas). Veuillez prêter attention aux autorisations et à la durée de validité du certificat ; après l’expiration d’un certificat personnalisé, vous devrez le renouveler vous-même.

**Certificat automatique** : Le script prend en charge la génération automatique d’un certificat Let's Encrypt (valable 3 mois) et, en théorie, permet également son renouvellement automatique.

## Afficher la configuration du client

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray Introduction

* Xray est un excellent outil open source de proxy réseau, pris en charge sur toutes les plateformes, notamment Windows, macOS, Android, iOS et Linux.
* Ce script constitue une configuration complète en une seule étape ; une fois toutes les étapes exécutées sans incident, il suffit de configurer le client conformément aux résultats affichés pour pouvoir l’utiliser.
* **Il est fortement recommandé** de bien comprendre le flux de travail et les principes de fonctionnement du programme.

## Gestion des services

| Opération | Commande |
|------|------|
| Lancer Xray | `systemctl start xray` |
| Arrêter Xray | `systemctl stop xray` |
| Lancer Nginx | `systemctl start nginx` |
| Arrêter Nginx | `systemctl stop nginx` |

## Répertoire associé

| Contenu | Chemin |
|------|------|
| Répertoire principal | `/etc/idleleo` |
| Configurer Xray | `/etc/idleleo/conf/xray/config.json` |
| Configurer Nginx | `/etc/idleleo/conf/nginx/` |
| Informations d'installation | `/etc/idleleo/conf/install_config.json` |
| Fichier de certificat | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| Répertoire des journaux | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Répertoire d’installation de Nginx | `/usr/local/nginx` |
| Commandes d'administration | `/usr/bin/idleleo` |

Test de la sonde : vérifier que le lien de traduction Qwen README fonctionne de bout en bout.
