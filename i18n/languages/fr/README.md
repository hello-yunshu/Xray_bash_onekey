# Script de gestion Xray

> Un outil tout-en-un de déploiement et de gestion Xray pour Debian, Ubuntu et CentOS Stream, couvrant Reality, TLS, ws/gRPC/xHTTP, les nœuds relais et Docker.

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE) [![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)](https://github.com/hello-yunshu/Xray_bash_onekey) [![Shell: Bash](https://img.shields.io/badge/shell-Bash-4EAA25)](https://github.com/hello-yunshu/Xray_bash_onekey)

Chinois simplifié | [English](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/en/README.md) | [Français](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fr/README.md) | [Русский](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ru/README.md) | [فارسی](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fa/README.md) | [한국어](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ko/README.md)

## Présentation

Ce projet est un script de déploiement et d'exploitation Xray écrit en Bash. Il réunit l'installation, les certificats, le frontal Nginx, la configuration client, la gestion des services, la sauvegarde et la restauration, ainsi que le dépannage courant dans un seul menu. Il convient aux utilisateurs qui veulent rapidement mettre en place un proxy sur un serveur unique sans maintenir toute la pile de configuration à la main.

Le script génère la configuration et orchestre les services, tandis que Xray assure le proxy proprement dit. Les modes Reality et TLS fonctionnent mieux avec un frontal Nginx. Chaque écriture critique est précédée d'une vérification de syntaxe ou d'une sauvegarde, et les échecs sont annulés autant que possible afin de ne pas laisser un service en cours d'exécution dans un état incomplet.

## Fonctionnalités

| Capacité | Description |
|---|---|
| Modes d'installation | Reality + Nginx, Nginx + TLS, ws/gRPC/xHTTP ONLY, nœud relais, Docker |
| Protocoles de transport | WebSocket, gRPC et xHTTP, seuls ou combinés en `ws+gRPC+xHTTP` |
| Réseau double pile | Détecte la sortie IPv4/IPv6, valide séparément les enregistrements A/AAAA du domaine et génère les points d'accès client correspondants |
| Sortie client | Liens de partage, QR codes et profils Clash ; Clash ne prend pas encore en charge xHTTP |
| Gestion de la sécurité | fail2ban, blocage du trafic, SNI Guard, pare-feu et gestion des certificats |
| Opérations quotidiennes | Gestion des services, modifications de configuration, nettoyage des journaux, inspection du trafic par port, sauvegarde et restauration |
| Statistiques de trafic | Lecture des octets montants, descendants et du total par inbound, avec JSON, réinitialisation et actualisation en direct |
| Assistant intelligent | Assistant d'exploitation local RillML pour la surveillance, le diagnostic et les conseils de remédiation |
| Maintenance | Mises à jour du script, de Xray, de Nginx et des certificats, avec sauvegarde et restauration en cas de changement critique |

## Systèmes pris en charge

| Système | Version | Remarques |
|---|---|---|
| Debian | 12, 13 | Utilise `apt` ; la CI couvre `debian:12-slim` et `debian:13-slim` |
| Ubuntu | 24.04, 26.04 | Utilise `apt` ; la CI couvre `ubuntu:24.04` et `ubuntu:26.04` |
| CentOS Stream | 10 | Utilise le gestionnaire de paquets RPM ; la CI couvre `quay.io/centos/centos:stream10` |
| Rocky / AlmaLinux | 10+ | Traités comme la famille RPM ; la version majeure doit être au moins 10 |

Le script exige root, systemd, une adresse IP publique et un accès réseau sortant fonctionnel. L'installation installe automatiquement les dépendances telles que `curl`, `jq`, `openssl`, `qrencode` et `nmap`. Les modes Reality/TLS exigent aussi un domaine avec des enregistrements A et/ou AAAA corrects pour le réseau du serveur.

> Les systèmes non pris en charge sont refusés avant l'installation. Les modèles CentOS varient beaucoup ; en cas de problème de compilation ou de dépendance, utilisez plutôt Debian ou Ubuntu.

## Démarrage rapide

Préparez un serveur Linux pris en charge et exécutez la commande suivante en root :

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

Une fois l'installation terminée, exécutez `idleleo` pour ouvrir le menu de gestion. Vous pouvez aussi lancer `idleleo --install-reality`, `idleleo --install-tls` ou `idleleo --install-none` pour entrer directement dans un mode.

Lors de la première utilisation, suivez l'assistant d'installation et appuyez sur Entrée pour accepter les valeurs par défaut des éléments que vous ne connaissez pas. Après l'installation, configurez le client à partir du lien de partage ou du QR code affiché par le script.

## Modes d'installation

| Mode | Cas d'usage | Points clés |
|---|---|---|
| Reality + Nginx | Point d'entrée recommandé pour un serveur unique | Des protocoles simples ws/gRPC/xHTTP peuvent être ajoutés pour l'équilibrage de charge |
| Nginx + TLS | Point d'entrée TLS standard | Demande et renouvelle automatiquement les certificats Let's Encrypt |
| ws/gRPC/xHTTP ONLY | Nœud backend ou d'équilibrage | Sans TLS ; écoute uniquement sur `127.0.0.1` par défaut |
| Nœud relais | Redirection TCP indépendante | Utilise Nginx Stream pour rediriger vers une seule cible et n'installe pas Xray |
| Docker | Déploiement conteneurisé | L'image inclut Xray, Nginx et le script principal |

Lors de l'installation d'un mode ws/gRPC/xHTTP, choisissez `ws`, `gRPC`, `xHTTP` ou `ws+gRPC+xHTTP`. Le script génère un port, un chemin, un lien de partage et un QR code pour chaque transport. Les profils Clash ignorent xHTTP et le script affiche un avertissement.

## Menu de gestion

Exécutez `idleleo` pour ouvrir le menu principal :

| Option | Fonction |
|---|---|
| `1` | Assistant d'installation |
| `2` | Modifications de configuration |
| `3` | Afficher les informations |
| `4` | Services et certificats Xray / TLS |
| `5` | Assistant de mise à jour |
| `6` | Options supplémentaires (accélération TCP, Fail2ban, statistiques de trafic, blocage du trafic, journaux, débit réseau) |
| `7` | Sauvegarde, restauration et désinstallation |
| `8` | Changer la langue |
| `9` | Assistant d'exploitation Rill Xray AI |
| `0` | Quitter |

L'entrée « Options supplémentaires → Statistiques de trafic Xray » propose quatre actions : activer ou désactiver les statistiques, les consulter, les réinitialiser et les surveiller en direct.

## Commandes courantes

| Action | Commande |
|---|---|
| Ouvrir le menu de gestion | `idleleo` |
| Afficher l'aide | `idleleo --help` |
| Installer le mode Reality | `idleleo --install-reality` |
| Installer le mode TLS | `idleleo --install-tls` |
| Installer ws/gRPC/xHTTP ONLY | `idleleo --install-none` |
| Installer un nœud relais | `idleleo --install-relay` |
| Afficher les informations d'installation | `idleleo --show` |
| Afficher les informations d'accès Xray | `idleleo --xray-access` |
| Afficher les erreurs Xray | `idleleo --xray-error` |
| Afficher le trafic en temps réel par port | `idleleo --port-traffic` |
| Mettre à jour le script | `idleleo --update` |
| Mettre à jour Xray | `idleleo --xray-update` |
| Mettre à jour Nginx | `idleleo --nginx-update` |
| Configurer Fail2ban | `idleleo --set-fail2ban` |
| Configurer le blocage du trafic | `idleleo --traffic-blocker` |
| Sauvegarder les fichiers gérés par le script | `idleleo --backup` |
| Restaurer les fichiers gérés par le script | `idleleo --restore` |
| Désinstaller le script avec Xray/Nginx | `idleleo --purge` |
| Consulter les statistiques de trafic | `idleleo --stats` / `idleleo --stats --json` |
| Réinitialiser les statistiques | `idleleo --stats-reset` (demande confirmation ; `--yes` la contourne) |
| Surveiller les statistiques en direct | `idleleo --stats-watch` [secondes] |

## Statistiques de trafic Xray

Lorsque les statistiques sont activées, l'API de statistiques écoute uniquement sur `127.0.0.1:10085` par défaut. La lecture est assurée par le script autonome `/etc/idleleo/scripts/xray_stats.sh`, avec les permissions `0600 root:root`. Le script principal ne fournit que le point d'entrée, le téléchargement, la vérification SHA256 et la délégation ; il ne duplique pas la logique de requête.

```bash
idleleo --stats                  # Tableau : montant, descendant et total par inbound
idleleo --stats --json           # JSON lisible par machine
idleleo --stats-reset            # Remise à zéro après confirmation interactive
idleleo --stats-reset --yes      # Confirmation pour l'automatisation
idleleo --stats-watch 5          # Actualisation toutes les 5 secondes ; Ctrl-C quitte
```

Si le script de statistiques est absent, le script principal télécharge `xray_stats.sh` depuis la Release actuelle et le vérifie avec `statsScriptSha256` de `release-manifest.json`. Un échec de vérification n'affecte que la lecture, pas l'activation des statistiques. Si les statistiques sont activées mais que `api.listen` manque, la première exécution de `--stats` demande explicitement s'il faut l'ajouter et redémarrer Xray ; un refus laisse la configuration inchangée.

### Codes de sortie

| Code de sortie | Signification |
|---|---|
| `0` | Requête réussie ; des compteurs à zéro restent un succès |
| `1` | L'utilisateur a annulé la réinitialisation |
| `2` | Prérequis manquant : statistiques désactivées, pas de `api.listen`, Xray arrêté, API inaccessible, script absent ou vérification échouée |
| `3` | Échec de l'appel API ou de l'analyse JSON |
| `4` | Arguments invalides |
| `5` | Utilisateur non root ou permissions insuffisantes |
| `130` | Surveillance interrompue par Ctrl-C |

Les échecs n'affichent jamais un faux zéro : des statistiques désactivées ou une API inaccessible renvoient `2`, un JSON invalide renvoie `3` et un utilisateur non root renvoie `5`.

### Frontière de sécurité

> L'API de statistiques écoute sur l'adresse de bouclage mais n'a pas d'authentification. D'autres utilisateurs locaux peuvent théoriquement accéder au port et lire ou réinitialiser les compteurs. Utilisez-la sur un VPS mono-utilisateur et n'exposez jamais `10085` sur Internet ; `--stats-reset` exige toujours une confirmation explicite.

Xray StatsService fournit uniquement les compteurs montants/descendants par inbound et l'Uptime ; il **ne fournit pas le nombre de connexions actives**. Pour obtenir ce nombre, utilisez des outils système ou une solution d'observabilité séparée plutôt que d'attendre cette information de `--stats`.

## Sauvegarde et restauration

`idleleo --backup` ne sauvegarde que les fichiers gérés par le script : `/etc/idleleo`, `/usr/local/nginx`, le binaire Xray, les unités systemd, la crontab root et l'état ACME. Ce n'est pas une sauvegarde complète de l'hôte et elle n'inclut pas automatiquement les données placées ailleurs.

`idleleo --restore` sélectionne la sauvegarde la plus récente. Les sauvegardes avec manifeste de sommes de contrôle vérifient le SHA256 de chaque fichier archivé et suppriment la configuration gérée absente de la sauvegarde ; les sauvegardes plus anciennes sans manifeste ne reçoivent qu'une validation structurelle et ignorent le nettoyage entre modes. Les fichiers créés par l'utilisateur sont conservés et les services ne sont pas démarrés automatiquement. Après une restauration entre modes, inspectez la configuration restante et redémarrez les services si nécessaire. Si une ancienne sauvegarde n'a pas de lien symbolique `/usr/local/share/xray`, la restauration le crée ou fusionne l'ancien répertoire GeoData dans `/etc/idleleo/share/xray`, puis valide avec un vrai `xray run -test` ; un échec de l'auto-réparation est annulé, donc les anciennes sauvegardes restent restaurables sur un nouvel hôte sans réinstallation.

Les archives de sauvegarde peuvent contenir des certificats, des clés privées et la configuration client. Traitez-les comme des fichiers sensibles et ne les téléchargez pas vers des emplacements publics.

## Mise à niveau et mises à jour

Mettez à jour depuis « Assistant de mise à jour → Mettre à jour le script » dans le menu de gestion, ou exécutez :

```bash
idleleo --update                  # Confirmation interactive
idleleo --update --yes            # Non interactif, confirmation automatique dans la même série de publication
idleleo --update --yes --allow-major  # Mise à jour entre séries ; lever explicitement la restriction
```

`--yes` ne confirme automatiquement que les mises à jour d'une même série de publication ; une mise à jour entre séries exige aussi `--allow-major`. `--allow-major` ne fait que lever la restriction de série et ne remplace pas la confirmation ; en mode non interactif, `--yes` reste nécessaire. Une mise à jour du script remplace `/etc/idleleo/install.sh` dans son ensemble, recalcule les URL de Release pour le nouveau script et synchronise les ressources auxiliaires.

`--xray-update` ne met à jour que le cœur Xray, tandis que `--nginx-update` ne met à jour que Nginx ; aucun des deux ne met à jour le script lui-même. Les mises à jour automatiques du script restent limitées à la même série de publication ; les mises à jour automatiques de Xray et Nginx suivent toujours les métadonnées de l'API. Exécutez `idleleo --backup` avant une mise à jour.

Le mode XTLS historique ne propose plus de point d'entrée pour une nouvelle installation ou une réinstallation. Les services XTLS existants peuvent continuer à fonctionner, mais le script ne peut plus les réinstaller ni changer de mode. Pour continuer à les gérer, sauvegardez puis désinstallez, avant de redéployer Reality, TLS ou le mode relais.

## Reconfiguration

Lorsque l'installateur est relancé sur un système déjà installé, il sauvegarde automatiquement la configuration en cours et propose trois chemins :

| Chemin | Description | Limite |
|---|---|---|
| Conserver la configuration et redéployer | Conserve le routage, les outbounds, le DNS et la configuration multi-utilisateur personnalisés ; ne modifie que les champs sélectionnés | Ne prend pas en charge les changements de structure de transport, par exemple ws vers gRPC |
| Reconstruire depuis le modèle standard | Génère un modèle standard à partir des paramètres réutilisables | Le routage, les outbounds et le DNS personnalisés peuvent être supprimés |
| Changement de mode | Passe à un autre mode de protocole, par exemple Reality vers TLS | Réutilise uniquement l'UUID/email de l'utilisateur principal par défaut ; les autres utilisateurs ne sont pas migrés |

Si une étape échoue (écriture de configuration, démarrage du service, contrôle de santé, etc.), le script revient à la configuration originale sauvegardée. Les répertoires de sauvegarde utilisent des horodatages uniques, de sorte que des reconfigurations successives ne se chevauchent pas.

## Migration vers le gestionnaire Go (expérimental)

> Niveau de preuve : `CONTAINER_VERIFIED` au niveau conteneur (Ubuntu 24.04 épinglé par digest avec systemd/Xray/nginx réels), **et non « vérifié sur un vrai VPS »**. L'émission/le renouvellement ACME réels sont hors périmètre de cette série.

- **La version actuelle n'active pas Go et ne propose jamais la migration** : une nouvelle installation, `-u`, `auto_update`, une réinstallation complète et le menu ne sondent, ne téléchargent et ne mentionnent jamais Go ; les utilisateurs ordinaires ne voient aucun point d'entrée de migration. Le code de migration n'est conservé que pour les versions ultérieures et n'est atteint que par le paramètre interne `--internal-bridge-offer`, lors des vérifications des mainteneurs.
- **Étapes de migration** : SHA256 du binaire candidat + vérification ELF → audit en lecture seule et résumé complet des changements → instantané/journal → pré-vérification `xray -test` / `nginx -t` → bascule atomique de `/usr/bin/idleleo` → suppression précise des 4 entrées cron du projet → installation de `idleleo-schedule.timer`.
- **Contenu conservé** : configuration `/etc/idleleo`, certificats et clés privées, utilisateurs, cron défini par l'utilisateur, fragments nginx personnalisés.
- **Retour arrière** : toute étape échouée est restaurée par `/opt/idleleo/recovery/idleleo-recover` ; après `COMMITTED`, aucune migration inverse implicite.
- **Tâches planifiées** : `idleleo schedule status` pour consulter, `install` / `remove` / `run` pour gérer. Le rafraîchissement GeoData et la collecte des statistiques sont natifs (timers systemd) ; la mise à jour automatique utilise le canal de release Go et **exige un `idleleo update configure --manifest-url URL` explicite** ; sans configuration, chaque cycle enregistre `degraded` (jamais de source devinée, jamais d'échec silencieux) ; le renouvellement des certificats reste sans ACME, avec seulement le contrat d'empreinte et les alertes d'expiration après renouvellement externe.
- **Commandes Phase 04** : `idleleo update status|check|apply|configure`, `idleleo stats [--json]`, `idleleo service status|start|stop|restart|reload|logs`, `idleleo rill status`. Les commandes de service n'autorisent que les unités propres ; `stats` est en lecture seule, sans watch/reset.
- **Contrat de certificat** : enregistre l'empreinte DER ; `restart xray` / `reload nginx` uniquement si l'empreinte change, pas de redémarrage sinon ; une clé privée lisible par tous refuse le reload ; expiration ou <30 jours sans changement enregistre `degraded`. **L'émission/le renouvellement/le nettoyage ACME réels ne sont pas implémentés.**
- **Contenu personnalisé** : les clés racine Xray inconnues et les fragments nginx personnalisés listés par l'audit doivent être confirmés manuellement, sinon `prepare` refuse avec exit 6, sans écrasement silencieux.

## Dépannage

| Symptôme | À vérifier en premier | Action suggérée |
|---|---|---|
| Installation refusée | `/etc/os-release` et la matrice de prise en charge | Passez à une version de système prise en charge, ou utilisez Debian/Ubuntu |
| Xray ne démarre pas | `systemctl status xray`, `idleleo --xray-error` | Consultez `journalctl -u xray`, la configuration et l'utilisation des ports |
| Erreur de syntaxe de configuration | `xray run -test -config /etc/idleleo/conf/xray/config.json` | Corrigez le problème signalé, ou revenez en arrière avec `idleleo --restore` |
| Port déjà utilisé | `ss -ltnp` | Libérez le port ou changez le port d'écoute depuis le menu |
| Problème de certificat | `idleleo --cert-status` | Vérifiez le DNS, les ports 80/443 et l'état ACME, puis exécutez `idleleo --cert-update` |
| Conflit avec un Nginx existant | `/usr/local/nginx/sbin/nginx -V`, `systemctl status nginx` | Ne mélangez pas avec un Nginx installé par LNMP ou un script similaire ; supprimez d'abord le conflit |
| Les statistiques renvoient `2` | Activation des statistiques, état de Xray, `127.0.0.1:10085` | Activez les statistiques, démarrez Xray ou vérifiez `api.listen` |
| Les statistiques renvoient `3` | Réponse de l'API et structure JSON | Vérifiez les journaux et la configuration Xray, et confirmez que StatsService est disponible |
| Les statistiques renvoient `5` | Utilisateur actuel | Exécutez en root ou vérifiez les permissions des fichiers |
| Clash n'a pas de nœuds | Type de protocole | Clash ne prend pas en charge xHTTP ; utilisez un client compatible |

Journaux et diagnostics : `/etc/idleleo/logs/`, `/var/log/xray/`, `idleleo --show`, `idleleo --xray-access` et `idleleo --xray-error`.

## Questions fréquentes

**Les statistiques peuvent-elles afficher le nombre de connexions actives ?** Non. StatsService fournit uniquement les compteurs montants/descendants par inbound et l'Uptime ; il ne fournit pas le nombre de connexions.

**Quand les utilisateurs de Cloudflare doivent-ils activer le CDN ?** Activez le CDN seulement après avoir vérifié l'installation, les certificats et la connectivité directe. Sinon, le proxy CDN peut interférer avec l'émission des certificats.

**Peut-on utiliser IPv4 et IPv6 ensemble ?** Oui. Le script détecte la capacité de sortie publique et valide séparément les enregistrements A/AAAA du domaine. En environnement double pile, configurez correctement les enregistrements A et AAAA.

**Comment modifier le port, l'UUID ou le transport ?** Ouvrez « Modifications de configuration » dans le menu, ou relancez l'assistant d'installation et choisissez un chemin de reconfiguration. Utilisez la reconstruction depuis le modèle standard pour changer la structure de transport.

**Comment désinstaller ?** Exécutez `idleleo --purge`. Avant la désinstallation, exécutez `idleleo --backup` et décidez si vous souhaitez conserver la configuration et les certificats.

**Quelles sont les exigences pour mapper une chaîne personnalisée vers un UUID ?** Le script utilise le mappage UUIDv5, qui exige la prise en charge côté client. Si le client ne la prend pas en charge, utilisez un UUID standard.

**Puis-je l'utiliser directement en production ?** Vérifiez d'abord la connectivité, le renouvellement des certificats, la sauvegarde/restauration et le chemin de mise à jour dans un environnement de test avant de l'utiliser en production.

## Consignes de sécurité

- L'API de statistiques écoute uniquement sur `127.0.0.1` et n'a pas d'authentification. N'exposez pas `10085` sur Internet et ne laissez pas des utilisateurs locaux non fiables y accéder.
- Le mode Reality + Nginx active SNI Guard par défaut : les SNI inconnus, les SNI vides et les TLS anormaux n'atteignent jamais le backend Xray Reality ; l'isolation `ssl_reject_handshake` est utilisée par défaut.
- Fail2ban, le pare-feu et le blocage du trafic sont des renforcements facultatifs. Avant de les activer, assurez-vous qu'ils ne peuvent pas bloquer votre propre accès d'administration.
- Les archives de sauvegarde, les certificats et la configuration client contiennent des informations sensibles. Restreignez les permissions et évitez tout partage public.
- Le script exige root ; ne l'utilisez pas en production avant d'avoir vérifié sa disponibilité.

## Répertoires et services

| Élément | Chemin |
|---|---|
| Répertoire principal | `/etc/idleleo` |
| Configuration Xray | `/etc/idleleo/conf/xray/config.json` |
| Configuration Nginx | `/etc/idleleo/conf/nginx/` |
| Configuration d'état du script | `/etc/idleleo/conf/install_config.json` |
| Fichiers de certificat | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| Répertoires de journaux | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Répertoire d'installation Nginx | `/usr/local/nginx` |
| Commande de gestion | `/usr/bin/idleleo` |
| Texte d'information d'installation | `/etc/idleleo/info/xray_info.inf` |

| Action | Commande |
|---|---|
| Démarrer Xray | `systemctl start xray` |
| Arrêter Xray | `systemctl stop xray` |
| Démarrer Nginx | `systemctl start nginx` |
| Arrêter Nginx | `systemctl stop nginx` |

## Docker et AI Skill

L'image Docker inclut Xray, Nginx et le script principal ; les fonctionnalités du script restent disponibles dans le conteneur. Consultez le [guide de déploiement Docker](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/docker/DOCKER.md).

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

AI Skill permet à un outil AI compatible de réaliser le déploiement automatiquement sans répondre à chaque question interactive. Consultez [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill).

Le script prend en charge Reality, TLS, ws/gRPC/xHTTP ONLY et le nœud relais Nginx Stream. Les modèles de déploiement automatique du Skill AI couvrent actuellement uniquement Reality et TLS ; utilisez idleleo sur le serveur pour ws/gRPC/xHTTP ONLY et le relais.

## Assistant d'exploitation RillML Xray AI

RillML (Rill en abrégé) fournit une exploitation locale et adaptative pour Xray : surveillance en temps réel de la santé de Xray/Nginx, diagnostic automatique des pannes et conseils de remédiation sans API externe. Saisissez `9` dans le menu principal ou exécutez `idleleo --rill-agent`.

| Action | Commande |
|---|---|
| Ouvrir le menu de l'assistant AI | `idleleo --rill-agent` |
| Installer ou réparer le moteur de décision AI | `idleleo --rill-agent-install` |
| Afficher l'état de la décision AI | `idleleo --rill-agent-status` |
| Lancer un diagnostic AI | `idleleo --rill-agent-diagnose` |
| Vérifier le moteur de décision AI | `idleleo --rill-agent-verify` |
| Désactiver prudemment les décisions AI | `idleleo --rill-agent-safe-disable` |
| Désinstaller le moteur Rill AI | `idleleo --rill-agent-uninstall` |

Rill privilégie les conseils de diagnostic par défaut et ne modifie pas le système avant l'activation des modifications automatiques.

## Pour aller plus loin

- Pourquoi la commande s'appelle `idleleo` : [Le vrai visage derrière la brume](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
- Guide d'installation Reality : [Construire un serveur Xray Reality](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
- Risques du protocole Reality : [Risques du protocole Xray Reality](https://hey.run/posts/reality-xie-yi-de-feng-xian)
- Accélération Reality : [Utiliser une « vulnérabilité » du protocole Reality pour accélérer un serveur](https://hey.run/posts/use-reality)
- Communauté : [Telegram](https://t.me/+48VSqv7xIIFmZDZl)
- Documentation officielle : [Documentation Xray](https://xtls.github.io)

## Licence et remerciements

Ce projet est sous licence [GPL-3.0](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE). Merci à JetBrains pour la licence de développement open source non commerciale.

- Basé sur [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey).
- Le script d'accélération TCP est dérivé de [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed).
- Le format des liens de partage suit la [proposition](https://github.com/XTLS/Xray-core/issues/91) de [@DuckSoft](https://github.com/DuckSoft) ; les détails UUIDv5 et REALITY suivent la proposition [XTLS](https://github.com/XTLS/Xray-core/issues/158).
- Merci aux projets amont Xray-core, Nginx, Let's Encrypt et aux autres.

Auteur : Yunshu. Le projet n'offre qu'un support limité ; lisez la documentation et conservez une sauvegarde avant toute opération en production.
