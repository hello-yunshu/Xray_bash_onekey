# Guide de déploiement Docker

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | Français | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

Ce guide décrit comment exécuter le script d'installation automatique Xray avec Docker. L'image intègre Xray et Nginx préinstallés, et toutes les fonctionnalités du script original sont disponibles dans le conteneur.

## Démarrage rapide

### 1. Cloner et construire

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
```

### 2. Accéder au menu d'installation interactif

```bash
docker attach xray-onekey
```

Lors de la première exécution, le script d'installation se lance automatiquement. Suivez les instructions pour terminer la configuration. Après avoir quitté le menu, le conteneur passe automatiquement en mode démon.

### 3. Gestion ultérieure

```bash
docker exec -it xray-onekey idleleo
```

## Modes de fonctionnement

| Mode | Description | Commande |
|------|-------------|----------|
| `idleleo` (par défaut) | Démarrer les services et accéder au menu de gestion | `docker compose up -d` + `docker attach xray-onekey` |
| `start` | Démarrer uniquement les services (mode démon) | Modifier `command: start` dans `docker-compose.yml` |
| `shell` | Démarrer les services et accéder à un shell | `docker exec -it xray-onekey bash` |

## Opérations de gestion

Toutes les commandes du script original sont disponibles :

```bash
docker exec -it xray-onekey idleleo          # Menu de gestion
docker exec -it xray-onekey idleleo -s        # Afficher les informations
docker exec -it xray-onekey idleleo -x        # Mettre à jour Xray
docker exec -it xray-onekey idleleo -n        # Mettre à jour Nginx
docker exec -it xray-onekey idleleo -h        # Afficher l'aide
```

## Utilisation de docker run

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey   --network host   --cap-add NET_ADMIN   -e TZ=Asia/Shanghai   -v xray-conf:/etc/idleleo/conf   -v xray-cert:/etc/idleleo/cert   -v xray-info:/etc/idleleo/info   -v xray-logs:/var/log/xray   -v acme-data:/root/.acme.sh   -it xray-onekey
```

## Persistance des données

| Volume | Chemin du conteneur | Description |
|--------|-------------------|-------------|
| `xray-conf` | `/etc/idleleo/conf` | Fichiers de configuration Xray et Nginx |
| `xray-cert` | `/etc/idleleo/cert` | Fichiers de certificats SSL |
| `xray-info` | `/etc/idleleo/info` | Informations de connexion et fichiers d'état |
| `xray-logs` | `/var/log/xray` | Fichiers de journaux Xray |
| `acme-data` | `/root/.acme.sh` | Données d'émission de certificats acme.sh |

## Configuration réseau

Le conteneur utilise `network_mode: host`, utilisant directement le réseau de l'hôte :

* Le mode Reality nécessite de voir la véritable IP du client
* Le mode TLS nécessite une liaison directe aux ports 443/80
* Évite la surcharge de performance liée au transfert NAT supplémentaire

## Remarques importantes

* Le conteneur utilise `fake-systemctl` au lieu de systemd ; les commandes `systemctl` fonctionnent normalement
* Un chien de garde intégré vérifie l'état des services toutes les 30 secondes et redémarre automatiquement en cas de défaillance
* Après avoir quitté le menu de gestion, le conteneur passe automatiquement en mode démon — les services continuent de fonctionner
* La gestion du pare-feu est recommandée au niveau de l'hôte
* Le renouvellement automatique des certificats fonctionne dans le conteneur (assurez-vous que le port 80 est accessible)

## Dépannage

```bash
docker logs xray-onekey                    # Afficher les journaux du conteneur
docker exec -it xray-onekey bash           # Entrer dans le conteneur
docker exec -it xray-onekey idleleo -s     # Afficher les informations d'installation
```

### Réinitialisation complète

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
