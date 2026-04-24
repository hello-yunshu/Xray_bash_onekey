# Guide de déploiement Docker

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | Français | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | [한국어](/languages/ko/DOCKER.md)

Ce document décrit comment déployer le script d'installation automatique Xray avec Docker.

## Prérequis

* Docker et Docker Compose installés
* Un serveur avec une adresse IP publique
* Pour le protocole Reality : préparez un domaine cible conforme aux exigences de Xray
* Pour la version TLS : préparez un domaine et ajoutez un enregistrement A

## Démarrage rapide

### 1. Cloner le dépôt

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
```

### 2. Construire et démarrer le conteneur

```bash
docker compose up -d
```

### 3. Accéder au menu d'installation interactif

```bash
docker attach xray-onekey
```

Lors de la première exécution, le conteneur lancera automatiquement le script d'installation. Suivez les instructions pour terminer la configuration.

## Modes de fonctionnement

Le conteneur prend en charge les modes suivants :

| Mode | Description | Commande |
|------|-------------|----------|
| `idleleo` (par défaut) | Démarrer les services et accéder au menu de gestion interactif | `docker compose up -d` |
| `start` | Démarrer uniquement les services (mode démon) | Modifier `command: start` dans `docker-compose.yml` |
| `shell` | Démarrer les services et accéder à un shell | `docker exec -it xray-onekey bash` |

## Opérations de gestion

### Accéder au menu de gestion

```bash
docker exec -it xray-onekey idleleo
```

### Vérifier le statut des services

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl status nginx
```

### Redémarrer les services

```bash
docker exec -it xray-onekey systemctl restart xray
docker exec -it xray-onekey systemctl restart nginx
```

### Afficher la configuration client

```bash
docker exec -it xray-onekey cat /etc/idleleo/info/xray_info.inf
```

### Afficher les journaux

```bash
docker exec -it xray-onekey cat /var/log/xray/access.log
docker exec -it xray-onekey cat /var/log/xray/error.log
```

## Utiliser docker run (alternative à docker compose)

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey \
  --network host \
  --cap-add NET_ADMIN \
  -e TZ=Asia/Shanghai \
  -v xray-conf:/etc/idleleo/conf \
  -v xray-cert:/etc/idleleo/cert \
  -v xray-info:/etc/idleleo/info \
  -v xray-logs:/var/log/xray \
  -v acme-data:/root/.acme.sh \
  -it xray-onekey
```

## Persistance des données

Le conteneur utilise des volumes Docker pour persister les données. La configuration est préservée lors de la recréation des conteneurs :

| Volume | Chemin du conteneur | Description |
|--------|-------------------|-------------|
| `xray-conf` | `/etc/idleleo/conf` | Fichiers de configuration Xray et Nginx |
| `xray-cert` | `/etc/idleleo/cert` | Fichiers de certificats SSL |
| `xray-info` | `/etc/idleleo/info` | Informations de connexion et fichiers d'état |
| `xray-logs` | `/var/log/xray` | Fichiers de journaux Xray |
| `acme-data` | `/root/.acme.sh` | Données d'émission de certificats acme.sh |

## Certificats personnalisés

Placez les fichiers `xray.crt` et `xray.key` dans le chemin hôte correspondant au volume de certificats. Utilisez `docker volume inspect xray-cert` pour trouver le chemin hôte.

## Configuration réseau

Le conteneur utilise `network_mode: host` par défaut, ce qui signifie qu'il utilise directement le réseau de l'hôte. Ceci est essentiel pour les services proxy Xray :

* Le mode Reality nécessite de voir la véritable IP du client
* Le mode TLS nécessite une liaison directe aux ports 443/80
* Évite la surcharge de performance liée au transfert NAT supplémentaire

## Remarques importantes

* Le conteneur utilise `fake-systemctl` au lieu de systemd ; les commandes `systemctl` fonctionnent normalement
* La gestion du pare-feu est recommandée au niveau de l'hôte plutôt que dans le conteneur
* Un chien de garde intégré vérifie l'état des services toutes les 30 secondes et redémarre automatiquement en cas de défaillance
* Le renouvellement automatique des certificats fonctionne dans le conteneur (assurez-vous que le port 80 est accessible)
* fail2ban peut être installé via le menu de gestion si nécessaire

## Dépannage

### Le conteneur ne démarre pas

```bash
docker logs xray-onekey
```

### Les services ne fonctionnent pas

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl start xray
```

### Réaccéder au menu d'installation

```bash
docker exec -it xray-onekey idleleo
```

### Réinitialisation complète

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
