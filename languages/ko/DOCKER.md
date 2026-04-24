# Docker 배포 가이드

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | 한국어

이 가이드에서는 Docker를 사용하여 Xray 원클릭 스크립트를 실행하는 방법을 설명합니다. 이미지에 Xray와 Nginx가 사전 설치되어 있으며, 컨테이너 내에서 원본 스크립트의 모든 기능을 사용할 수 있습니다.

## 빠른 시작

### 1. 클론 및 빌드

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
```

### 2. 대화형 설치 메뉴 진입

```bash
docker attach xray-onekey
```

첫 실행 시 설치 스크립트가 자동으로 시작됩니다. 안내에 따라 설정을 완료하세요. 메뉴를 종료하면 컨테이너가 자동으로 데몬 모드로 전환됩니다.

### 3. 이후 관리

```bash
docker exec -it xray-onekey idleleo
```

## 실행 모드

| 모드 | 설명 | 명령어 |
|------|------|--------|
| `idleleo` (기본값) | 서비스 시작 및 관리 메뉴 진입 | `docker compose up -d` + `docker attach xray-onekey` |
| `start` | 서비스만 시작 (데몬 모드) | `docker-compose.yml`에서 `command: start`로 수정 |
| `shell` | 서비스 시작 및 셸 진입 | `docker exec -it xray-onekey bash` |

## 관리 작업

원본 스크립트의 모든 명령을 사용할 수 있습니다:

```bash
docker exec -it xray-onekey idleleo          # 관리 메뉴
docker exec -it xray-onekey idleleo -s        # 설치 정보 확인
docker exec -it xray-onekey idleleo -x        # Xray 업데이트
docker exec -it xray-onekey idleleo -n        # Nginx 업데이트
docker exec -it xray-onekey idleleo -h        # 도움말
```

## docker run 사용

```bash
docker build -t xray-onekey .

docker run -d --name xray-onekey   --network host   --cap-add NET_ADMIN   -e TZ=Asia/Shanghai   -v xray-conf:/etc/idleleo/conf   -v xray-cert:/etc/idleleo/cert   -v xray-info:/etc/idleleo/info   -v xray-logs:/var/log/xray   -v acme-data:/root/.acme.sh   -it xray-onekey
```

## 데이터 지속성

| 볼륨 | 컨테이너 경로 | 설명 |
|------|-------------|------|
| `xray-conf` | `/etc/idleleo/conf` | Xray 및 Nginx 설정 파일 |
| `xray-cert` | `/etc/idleleo/cert` | SSL 인증서 파일 |
| `xray-info` | `/etc/idleleo/info` | 연결 정보 및 상태 파일 |
| `xray-logs` | `/var/log/xray` | Xray 로그 파일 |
| `acme-data` | `/root/.acme.sh` | acme.sh 인증서 발급 데이터 |

## 네트워크 설정

컨테이너는 `network_mode: host`를 사용하여 호스트 네트워크를 직접 사용합니다:

* Reality 모드는 실제 클라이언트 IP를 확인해야 합니다
* TLS 모드는 443/80 포트에 직접 바인딩해야 합니다
* 추가 NAT 전달로 인한 성능 오버헤드를 방지합니다

## 주의사항

* 컨테이너에서는 systemd 대신 `fake-systemctl`을 사용합니다; `systemctl` 명령어가 정상적으로 작동합니다
* 내장 와치독이 30초마다 서비스 상태를 확인하고 장애 시 자동으로 재시작합니다
* 관리 메뉴를 종료하면 컨테이너가 자동으로 데몬 모드로 전환됩니다 — 서비스가 계속 실행됩니다
* 방화벽 관리는 호스트 수준에서 권장됩니다
* 자동 인증서 갱신이 컨테이너 내에서 작동합니다 (포트 80에 접근 가능한지 확인)

## 문제 해결

```bash
docker logs xray-onekey                    # 컨테이너 로그 확인
docker exec -it xray-onekey bash           # 컨테이너 진입
docker exec -it xray-onekey idleleo -s     # 설치 정보 확인
```

### 전체 초기화

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
