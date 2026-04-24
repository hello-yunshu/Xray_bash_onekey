# Docker 배포 가이드

[简体中文](/DOCKER.md) | [English](/languages/en/DOCKER.md) | [Français](/languages/fr/DOCKER.md) | [Русский](/languages/ru/DOCKER.md) | [فارسی](/languages/fa/DOCKER.md) | 한국어

이 문서에서는 Docker를 사용하여 Xray 원클릭 스크립트를 배포하는 방법을 설명합니다.

## 사전 준비

* Docker 및 Docker Compose 설치됨
* 공인 IP를 가진 서버
* Reality 프로토콜: Xray 요구사항을 충족하는 대상 도메인 준비
* TLS 버전: 도메인 준비 및 A 레코드 추가

## 빠른 시작

### 1. 저장소 클론

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
```

### 2. 컨테이너 빌드 및 시작

```bash
docker compose up -d
```

### 3. 대화형 설치 메뉴 진입

```bash
docker attach xray-onekey
```

첫 실행 시 컨테이너가 자동으로 설치 스크립트를 시작합니다. 안내에 따라 설정을 완료하세요.

## 실행 모드

컨테이너는 다음 실행 모드를 지원합니다:

| 모드 | 설명 | 명령어 |
|------|------|--------|
| `idleleo` (기본값) | 서비스 시작 및 대화형 관리 메뉴 진입 | `docker compose up -d` |
| `start` | 서비스만 시작 (데몬 모드) | `docker-compose.yml`에서 `command: start`로 수정 |
| `shell` | 서비스 시작 및 셸 진입 | `docker exec -it xray-onekey bash` |

## 관리 작업

### 관리 메뉴 진입

```bash
docker exec -it xray-onekey idleleo
```

### 서비스 상태 확인

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl status nginx
```

### 서비스 재시작

```bash
docker exec -it xray-onekey systemctl restart xray
docker exec -it xray-onekey systemctl restart nginx
```

### 클라이언트 설정 확인

```bash
docker exec -it xray-onekey cat /etc/idleleo/info/xray_info.inf
```

### 로그 확인

```bash
docker exec -it xray-onekey cat /var/log/xray/access.log
docker exec -it xray-onekey cat /var/log/xray/error.log
```

## docker run 사용 (docker compose 대안)

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

## 데이터 지속성

컨테이너는 Docker 볼륨을 사용하여 데이터를 유지합니다. 컨테이너를 재생성해도 설정이 보존됩니다:

| 볼륨 | 컨테이너 경로 | 설명 |
|------|-------------|------|
| `xray-conf` | `/etc/idleleo/conf` | Xray 및 Nginx 설정 파일 |
| `xray-cert` | `/etc/idleleo/cert` | SSL 인증서 파일 |
| `xray-info` | `/etc/idleleo/info` | 연결 정보 및 상태 파일 |
| `xray-logs` | `/var/log/xray` | Xray 로그 파일 |
| `acme-data` | `/root/.acme.sh` | acme.sh 인증서 발급 데이터 |

## 사용자 정의 인증서

`xray.crt` 및 `xray.key` 파일을 인증서 볼륨에 해당하는 호스트 경로에 배치하세요. `docker volume inspect xray-cert`로 호스트 경로를 확인할 수 있습니다.

## 네트워크 설정

컨테이너는 기본적으로 `network_mode: host`를 사용하여 호스트 네트워크를 직접 사용합니다. 이는 Xray 프록시 서비스에 필수적입니다:

* Reality 모드는 실제 클라이언트 IP를 확인해야 합니다
* TLS 모드는 443/80 포트에 직접 바인딩해야 합니다
* 추가 NAT 전달로 인한 성능 오버헤드를 방지합니다

## 주의사항

* 컨테이너에서는 systemd 대신 `fake-systemctl`을 사용합니다; `systemctl` 명령어가 정상적으로 작동합니다
* 방화벽 관리는 컨테이너 내부가 아닌 호스트 수준에서 권장됩니다
* 내장 와치독이 30초마다 서비스 상태를 확인하고 장애 시 자동으로 재시작합니다
* 자동 인증서 갱신이 컨테이너 내에서 작동합니다 (포트 80에 접근 가능한지 확인)
* 필요한 경우 관리 메뉴를 통해 fail2ban을 설치할 수 있습니다

## 문제 해결

### 컨테이너가 시작되지 않는 경우

```bash
docker logs xray-onekey
```

### 서비스가 실행되지 않는 경우

```bash
docker exec -it xray-onekey systemctl status xray
docker exec -it xray-onekey systemctl start xray
```

### 설치 메뉴 다시 진입

```bash
docker exec -it xray-onekey idleleo
```

### 전체 초기화

```bash
docker compose down
docker volume rm xray-conf xray-cert xray-info xray-logs acme-data
docker compose up -d
```
