# Xray 관리 스크립트

> Debian, Ubuntu, CentOS Stream을 위한 Xray 원스톱 배포 및 관리 도구로, Reality, TLS, ws/gRPC/xHTTP, 중계 노드, Docker를 지원합니다.

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE) [![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)](https://github.com/hello-yunshu/Xray_bash_onekey) [![Shell: Bash](https://img.shields.io/badge/shell-Bash-4EAA25)](https://github.com/hello-yunshu/Xray_bash_onekey)

중국어(간체) | [English](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/en/README.md) | [Français](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fr/README.md) | [Русский](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ru/README.md) | [فارسی](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/fa/README.md) | [한국어](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/i18n/languages/ko/README.md)

## 프로젝트 소개

이 프로젝트는 Bash로 작성된 Xray 배포 및 운영 스크립트입니다. 설치, 인증서, Nginx 프런트엔드, 클라이언트 구성, 서비스 관리, 백업과 복구, 일상 문제 진단을 하나의 메뉴에 모았습니다. 단일 서버 프록시를 빠르게 구축하면서 전체 구성을 수동으로 관리하고 싶지 않은 사용자에게 적합합니다.

스크립트는 구성을 생성하고 서비스를 조정하며, Xray가 실제 프록시를 담당합니다. Reality와 TLS 모드는 Nginx 프런트엔드와 함께 사용할 때 가장 잘 동작합니다. 모든 중요한 쓰기 작업은 구문 검사나 백업을 거치며, 실패하면 가능한 범위에서 롤백하여 실행 중인 서비스가 불완전한 상태로 남지 않도록 합니다.

## 기능 개요

| 기능 | 설명 |
|---|---|
| 설치 모드 | Reality + Nginx, Nginx + TLS, ws/gRPC/xHTTP ONLY, 중계 노드, Docker |
| 전송 프로토콜 | WebSocket, gRPC, xHTTP를 단독 또는 `ws+gRPC+xHTTP` 조합으로 사용 |
| 듀얼 스택 네트워크 | IPv4/IPv6 출구를 감지하고 도메인 A/AAAA 레코드를 별도로 검증하며 대응하는 클라이언트 진입점을 생성 |
| 클라이언트 출력 | 공유 링크, QR 코드, Clash 프로필; Clash는 현재 xHTTP를 지원하지 않음 |
| 보안 관리 | fail2ban, 트래픽 차단, SNI Guard, 방화벽, 인증서 관리 |
| 일상 운영 | 서비스 관리, 구성 변경, 로그 정리, 포트 트래픽 조회, 백업과 복구 |
| 트래픽 통계 | 인바운드별 업로드, 다운로드, 합계 바이트를 읽고 JSON, 초기화, 실시간 갱신 지원 |
| 지능형 도우미 | RillML 로컬 AI 운영 도우미가 모니터링, 진단, 조치 제안 제공 |
| 유지 관리 | 스크립트, Xray, Nginx, 인증서 업데이트와 중요 변경의 백업 및 롤백 |

## 지원 시스템

| 시스템 | 버전 | 비고 |
|---|---|---|
| Debian | 12, 13 | `apt` 사용; CI는 `debian:12-slim`과 `debian:13-slim`을 포함 |
| Ubuntu | 24.04, 26.04 | `apt` 사용; CI는 `ubuntu:24.04`와 `ubuntu:26.04`를 포함 |
| CentOS Stream | 10 | RPM 패키지 관리자 사용; CI는 `quay.io/centos/centos:stream10`을 포함 |
| Rocky / AlmaLinux | 10+ | RPM 계열로 처리하며 주 버전은 10 이상이어야 함 |

스크립트에는 root, systemd, 공인 IP, 정상적인 아웃바운드 네트워크가 필요합니다. 설치 과정에서 `curl`, `jq`, `openssl`, `qrencode`, `nmap` 등의 의존성을 자동으로 보충합니다. Reality/TLS 모드는 서버 네트워크에 맞는 A 및/또는 AAAA 레코드가 있는 도메인도 필요합니다.

> 지원하지 않는 시스템은 설치 전에 거부됩니다. CentOS 템플릿은 차이가 크므로 컴파일이나 의존성 문제가 발생하면 Debian 또는 Ubuntu를 사용하세요.

## 빠른 시작

지원되는 Linux 서버를 준비하고 root로 다음 명령을 실행합니다:

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

설치가 끝나면 `idleleo`를 실행하여 관리 메뉴를 엽니다. `idleleo --install-reality`, `idleleo --install-tls`, `idleleo --install-none`을 직접 실행하여 해당 모드로 진입할 수도 있습니다.

처음 사용할 때는 설치 마법사를 따르고, 잘 모르는 항목은 Enter를 눌러 기본값을 사용하세요. 설치 후 스크립트가 출력하는 공유 링크나 QR 코드로 클라이언트를 구성합니다.

## 설치 모드

| 모드 | 사용 사례 | 핵심 설명 |
|---|---|---|
| Reality + Nginx | 단일 서버에 권장되는 진입점 | 필요하면 로드 밸런싱을 위해 간단한 ws/gRPC/xHTTP 프로토콜을 추가 가능 |
| Nginx + TLS | 표준 TLS 진입점 | Let's Encrypt 인증서를 자동으로 신청하고 갱신 |
| ws/gRPC/xHTTP ONLY | 백엔드 또는 로드 밸런싱 노드 | TLS 없음; 기본적으로 `127.0.0.1`에서만 수신 |
| 중계 노드 | 독립 TCP 전달 | Nginx Stream으로 단일 대상에 전달하며 Xray를 설치하지 않음 |
| Docker | 컨테이너 배포 | 이미지에 Xray, Nginx, 메인 스크립트가 포함됨 |

ws/gRPC/xHTTP 모드를 설치할 때 `ws`, `gRPC`, `xHTTP`, `ws+gRPC+xHTTP` 중 하나를 선택합니다. 스크립트는 전송마다 포트, 경로, 공유 링크, QR 코드를 생성합니다. Clash 프로필은 xHTTP를 건너뛰며 스크립트가 출력에서 알려줍니다.

## 관리 메뉴

`idleleo`를 실행하여 메인 메뉴를 엽니다:

| 옵션 | 기능 |
|---|---|
| `1` | 설치 마법사 |
| `2` | 구성 변경 |
| `3` | 정보 보기 |
| `4` | Xray / TLS 서비스와 인증서 |
| `5` | 업데이트 마법사 |
| `6` | 기타 옵션 (TCP 가속, Fail2ban, 트래픽 통계, 트래픽 차단, 로그, 네트워크 속도) |
| `7` | 백업, 복구, 삭제 |
| `8` | 언어 변경 |
| `9` | Rill Xray AI 운영 도우미 |
| `0` | 종료 |

"기타 옵션 → Xray 트래픽 통계" 항목은 통계 켜기/끄기, 조회, 초기화, 실시간 모니터링의 네 가지 작업을 제공합니다.

## 자주 쓰는 명령

| 작업 | 명령 |
|---|---|
| 관리 메뉴 열기 | `idleleo` |
| 도움말 보기 | `idleleo --help` |
| Reality 모드 설치 | `idleleo --install-reality` |
| TLS 모드 설치 | `idleleo --install-tls` |
| ws/gRPC/xHTTP ONLY 설치 | `idleleo --install-none` |
| 중계 노드 설치 | `idleleo --install-relay` |
| 설치 정보 보기 | `idleleo --show` |
| Xray 접속 정보 보기 | `idleleo --xray-access` |
| Xray 오류 정보 보기 | `idleleo --xray-error` |
| 포트 실시간 트래픽 보기 | `idleleo --port-traffic` |
| 스크립트 업데이트 | `idleleo --update` |
| Xray 업데이트 | `idleleo --xray-update` |
| Nginx 업데이트 | `idleleo --nginx-update` |
| Fail2ban 설정 | `idleleo --set-fail2ban` |
| 트래픽 차단 설정 | `idleleo --traffic-blocker` |
| 스크립트 관리 파일 백업 | `idleleo --backup` |
| 스크립트 관리 파일 복구 | `idleleo --restore` |
| 스크립트와 Xray/Nginx 삭제 | `idleleo --purge` |
| 트래픽 통계 보기 | `idleleo --stats` / `idleleo --stats --json` |
| 트래픽 통계 초기화 | `idleleo --stats-reset` (확인 후 실행, `--yes`는 확인 생략) |
| 트래픽 통계 실시간 모니터링 | `idleleo --stats-watch` [초] |

## Xray 트래픽 통계

통계를 켜면 통계 API는 기본적으로 `127.0.0.1:10085`에서만 수신합니다. 조회는 독립 스크립트 `/etc/idleleo/scripts/xray_stats.sh`가 수행하며 권한은 `0600 root:root`입니다. 메인 스크립트는 진입점, 다운로드, SHA256 검증, 위임만 담당하고 조회 로직을 중복 구현하지 않습니다.

```bash
idleleo --stats                  # 표: 인바운드별 업로드, 다운로드, 합계
idleleo --stats --json           # 기계 판독 가능한 JSON
idleleo --stats-reset            # 대화형 확인 후 카운터 초기화
idleleo --stats-reset --yes      # 자동화 확인
idleleo --stats-watch 5          # 5초마다 갱신, Ctrl-C로 종료
```

통계 스크립트가 없으면 메인 스크립트가 현재 Release에서 `xray_stats.sh`를 다운로드하고 `release-manifest.json`의 `statsScriptSha256`으로 검증합니다. 검증 실패는 조회에만 영향을 주며 통계 스위치에는 영향을 주지 않습니다. 통계가 켜져 있지만 `api.listen`이 없으면 첫 `--stats` 실행 시 이를 추가하고 Xray를 재시작할지 명시적으로 묻습니다. 거부하면 구성은 변경되지 않습니다.

### 종료 코드

| 종료 코드 | 의미 |
|---|---|
| `0` | 조회 성공; 카운터가 0이어도 성공 |
| `1` | 사용자가 초기화를 취소함 |
| `2` | 전제 조건 누락: 통계 꺼짐, `api.listen` 없음, Xray 미실행, API 접근 불가, 스크립트 없음 또는 검증 실패 |
| `3` | API 호출 또는 JSON 파싱 실패 |
| `4` | 잘못된 인수 |
| `5` | root가 아니거나 권한 부족 |
| `130` | Ctrl-C로 모니터링 중단 |

실패 시 거짓 0을 출력하지 않습니다: 통계가 꺼져 있거나 API에 접근할 수 없으면 `2`, 잘못된 JSON은 `3`, root가 아니면 `5`를 반환합니다.

### 보안 경계

> 통계 API는 루프백 주소에만 바인딩되지만 인증이 없습니다. 다른 로컬 사용자가 이론적으로 포트에 접근하여 카운터를 읽거나 초기화할 수 있습니다. 단일 사용자 VPS에서 사용하고 `10085`를 공용 인터넷에 노출하지 마세요. `--stats-reset`은 항상 명시적 확인을 요구합니다.

Xray StatsService는 인바운드 업로드/다운로드와 Uptime 카운터만 제공하며 **활성 연결 수는 제공하지 않습니다**. 연결 수가 필요하면 시스템 도구나 별도 관측 솔루션을 사용하고 `--stats`가 연결 수를 알려주리라 기대하지 마세요.

## 백업과 복구

`idleleo --backup`은 스크립트가 관리하는 파일만 백업합니다: `/etc/idleleo`, `/usr/local/nginx`, Xray 바이너리, systemd unit, root crontab, ACME 상태. 전체 호스트 백업이 아니며 다른 경로에 둔 데이터를 자동으로 포함하지 않습니다.

`idleleo --restore`는 타임스탬프가 가장 최신인 백업을 선택합니다. 체크섬 매니페스트가 있는 백업은 아카이브 안의 각 파일 SHA256을 검증하고 백업에 없는 스크립트 관리 구성을 제거합니다. 매니페스트가 없는 오래된 백업은 구조 검증만 수행하고 모드 간 정리를 건너뜁니다. 사용자 정의 파일은 유지되며 서비스는 자동으로 시작되지 않습니다. 모드 간 복구 후에는 남은 구성을 확인하고 필요에 따라 서비스를 재시작하세요. 오래된 백업에 `/usr/local/share/xray` 심볼릭 링크가 없으면 복구 시 링크를 만들거나 이전 GeoData 디렉터리를 `/etc/idleleo/share/xray`에 병합한 뒤 실제 `xray run -test`로 검증합니다. 자동 복구에 실패하면 롤백되므로 오래된 백업도 재설치 없이 새 호스트로 복구할 수 있습니다.

백업 아카이브에는 인증서, 개인 키, 클라이언트 구성이 포함될 수 있습니다. 민감한 파일로 취급하고 공개 위치에 업로드하지 마세요.

## 업그레이드와 업데이트

관리 메뉴의 "업데이트 마법사 → 스크립트 업데이트"에서 업데이트하거나 다음을 실행합니다:

```bash
idleleo --update                  # 대화형 확인
idleleo --update --yes            # 비대화형, 같은 릴리스 계열에서 자동 확인
idleleo --update --yes --allow-major  # 계열 간 업데이트; 제한을 명시적으로 해제
```

`--yes`는 같은 릴리스 계열의 업데이트만 자동 확인하며, 계열 간 업데이트에는 `--allow-major`도 필요합니다. `--allow-major`는 계열 제한만 해제하고 확인을 대체하지 않으므로 비대화형 환경에서는 여전히 `--yes`가 필요합니다. 스크립트 업데이트는 `/etc/idleleo/install.sh`를 통째로 교체하고 새 스크립트에 맞춰 Release 주소를 다시 계산하며 보조 자산을 동기화합니다.

`--xray-update`는 Xray 코어만, `--nginx-update`는 Nginx만 업데이트하며 어느 것도 스크립트 자체를 업그레이드하지 않습니다. 스크립트 자동 업데이트는 같은 릴리스 계열에서만 이루어지며 Xray와 Nginx 자동 업데이트는 계속 API 메타데이터를 따릅니다. 업그레이드 전에 `idleleo --backup`을 실행하세요.

레거시 XTLS 모드는 새 설치나 재설치 진입점을 제공하지 않습니다. 기존 XTLS 서비스는 계속 실행할 수 있지만 스크립트로 재설치하거나 모드를 전환할 수 없습니다. 계속 관리하려면 먼저 백업하고 삭제한 뒤 Reality, TLS 또는 중계 모드를 다시 배포하세요.

## 재구성

이미 설치된 시스템에서 설치 프로그램을 다시 실행하면 현재 실행 구성을 자동으로 백업하고 세 가지 경로를 제공합니다:

| 경로 | 설명 | 제한 |
|---|---|---|
| 구성 유지 후 재배포 | 사용자 지정 routing, outbounds, DNS, 다중 사용자 구성을 유지하고 선택한 필드만 변경 | ws에서 gRPC로 변경하는 등 전송 구조 변경은 지원하지 않음 |
| 표준 템플릿으로 재구성 | 재사용 가능한 매개변수로 표준 템플릿 구성 생성 | 사용자 지정 routing, outbounds, DNS가 제거될 수 있음 |
| 모드 전환 | Reality에서 TLS로 등 다른 프로토콜 모드로 전환 | 기본적으로 주 사용자의 UUID/email만 재사용하며 다른 사용자는 이전되지 않음 |

어느 단계라도 실패하면(구성 쓰기, 서비스 시작, 상태 확인 등) 스크립트는 백업된 원래 구성으로 롤백합니다. 백업 디렉터리는 고유 타임스탬프를 사용하여 연속 재구성이 충돌하지 않습니다.

## Go 관리자 마이그레이션(실험)

> 근거 수준: 컨테이너 수준 `CONTAINER_VERIFIED`(digest가 고정된 Ubuntu 24.04와 실제 systemd/Xray/nginx), **"실제 VPS에서 검증됨"은 아님**. 실제 ACME 발급/갱신은 이번 범위에서 제외됩니다.

- **3.3.5는 Go를 활성화하지 않으며 마이그레이션을 자동으로 제안하지 않습니다**: 새 설치, `-u`, `auto_update`, 전체 재설치, 메뉴 모두 Go를 탐지·다운로드·언급하지 않으며, 일반 사용자는 어떤 마이그레이션 진입점도 볼 수 없습니다. 마이그레이션 코드는 이후 버전을 위해 남겨진 것이고, 관리자가 검증할 때 내부 매개변수 `--internal-bridge-offer`로만 도달합니다.
- **마이그레이션 절차**: 후보 바이너리 SHA256 + ELF 검증 → 읽기 전용 감사 및 전체 변경 요약 → 스냅샷/journal → `xray -test` / `nginx -t` 사전 검증 → `/usr/bin/idleleo` 원자적 전환 → 프로젝트 cron 4개 정확히 제거 → `idleleo-schedule.timer` 설치.
- **보존 항목**: `/etc/idleleo` 구성, 인증서와 개인 키, 사용자, 사용자 정의 cron, 사용자 정의 nginx 조각.
- **복구**: 실패한 단계는 `/opt/idleleo/recovery/idleleo-recover`로 복원되며, `COMMITTED` 이후에는 암시적 역마이그레이션을 하지 않습니다.
- **예약 작업**: `idleleo schedule status`로 조회하고 `install` / `remove` / `run`으로 관리합니다. GeoData 새로고침과 통계 수집은 네이티브(systemd timer)로 구현되었으며, 자동 업데이트는 Go 릴리스 채널을 사용하고 **명시적 `idleleo update configure --manifest-url URL`이 필요합니다**; 미설정 시 매 주기 `degraded`를 기록합니다(출처를 추측하지 않고 조용히 실패하지 않음). 인증서 갱신은 여전히 ACME가 없으며 외부 갱신 후 지문 계약과 만료 경고만 제공합니다.
- **Phase 04 명령**: `idleleo update status|check|apply|configure`, `idleleo stats [--json]`, `idleleo service status|start|stop|restart|reload|logs`, `idleleo rill status`. 서비스 명령은 자체 unit만 허용하며 `stats`는 읽기 전용이고 watch/reset은 지원하지 않습니다.
- **인증서 계약**: 인증서 DER 지문 기준선을 기록하고 지문이 바뀔 때만 `restart xray` / `reload nginx`를 수행하며, 바뀌지 않으면 재시작하지 않습니다. 모든 사용자가 읽을 수 있는 개인 키는 reload를 거부하며, 만료 또는 30일 미만에서 변화가 없으면 `degraded`를 기록합니다. **실제 ACME 발급/갱신/정리는 구현되지 않았습니다.**
- **사용자 정의 콘텐츠**: 감사에서 나열된 미지의 Xray 최상위 키와 사용자 정의 nginx 조각은 먼저 수동 확인해야 하며, 그렇지 않으면 `prepare`가 exit 6으로 거부하고 조용히 덮어쓰지 않습니다.

## 문제 해결

| 증상 | 먼저 확인 | 제안 |
|---|---|---|
| 설치 거부 | `/etc/os-release`와 지원 시스템 매트릭스 | 지원되는 시스템 버전으로 업그레이드하거나 Debian/Ubuntu 사용 |
| Xray 미실행 | `systemctl status xray`, `idleleo --xray-error` | `journalctl -u xray`, 구성, 포트 사용 확인 |
| 구성 구문 오류 | `xray run -test -config /etc/idleleo/conf/xray/config.json` | 출력에 따라 수정하거나 `idleleo --restore`로 롤백 |
| 포트 사용 중 | `ss -ltnp` | 포트를 확보하거나 메뉴에서 수신 포트 변경 |
| 인증서 문제 | `idleleo --cert-status` | DNS, 80/443 포트, ACME 상태를 확인한 뒤 `idleleo --cert-update` 실행 |
| 기존 Nginx와 충돌 | `/usr/local/nginx/sbin/nginx -V`, `systemctl status nginx` | LNMP 등으로 설치한 Nginx와 혼용하지 말고 먼저 충돌을 정리 |
| 통계가 `2` 반환 | 통계 스위치, Xray 상태, `127.0.0.1:10085` | 통계를 켜고 Xray를 시작하거나 `api.listen` 확인 |
| 통계가 `3` 반환 | API 응답과 JSON 구조 | Xray 로그와 구성을 확인하고 StatsService 사용 가능 여부 확인 |
| 통계가 `5` 반환 | 현재 사용자 | root로 실행하거나 파일 권한 확인 |
| Clash에 노드 없음 | 프로토콜 유형 | Clash는 xHTTP를 지원하지 않으므로 지원 클라이언트 사용 |

로그와 진단: `/etc/idleleo/logs/`, `/var/log/xray/`, `idleleo --show`, `idleleo --xray-access`, `idleleo --xray-error`.

## 자주 묻는 질문

**통계에서 활성 연결 수를 볼 수 있나요?** 아니요. StatsService는 인바운드 업로드/다운로드와 Uptime 카운터만 제공하며 연결 수는 제공하지 않습니다.

**Cloudflare 사용자는 언제 CDN을 켜야 하나요?** 설치, 인증서, 직접 연결 검증이 끝난 뒤 CDN을 켜세요. 그렇지 않으면 CDN 프록시가 인증서 발급을 방해할 수 있습니다.

**IPv4와 IPv6를 동시에 사용할 수 있나요?** 예. 스크립트는 공인 출구 기능을 감지하고 도메인 A/AAAA 레코드를 별도로 검증합니다. 듀얼 스택 환경에서는 A와 AAAA 레코드를 모두 올바르게 설정하세요.

**포트, UUID, 전송 방식을 어떻게 변경하나요?** 메뉴의 "구성 변경"을 열거나 설치 마법사를 다시 실행하여 재구성 경로를 선택하세요. 전송 구조를 변경할 때는 표준 템플릿 재구성을 사용하세요.

**어떻게 삭제하나요?** `idleleo --purge`를 실행합니다. 삭제 전에 `idleleo --backup`을 실행하고 구성과 인증서를 보관할지 결정하세요.

**사용자 지정 문자열을 UUID에 매핑하려면 무엇이 필요한가요?** 스크립트는 UUIDv5 매핑을 사용하며 클라이언트 지원이 필요합니다. 클라이언트가 지원하지 않으면 표준 UUID를 사용하세요.

**운영 환경에서 바로 사용할 수 있나요?** 먼저 테스트 환경에서 연결, 인증서 갱신, 백업/복구, 업그레이드 경로를 검증한 뒤 운영 환경에서 사용하세요.

## 보안 안내

- 통계 API는 `127.0.0.1`에만 바인딩되며 인증이 없습니다. `10085`를 공용 인터넷에 노출하지 말고 신뢰할 수 없는 로컬 사용자가 접근하지 않도록 하세요.
- Reality + Nginx 모드는 기본으로 SNI Guard를 켭니다. 알 수 없는 SNI, 빈 SNI, 비정상 TLS는 Xray Reality 백엔드에 도달하지 않으며 기본적으로 `ssl_reject_handshake` 격리를 사용합니다.
- Fail2ban, 방화벽, 트래픽 차단은 선택적 강화 기능입니다. 켜기 전에 자체 관리 접근을 차단하지 않는지 확인하세요.
- 백업 아카이브, 인증서, 클라이언트 구성에는 민감한 정보가 있습니다. 파일 권한을 제한하고 공개 공유를 피하세요.
- 스크립트에는 root가 필요합니다. 가용성을 검증하기 전에는 운영 환경에서 사용하지 마세요.

## 디렉터리와 서비스

| 항목 | 경로 |
|---|---|
| 메인 디렉터리 | `/etc/idleleo` |
| Xray 구성 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 구성 | `/etc/idleleo/conf/nginx/` |
| 스크립트 상태 구성 | `/etc/idleleo/conf/install_config.json` |
| 인증서 파일 | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| 로그 디렉터리 | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Nginx 설치 디렉터리 | `/usr/local/nginx` |
| 관리 명령 | `/usr/bin/idleleo` |
| 설치 정보 텍스트 | `/etc/idleleo/info/xray_info.inf` |

| 작업 | 명령 |
|---|---|
| Xray 시작 | `systemctl start xray` |
| Xray 중지 | `systemctl stop xray` |
| Nginx 시작 | `systemctl start nginx` |
| Nginx 중지 | `systemctl stop nginx` |

## Docker와 AI Skill

Docker 이미지에는 Xray, Nginx, 메인 스크립트가 포함되며 컨테이너 안에서 원래 스크립트 기능을 사용할 수 있습니다. [Docker 배포 가이드](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/docker/DOCKER.md)를 참고하세요.

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

AI Skill은 Skills를 지원하는 AI 도구가 각 대화형 질문에 답하지 않고 배포를 자동으로 완료하도록 합니다. [Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)을 참고하세요.

스크립트는 Reality, TLS, ws/gRPC/xHTTP ONLY, Nginx Stream 중계 노드를 지원합니다. AI Skill 자동 배포 템플릿은 현재 Reality와 TLS만 지원하므로, ws/gRPC/xHTTP ONLY와 중계 노드는 서버에서 idleleo로 설정하세요.

## RillML Xray AI 운영 도우미

RillML(줄여서 Rill)은 Xray에 로컬 적응형 지능 운영 기능을 제공합니다. 외부 API 없이 Xray/Nginx 상태를 실시간 모니터링하고, 장애를 자동 진단하며, 조치 제안을 제공합니다. 메인 메뉴에서 `9`를 입력하거나 `idleleo --rill-agent`를 실행하세요.

| 작업 | 명령 |
|---|---|
| AI 운영 도우미 메뉴 열기 | `idleleo --rill-agent` |
| AI 판단 엔진 설치 또는 복구 | `idleleo --rill-agent-install` |
| AI 판단 상태 보기 | `idleleo --rill-agent-status` |
| AI 장애 진단 실행 | `idleleo --rill-agent-diagnose` |
| AI 판단 엔진 검증 | `idleleo --rill-agent-verify` |
| AI 판단 안전 비활성화 | `idleleo --rill-agent-safe-disable` |
| Rill AI 엔진 삭제 | `idleleo --rill-agent-uninstall` |

Rill은 기본적으로 진단 제안에 집중하며 자동 변경이 켜지기 전에는 시스템을 변경하지 않습니다.

## 더 읽을거리

- 명령 이름이 `idleleo`인 이유: [안개 뒤의 진실](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
- Reality 설치 가이드: [Xray Reality 서버 구축](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
- Reality 프로토콜 위험: [Xray Reality 프로토콜의 위험](https://hey.run/posts/reality-xie-yi-de-feng-xian)
- Reality 가속: [Reality 프로토콜의 "취약점"을 이용한 서버 가속](https://hey.run/posts/use-reality)
- 커뮤니티: [Telegram](https://t.me/+48VSqv7xIIFmZDZl)
- 공식 문서: [Xray 문서](https://xtls.github.io)

## 라이선스와 감사의 말

이 프로젝트는 [GPL-3.0](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/LICENSE) 라이선스를 따릅니다. 비상업적 오픈 소스 개발 라이선스를 제공한 JetBrains에 감사드립니다.

- [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)를 기반으로 개발했습니다.
- TCP 가속 스크립트는 [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)에서 인용했습니다.
- 공유 링크 형식은 [@DuckSoft](https://github.com/DuckSoft)의 [제안](https://github.com/XTLS/Xray-core/issues/91)을 따르며, UUIDv5와 REALITY 관련 내용은 [XTLS](https://github.com/XTLS/Xray-core/issues/158) 제안을 따릅니다.
- Xray-core, Nginx, Let's Encrypt 등 업스트림 프로젝트에 감사드립니다.

작성자: Yunshu. 프로젝트는 제한적인 지원만 제공합니다. 운영 환경에서 작업하기 전에 문서를 읽고 백업을 보관하세요.
