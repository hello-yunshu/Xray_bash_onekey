# Xray 관리 스크립트 — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

현재 버전: **3.3.1**

간체 중국어 |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## 기능 특성

* 입력`idleleo`Xray 관리 메뉴를 열어 설치, 서비스, 보안 설정 등을 관리하십시오.
* Qwen-MT-Plus AI를 활용하여 다국어 정밀 번역을 구현합니다.
* Reality 프로토콜을 지원하며, Nginx 프리셋(스크립트 내에서 설치 가능)과 함께 사용하는 것을 권장합니다.
* WebSocket, gRPC, xHTTP 전송을 지원하며, 단일 전송 또는`ws+gRPC+xHTTP`동시에 활성화
* IPv4 / IPv6 듀얼 스택 지원: 설치 시 인터넷 공인망 출구 여부를 자동으로 감지하고, 도메인명 A/AAAA 기준으로 개별 검증을 수행하여 해당 공유 링크와 Clash 구성 파일을 생성합니다.
* fail2ban 내장 보호 기능(스크립트 내에서 설치 가능)
* 내장된 Xray 트래픽 통계, 트래픽 차단, GeoIP/GeoSite 규칙 업데이트 및 정기 업데이트
* 스크립트, Xray, Nginx 및 인증서 업데이트를 지원하며, 주요 업데이트에 대한 백업과 실패 시 롤백 기능을 제공합니다.
* 재설치 및 모드 전환 전에 현재 실행 중인 구성이 자동으로 백업되며, 실패 시 원래 구성으로 복원됩니다.
* 재구성은 세 가지 보안 경로를 제공합니다: 구성 유지 재배포, 표준 템플릿 재구성, 모드 전환
* 채택하다[@DuckSoft](https://github.com/DuckSoft)공유 링크[제안](https://github.com/XTLS/Xray-core/issues/91)(beta)은 Qv2ray, V2rayN, V2rayNG과 호환됩니다.
* 채택하다[XTLS](https://github.com/XTLS/Xray-core/issues/158)제안, 준수[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)표준, 사용자 정의 문자열을 VLESS 및 UUID에 매핑하는 기능을 지원합니다.
* gRPC 프로토콜 지원:[gRPC 프로토콜 사용](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Reality / ws/gRPC/xHTTP 로드 밸런싱을 지원합니다:
  - [Reality 로드 밸런싱 배포](https://hey.run/posts/bushu-reality-balance)
  - [백엔드 로드 밸런싱 구축](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Reality + Nginx 모드는 기본적으로 활성화되어 있으며, SNI Guard: 알 수 없음 SNI, 빈 SNI 및 예외 TLS은 Xray Reality 백엔드로 전달되지 않으며, 기본적으로 격리 정책(ssl_reject_handshake)이 적용됩니다. 고급 사용자는 자체 구축 decoy 사이트로의 롤백 또는 직접 TCP 거부로 전환할 수 있습니다. 이 기능은 능동 탐지와 잘못된 구성으로 인한 노출을 줄이는 데 사용되며, 완벽한 위장은 목표로 하지 않습니다.

## 추가 읽을거리

* `idleleo`이름의 배경 이야기:[안개 너머의 진면목](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality 설치 가이드:[Xray Reality 서버 구축](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality 협약 위험:[Xray Reality 협약의 위험](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality REALITY 서버 가속:[Reality 프로토콜의 "취약점"을 이용하여 서버를 가속화합니다.](https://hey.run/posts/use-reality)

## Telegram 그룹

* 교류 그룹:[클릭하여 가입하기](https://t.me/+48VSqv7xIIFmZDZl)

## 준비 작업

* 외국 서버 한 대, 공인 IP
* Reality 프로토콜 설치: Xray 요건을 충족하는 대상 도메인 이름을 준비해야 합니다.
* TLS 버전 설치: 도메인을 준비하고, 서버의 네트워크 환경에 따라 A 및/또는 A 레코드를 올바르게 구성해야 합니다. 듀얼 스택 환경에서는 A과 A도 동시에 올바르게 구성하는 것을 권장합니다. 스크립트는 IPv4/IPv6 네트워크 기능을 자동으로 감지하며, 듀얼 스택이 사용 가능할 경우 해당 클라이언트 엔트리 포인트를 동시에 생성할 수 있습니다.
* 읽기[Xray 공식 문서](https://xtls.github.io), Reality, TLS, WebSocket, gRPC 및 Xray 관련 개념을 이해합니다.
* **curl이 설치되어 있는지 확인하세요**: CentOS 사용자가 실행합니다`yum install -y curl`Debian/Ubuntu 사용자가 실행함`apt install -y curl`

## 빠른 설치

```bash
bash <(curl -fsSL https://github.com/hello-yunshu/Xray_bash_onekey/releases/latest/download/install.sh)
```

## 설치 모드

| 모드 | 설명 |
|------|------|
| Reality + Nginx | 추천 모드에서는 필요에 따라 ws/gRPC/xHTTP 간단한 프로토콜을 부착하여 로드 밸런싱에 사용할 수 있습니다. |
| Nginx + TLS | ws/gRPC/xHTTP을 지원하며, Let's Encrypt 인증서를 자동으로 신청하고 갱신합니다. |
| ws/gRPC/xHTTP ONLY | TLS 없는 독립형 인바운드 모드로, 주로 백엔드 또는 로드 밸런싱 시나리오에 사용됩니다. |
| 중전 노드 | 독립 서버 역할로, Nginx Stream만을 사용하여 단일 목적지 TCP 전달을 수행하며, Xray은 설치하지 않습니다. |
| Docker | 이미지 내에 Xray, Nginx 및 메인 스크립트가 사전 설치되어 있습니다. |

ws/gRPC/xHTTP 관련 모드를 설치할 때, 선택할 수 있습니다.`ws`, `gRPC`, `xHTTP`또는`ws+gRPC+xHTTP`스크립트는 각각 해당 포트, 경로, 공유 링크 및 QR 코드를 생성합니다. Clash은 현재 xHTTP을 지원하지 않으며, 스크립트는 구성 출력에서 이를 알려줍니다.

## 재구성 설명

기존에 설치된 환경에서 다시 설치를 실행하면 스크립트가 현재 실행 중인 구성 파일을 자동으로 백업하고, 세 가지 재구성 경로를 제공합니다.

| 경로 | 설명 | 제한 |
|------|------|------|
| 구성을 유지한 채로 재배포 | 사용자 정의 routing/outbounds/DNS 및 다중 사용자 구성은 유지하고, 사용자가 선택한 필드(포트, 경로, UUID, Reality 파라미터 등)만 수정합니다. | 구조 변경(ws → gRPC 등)은 지원되지 않습니다. 전송 조합을 변경해야 하는 경우 표준 템플릿을 사용하여 재구성해 주십시오. |
| 표준 템플릿 재구성 | 현재 재사용 가능한 매개변수를 사용하여 표준 템플릿 구성을 생성하며, 사용자 정의 routing/outbounds/DNS는 제거될 수 있습니다. | 사용자 수가 변하지 않아야 한다는 강제 조건은 없습니다. |
| 모드 전환 | 다른 프로토콜 모드(Reality → TLS)로 전환하면, 기본적으로 메인 사용자 UUID/email만 재사용됩니다. | 다른 사용자는 자동으로 이전되지 않으며, 전환 전에 명확히 안내됩니다. |

재구성 과정 중 어느 단계든 실패하면(구성 파일 기록, 서비스 시작, 상태 점검 등) 백업된 원래 구성으로 자동 롤백됩니다. 백업 디렉터리는 고유한 타임스탬프를 사용하므로 연속적인 여러 번의 재구성이 서로 충돌하지 않습니다.

## 자주 사용하는 명령

| 작업 | 명령 |
|------|------|
| 관리 메뉴 열기 | `idleleo` |
| 도움말 보기 | `idleleo --help` |
| Reality 모드를 설치합니다 | `idleleo --install-reality` |
| TLS 모드 설치 | `idleleo --install-tls` |
| ws/gRPC/xHTTP ONLY을 설치합니다 | `idleleo --install-none` |
| 중계 노드 설치 중 | `idleleo --install-relay` |
| 제거 스크립트와 Xray/Nginx | `idleleo --purge` |
| 설치 정보 보기 | `idleleo --show` |
| 업데이트 스크립트 | `idleleo --update` |
| Xray 업데이트 | `idleleo --xray-update` |
| Nginx 업데이트 | `idleleo --nginx-update` |
| Fail2ban 설정 | `idleleo --set-fail2ban` |
| 트래픽 차단 설정 | `idleleo --traffic-blocker` |
| 포트의 실시간 트래픽을 확인합니다 | `idleleo --port-traffic` |

## 업그레이드 안내

### 3.2.9 / 3.2.10 / 3.2.11 → 3.3.x

기존 Shell의 자동 업데이트는 minor을 넘어 적용되지 않습니다.`idleleo --update auto_update`명확히 건너뛰고 유지됩니다.
이전 버전이며, 성공 여부를 자동으로 보고하지 않습니다. 대화형 2단계 업그레이드를 사용하십시오.

```bash
bash /etc/idleleo/install.sh --update          # 交互终端，选择 Y
bash /etc/idleleo/install.sh --xray-update     # 再更新 Xray
```

자동화 환경은 반드시 명시적으로 확인해야 합니다:

```bash
bash /etc/idleleo/install.sh --update --yes                  # 同一 minor
bash /etc/idleleo/install.sh --update --yes --allow-major    # 跨 minor
```

`--yes`동일한 minor의 업데이트만 자동으로 확인합니다; minor을 넘어서는 경우에도 명시적으로 추가해야 합니다.`--allow-major`.
`--allow-major`minor 제한만 해제하며, 자체적으로 Y/N 확인을 대체하지 않습니다(비대화형 시나리오에서는 여전히 필요합니다).
동시에 제공하다`--yes`). 업그레이드 전에 먼저 실행하는 것을 권장합니다.`idleleo --backup`3.3.1 백업 파일 권한 설정
0600입니다.

### 3.3.0 → 3.3.1

관리 메뉴의 “업데이트 마법사 → 업데이트 스크립트”에서 업데이트하거나, 다음을 실행하십시오:

```bash
bash /etc/idleleo/install.sh --update
```

3.3.1 오프라인 제거 후 남은 파일, 백업/로그 권한, Xray 수정, 실패 기록 installer 신원 및
Shell 메타데이터 롤백 방지. 업그레이드는 기존 Xray 구성은 변경하지 않습니다; REALITY`minClientVer`보충은 여전히 따름
3.3.0의 규칙 실행.

3.3.1 재배포 시 버전 번호는 변경되지 않습니다. 이미 구버전 3.3.1을 설치한 노드는 이를 통해`-u`새 설치 프로그램을 자동으로 받음
(동일 버전은 이미 최신으로 간주됩니다);`-x`Xray 코어만 업데이트하고, Shell 스크립트는 업데이트하지 않습니다. 새 패키지가 필요할 때
다시 설치하거나 수동으로 덮어씌워 주세요.`/etc/idleleo/install.sh`.

### 구버전 XTLS 모드

3.3.0부터 이전 버전의 XTLS 모드가 제거되었습니다. 기존 XTLS 서비스는 업그레이드 후에도 계속 실행될 수 있지만, 스크립트를 통해 다시 설치할 수 없습니다.
모드를 전환하세요. 관리를 계속해야 할 경우 먼저 백업하고 제거한 다음, Reality/TLS/ 중계 모드를 다시 배포해 주세요.

### 자동 업데이트

자동 업데이트는 동일한 minor 내에서만 Shell을 자동으로 업그레이드합니다. minor를 넘어서는 경우 위의 두 단계를 수동으로 수행해야 합니다. Xray 및
Nginx의 자동 업데이트는 여전히 API 메타데이터에 따라 수행됩니다. 실패 기록에는 다음이 포함됩니다:`component`, `version`, `installer_ref`, `installer_sha`와`failed_at`필드(각각 컴포넌트, 대상 버전, installer 참조, installer 해시 및 실패 시간을 나타냅니다).

## RillML Xray AI 운영 유지보수 도우미

RillML(약칭 Rill)은 Xray에 현지 맞춤형 지능형 운영 및 유지보수 기능을 제공합니다.

내장된 로컬 AI O&M 어시스턴트가 Xray/Nginx의 상태를 실시간으로 모니터링하고, 자동으로 장애를 진단한 후 처리 권장 사항을 제시하며, 외부 API이 필요하지 않습니다. 메인 메뉴에서 입력하십시오.`9`또는 실행`idleleo --rill-agent`들어가다.

**핵심 역량**

* 모니터링: Xray/Nginx 서비스 및 구성 상태를 실시간으로 관찰
* 진단: 장애의 근본 원인을 규명하고, 신뢰도에 대한 권장 사항(높음/중간/낮음/증거 불충분)을 제시합니다.
* 판단: 고장 유형을 자동으로 판별하고 처리 권고를 제시하며, 설명에는 자동 처리가 허용되는지 또는 단순히 권고만 제공하는지 명확히 표기합니다.
* 모드: 스마트 판단 / 관찰 전용 / 안전 비활성화, 자동 수정이 활성화되기 전에는 시스템을 변경하지 않습니다.

**자주 사용하는 명령어**

| 작업 | 명령 |
|------|------|
| AI 운영 유지보수 도우미 메뉴를 엽니다. | `idleleo --rill-agent` |
| AI 판단 엔진 설치 또는 복구 | `idleleo --rill-agent-install` |
| AI 판단 상태 확인 | `idleleo --rill-agent-status` |
| AI 고장 진단 실행 | `idleleo --rill-agent-diagnose` |
| AI 판단 엔진 검증 | `idleleo --rill-agent-verify` |
| AI 판단 안전 정지 | `idleleo --rill-agent-safe-disable` |
| Rill AI 엔진 제거 | `idleleo --rill-agent-uninstall` |

AI 판단 엔진은 현재 여전히 테스트 단계에 있으므로 진단 제안을 우선적으로 참고하시고, 기본적으로 시스템을 자동으로 수정하지 않습니다.

## Docker 배포

Docker를 사용한 배포를 지원하며, 이미지에는 Xray과 Nginx가 사전 설치되어 있어 컨테이너 내에서 원 스크립트의 모든 기능을 바로 사용할 수 있습니다. 자세한 내용은 참조하십시오.[Docker 배포 가이드](/docker/DOCKER.md).

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill 배포

Trae와 같은 AI 도구를 통해 Xray을 자동으로 배포할 수 있으며, 수동 상호작용이 필요하지 않습니다. 자세한 내용은[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill).

기존 방식에서는 SSH을 서버에 접속하고 설치 스크립트를 실행한 뒤, 대화형 질문에 하나씩 답해야 합니다. 반면 Skill 방식은 AI에게 요구사항을 알려주기만 하면, AI가 비대화형 스크립트를 자동으로 생성해 실행하고, 바로 VLESS 링크를 반환합니다.

**지원 모드**: Reality / TLS / ws ONLY / 중전 노드

**사용 방법**: Skill을 지원하는 AI 도구에서 직접 "서버에 Xray을 구축해줘"라고 말하면, AI가 자동으로 정보를 수집하고 스크립트를 생성한 뒤 배포를 수행하며 연결 정보를 반환합니다.

## 주의사항

* 각 설정의 의미를 잘 모를 경우, 필수 입력 항목을 제외하고는 기본값을 그대로 사용하세요(전체 과정에서 Enter 키만 누르면 됩니다).
* Cloudflare 사용자는 설치가 완료된 후에 CDN을 활성화해 주세요.
* 이 스크립트는 Linux에 대한 기초 지식과 컴퓨터 네트워크에 관한 일반 상식이 필요합니다.
* Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+를 지원하며, 일부 CentOS 템플릿에서는 컴파일 문제가 발생할 수 있으니, 문제가 발생할 경우 운영체제를 변경하는 것을 권장합니다.
* 단일 서버에는 단일 에이전트만 배포하고, 기본 443번 포트를 사용할 것을 권장합니다.
* 사용자 정의 문자열을 UUIDv5에 매핑하려면 클라이언트 측 지원이 필요합니다.
* 깨끗한 환경에서 사용하는 것을 권장합니다; 초보자는 CentOS을 사용하지 마십시오.
* 본 프로그램은 Nginx에 의존하며, 이미 통과되었습니다.[LNMP](https://lnmp.org)Nginx 스크립트를 이미 설치한 사용자는 잠재적인 충돌에 유의하시기 바랍니다.
* xHTTP 공유 링크는 xHTTP을 지원하는 클라이언트에 적용됩니다. Clash 구성 출력에서는 xHTTP이 건너뛰어집니다.
* 사용 가능성을 확인하기 전에는 이 스크립트를 본격적인 운영 환경에 사용하지 마십시오.
* 저자: 윈슈, 제한된 지원만 제공됩니다.

## 감사의 말씀

* 기반으로[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)개발
* TCP 스크립트 참조를 가속화함[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## 인증서 구성

**사용자 정의 인증서**: crt 및 key 파일을 각각 다음과 같이 이름을 변경합니다.`xray.crt`와`xray.key`, 넣기`/etc/idleleo/cert`목록(목록이 없으면 먼저 생성합니다). 인증서의 권한 및 유효 기간에 유의하시기 바랍니다. 사용자 정의 인증서의 유효 기간이 만료되면 직접 갱신해야 합니다.

**자동 인증서**: 스크립트는 Let's Encrypt 인증서(유효기간 3개월)를 자동으로 생성할 수 있으며, 이론적으로 자동 갱신도 지원합니다.

## 클라이언트 설정 보기

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray 소개

* Xray는 뛰어난 오픈소스 네트워크 프록시 도구로, Windows, macOS, Android, iOS, Linux 등 모든 플랫폼을 지원합니다.
* 본 스크립트는 원클릭 완전 구성 스크립트입니다. 모든 과정이 정상적으로 완료된 후, 출력 결과에 따라 클라이언트를 설정하면 바로 사용할 수 있습니다.
* **강력히 권장합니다** 프로그램의 작업 흐름과 원리를 전반적으로 숙지하십시오.

## 서비스 관리

| 작업 | 명령 |
|------|------|
| Xray 시작 | `systemctl start xray` |
| Xray을 중지합니다 | `systemctl stop xray` |
| Nginx 시작 | `systemctl start nginx` |
| Nginx을 중지합니다 | `systemctl stop nginx` |

## 관련 디렉토리

| 내용 | 경로 |
|------|------|
| 홈 디렉토리 | `/etc/idleleo` |
| Xray 구성 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 구성 | `/etc/idleleo/conf/nginx/` |
| 설치 정보 | `/etc/idleleo/conf/install_config.json` |
| 인증서 파일 | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| 로그 디렉터리 | `/etc/idleleo/logs/`, `/var/log/xray/` |
| Nginx 설치 디렉터리 | `/usr/local/nginx` |
| 관리 명령 | `/usr/bin/idleleo` |

프로브 테스트: 새로운 용어와 품질 게이트 링크를 검증합니다.
