# Xray 관리 스크립트 — Reality / VLESS WebSocket/gRPC/xHTTP+TLS + Nginx

중국어 간체 |[English](/i18n/languages/en/README.md) | [Français](/i18n/languages/fr/README.md) | [Русский](/i18n/languages/ru/README.md) | [فارسی](/i18n/languages/fa/README.md) | [한국어](/i18n/languages/ko/README.md)

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> Thanks for non-commercial open source development authorization by JetBrains

## 특징

* 입력하다`idleleo`Xray 관리 메뉴를 열어 설치, 서비스, 보안 설정 등을 관리하세요.
* 여러 언어로 정확한 번역을 얻으려면 Qwen-MT-Plus AI을 사용하세요.
* Reality 프로토콜을 지원합니다. Nginx 접두사 사용을 권장합니다(스크립트에 설치 가능).
* WebSocket, gRPC, xHTTP 전송을 지원하며 단일 전송 또는`ws+gRPC+xHTTP`둘 다 활성화
* IPv4 / IPv6 듀얼 스택 지원: 설치 중 공용 네트워크 내보내기 기능을 자동으로 감지하고 도메인 이름 A/AAAA을 기반으로 독립적인 확인을 기록하며 해당 공유 링크 및 Clash 구성을 생성할 수 있습니다.
* 내장된 fail2ban 보호(스크립트 내에 설치 가능)
* 내장된 Xray 트래픽 통계, 트래픽 차단, GeoIP/GeoSite 규칙 업데이트 및 정기 업데이트
* 스크립트, Xray, Nginx 및 인증서 업데이트를 지원하고 중요 업데이트에 대한 백업 및 오류 롤백을 제공합니다.
* 현재 실행 중인 구성은 재설치 및 모드 전환 전에 자동으로 백업되며, 장애 발생 시 원래 구성이 복원됩니다.
* 재구성은 구성 보존 재배포, 표준 템플릿 재구성 및 모드 전환이라는 세 가지 안전한 경로를 제공합니다.
* 사용[@DuckSoft](https://github.com/DuckSoft)님의 공유 링크[提案](https://github.com/XTLS/Xray-core/issues/91)(beta), Qv2ray, V2rayN, V2rayNG과 호환 가능
* 사용[XTLS](https://github.com/XTLS/Xray-core/issues/158)제안, 따르다[UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3)표준, VLESS UUID에 대한 사용자 정의 문자열 매핑 지원
* gRPC 프로토콜을 지원합니다:[使用 gRPC 协议](https://hey.run/posts/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Reality / ws/gRPC/xHTTP 로드 밸런싱을 지원합니다.
  - [部署 Reality 负载均衡](https://hey.run/posts/bushu-reality-balance)
  - [搭建后端负载均衡](https://hey.run/posts/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)
* Reality + Nginx 모드는 기본적으로 활성화되어 있습니다. SNI Guard: 알 수 없는 SNI, 비어 있는 SNI 및 예외 TLS은 Xray Reality 백엔드를 입력하지 않습니다. 기본적으로 격리 전략(ssl_reject_handshake)이 채택됩니다. 고급 사용자는 자체 구축된 decoy 사이트 대체 또는 직접 TCP 거부로 전환할 수 있습니다. 이 기능은 능동감지 및 오설정 노출을 줄이기 위해 사용되며, 완벽한 위장을 추구하지는 않습니다.

## 추가 읽기

* `idleleo`뒷이야기 명명:[迷雾后的真容](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%E8%BF%B7%E9%9B%9C%E5%90%8E%E7%9A%84%E7%9C%9F%E5%AE%B9)
* Reality 설치 안내서:[搭建 Xray Reality 服务器](https://hey.run/posts/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality 프로토콜 위험:[Xray Reality 协议的风险](https://hey.run/posts/reality-xie-yi-de-feng-xian)
* Reality 가속 서버:[利用 Reality 协议"漏洞"加速服务器](https://hey.run/posts/use-reality)

## Telegram 그룹

* 커뮤니케이션 그룹:[点击加入](https://t.me/+48VSqv7xIIFmZDZl)

## 준비

* 공용 네트워크가 있는 해외 서버 IP
* Reality 프로토콜 설치: Xray의 요구 사항을 충족하는 대상 도메인 이름을 준비해야 합니다.
* TLS 버전 설치: 서버의 사용 가능한 네트워크에 따라 도메인 이름을 준비하고 A 및/또는 AAAA 레코드를 올바르게 구성해야 합니다. 이중 스택 환경의 경우 올바른 A 및 AAAA을 동시에 구성하는 것이 좋습니다. 이 스크립트는 IPv4/IPv6 네트워크 기능의 자동 감지를 지원합니다. 듀얼 스택을 사용할 수 있는 경우 해당 클라이언트 항목이 동시에 생성될 수 있습니다.
* 읽다[Xray 官方文档](https://xtls.github.io), Reality, TLS, WebSocket, gRPC 및 Xray 관련 개념을 이해합니다.
* **curl이 설치되어 있는지 확인: CentOS 사용자 실행`yum install -y curl`;Debian/Ubuntu 사용자 실행`apt install -y curl`

## 빠른 설치

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## 설치 모드

| 모델 | 설명하다 |
|------|------|
| Reality + Nginx | 권장 모드, 로드 밸런싱에 필요에 따라 ws/gRPC/xHTTP 간단한 프로토콜을 연결할 수 있습니다. |
| Nginx + TLS | ws/gRPC/xHTTP 지원, Let's Encrypt 인증서 자동 신청 및 갱신 |
| ws/gRPC/xHTTP ONLY | TLS이 없는 독립 인바운드 모드(주로 백엔드 또는 로드 밸런싱 시나리오에 사용됨) |
| XTLS ONLY | 트래픽 전송과 같은 특정 시나리오에서만 사용됩니다. |
| Docker | Xray, Nginx 및 기본 스크립트가 이미지에 사전 설치되어 있습니다. |

ws/gRPC/xHTTP 관련 모드 설치 시 선택 사항`ws`、`gRPC`、`xHTTP`또는`ws+gRPC+xHTTP`. 스크립트는 각각 해당 포트, 경로, 공유 링크 및 QR 코드를 생성합니다. Clash은(는) 현재 xHTTP을 지원하지 않으며 스크립트는 구성 출력에 메시지를 표시합니다.

## 재구성 지침

설치된 환경이 다시 설치되면 스크립트는 현재 실행 중인 구성을 자동으로 백업하고 세 가지 재구성 경로를 제공합니다.

| 길 | 설명하다 | 한계 |
|------|------|------|
| 구성 재배포 유지 | 사용자 정의 routing/outbounds/DNS 및 다중 사용자 구성을 유지하고 사용자가 선택한 필드(포트, 경로, UUID, Reality 매개변수 등)만 수정합니다. | 전송 구조 변경(예: ws → gRPC)은 지원되지 않습니다. 전송 조합을 변경해야 하는 경우 표준 템플릿을 사용하여 다시 구성하십시오. |
| 표준 템플릿 재구성 | 현재 재사용 가능한 매개변수를 사용하여 표준 템플릿 구성을 생성합니다. 사용자 정의 routing/outbounds/DNS이(가) 제거될 수 있습니다. | 사용자 수를 변경하지 않아도 됩니다. |
| 모드 스위치 | 다른 프로토콜 모드로 전환합니다(예: Reality → TLS). 기본적으로 기본 사용자 UUID/email만 재사용됩니다. | 다른 사용자는 자동으로 마이그레이션되지 않으며 전환하기 전에 명확한 메시지가 표시됩니다. |

재구성 프로세스의 특정 단계(구성 작성, 서비스 시작, 상태 확인 등)가 실패하면 자동으로 원래 백업 구성으로 롤백됩니다. 백업 디렉터리는 고유한 타임스탬프를 사용하여 서로 충돌하지 않고 여러 번의 연속 재구성을 지원합니다.

## 일반적인 명령

| 작동하다 | 주문하다 |
|------|------|
| 관리자 메뉴 열기 | `idleleo` |
| 도움말 보기 | `idleleo --help` |
| Reality 모드 설치 | `idleleo --install-reality` |
| TLS 모드 설치 | `idleleo --install-tls` |
| ws/gRPC/xHTTP ONLY 설치 | `idleleo --install-none` |
| 설치정보 보기 | `idleleo --show` |
| 업데이트 스크립트 | `idleleo --update` |
| Xray 업데이트 | `idleleo --xray-update` |
| Nginx 업데이트 | `idleleo --nginx-update` |
| Fail2ban 설정 | `idleleo --set-fail2ban` |
| 트래픽 차단 설정 | `idleleo --traffic-blocker` |
| 실시간 포트 트래픽 보기 | `idleleo --port-traffic` |

## Rill Xray AI 운영 및 유지 관리 보조원

내장된 로컬 AI 작동 및 유지 관리 도우미는 Xray/Nginx의 상태를 실시간으로 모니터링하고, 자동으로 결함을 진단하고, 외부 API 없이도 치료 제안을 제공합니다. 메인 메뉴 입력`9`또는 실행`idleleo --rill-agent`입력하다.

**핵심 역량**

* 모니터링: Xray/Nginx 서비스 및 구성 상태를 실시간 관찰
* 진단: 신뢰도 권장 사항(높음/중간/낮음/증거 불충분)을 통해 결함의 근본 원인을 찾습니다.
* 판단: 오류 유형을 자동으로 결정하고 처리 제안을 제공합니다. 지침에는 자동 처리가 허용되거나 제안만 제공된다는 내용이 명확하게 표시되어 있습니다.
* 모드: 지능형 판단/관찰 전용/안전 비활성화, 자동 수정이 켜질 때까지 시스템은 변경되지 않습니다.

**자주 사용하는 명령어**

| 작동하다 | 주문하다 |
|------|------|
| AI 운영 및 유지 관리 보조 메뉴 열기 | `idleleo --rill-agent` |
| AI 판단 엔진 설치 또는 수리 | `idleleo --rill-agent-install` |
| AI 판정 상태를 확인하세요 | `idleleo --rill-agent-status` |
| AI 문제 해결 실행 | `idleleo --rill-agent-diagnose` |
| 검증 AI 판단 엔진 | `idleleo --rill-agent-verify` |
| 보안 비활성화 AI 판단 | `idleleo --rill-agent-safe-disable` |
| Rill AI 엔진 제거 | `idleleo --rill-agent-uninstall` |

AI 판단 엔진은 아직 테스트 단계입니다. 진단 제안에 중점을 두는 것이 좋습니다. 시스템은 기본적으로 자동으로 수정되지 않습니다.

## Docker 배포

Docker을 사용한 배포를 지원하고, 이미지에는 Xray 및 Nginx이 사전 설치되어 있으며 원본 스크립트의 모든 기능을 컨테이너에서 직접 사용할 수 있습니다. 세부정보 보기[Docker 部署指南](/docker/DOCKER.md)。

```bash
git clone https://github.com/hello-yunshu/Xray_bash_onekey.git
cd Xray_bash_onekey
docker compose up -d
docker attach xray-onekey
```

## AI Skill 배포

수동 상호 작용 없이 Trae과 같은 AI 도구를 통해 Xray의 자동 배포를 지원합니다. 세부정보 보기[Xray_bash_onekey_skill](https://github.com/hello-yunshu/Xray_bash_onekey_skill)。

기존 방법에서는 SSH이(가) 서버로 이동하여 설치 스크립트를 실행하고 대화형 질문에 하나씩 대답해야 합니다. Skill 메소드는 AI에 필요한 사항만 알려주면 되며 AI은 자동으로 비대화형 스크립트를 생성하고 실행하여 VLESS 링크를 직접 반환합니다.

**지원되는 모드**: Reality / TLS / ws ONLY / XTLS ONLY

**使用方式**：在支持 Skill 的 AI 工具中直接说"帮我在服务器上搭建 Xray"，AI 会自动收集信息、生成脚本、执行部署并返回连接信息。

## 주의할 점

* 각 설정의 의미를 이해하지 못하는 경우, 필수 항목을 제외하고는 기본값을 그대로 사용하시기 바랍니다. (Enter만 누르시면 됩니다.)
* Cloudflare 사용자는 설치가 완료된 후 CDN을(를) 열어주세요.
* 이 스크립트를 사용하려면 Linux에 대한 기본 지식과 컴퓨터 네트워크 지식이 필요합니다.
* Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+를 지원하며 일부 CentOS 템플릿에는 컴파일 문제가 있을 수 있으므로 문제가 발생하면 시스템을 변경하는 것이 좋습니다.
* 단일 서버는 단일 에이전트만 배포하고 기본 포트 443을 사용하는 것이 좋습니다.
* UUIDv5에 대한 사용자 정의 문자열 매핑에는 클라이언트 지원이 필요합니다.
* 순수한 환경에서 사용하는 것을 권장합니다. 초보자는 CentOS을 사용하면 안 됩니다.
* 이 프로그램은 Nginx에 따라 달라지며 통과되었습니다.[LNMP](https://lnmp.org)Nginx 스크립트를 설치한 사용자는 잠재적인 충돌에 유의하시기 바랍니다.
* xHTTP 공유 링크는 xHTTP을 지원하는 클라이언트를 위한 것입니다. Clash 구성 출력은 xHTTP을 건너뜁니다.
* 먼저 가용성을 확인하지 않고 프로덕션 환경에서 이 스크립트를 사용하지 마세요.
* 작성자: Yun Shu, 제한된 지원만 제공

## 감사의 말

* 기반으로[wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey)개발하다
* TCP에서 인용된 가속 스크립트[ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## 인증서 구성

**맞춤 인증서**: crt 및 key 파일의 이름을 각각 지정합니다.`xray.crt`그리고`xray.key`, 넣다`/etc/idleleo/cert`디렉토리(디렉토리가 없으면 먼저 작성하십시오). 인증기관 및 유효기간에 주의하시기 바랍니다. 사용자 정의 인증서가 만료된 후에는 직접 갱신해야 합니다.

**자동 인증서**: 스크립트는 Let's Encrypt 인증서(3개월 동안 유효) 자동 생성을 지원하며 이론적으로 자동 갱신을 지원합니다.

## 클라이언트 구성 보기

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray 소개

* Xray은 Windows, macOS, Android, iOS, Linux 및 기타 전체 플랫폼을 지원하는 뛰어난 오픈 소스 네트워크 프록시 도구입니다.
* 이 스크립트는 원클릭 완전한 구성 스크립트입니다. 모든 과정이 정상적으로 완료된 후, 출력 결과에 따라 클라이언트를 이용하실 수 있습니다.
* **적극 권장** 프로그램의 작업 흐름과 원칙에 대한 포괄적인 이해

## 서비스 관리

| 작동하다 | 주문하다 |
|------|------|
| Xray 시작 | `systemctl start xray` |
| Xray 중지 | `systemctl stop xray` |
| Nginx 시작 | `systemctl start nginx` |
| Nginx 중지 | `systemctl stop nginx` |

## 관련 카탈로그

| 콘텐츠 | 길 |
|------|------|
| 홈 디렉토리 | `/etc/idleleo` |
| Xray 구성 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 구성 | `/etc/idleleo/conf/nginx/` |
| 설치정보 | `/etc/idleleo/conf/install_config.json` |
| 인증서 파일 | `/etc/idleleo/cert/xray.key`、`/etc/idleleo/cert/xray.crt` |
| 로그 디렉터리 | `/etc/idleleo/logs/`、`/var/log/xray/` |
| Nginx 설치 디렉터리 | `/usr/local/nginx` |
| 관리 명령 | `/usr/bin/idleleo` |
