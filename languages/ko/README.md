# Xray Reality / VLESS WebSocket/gRPC+TLS 프로토콜 + Nginx 일괄 설치 스크립트

[简体中文](/README.md) | [English](/languages/en/README.md) | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | 한국어

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> JetBrains 허가에 감사드립니다.

## 사용 방법

* `idleleo` 명령을 직접 입력하여 스크립트를 관리할 수 있습니다.
* Reality는 Nginx 프론트엔드를 권장하며, 스크립트에서 설치할 수 있습니다.
* fail2ban 활성화를 권장하며, 스크립트에서 설치할 수 있습니다.
* [@DuckSoft](https://github.com/DuckSoft)의 공유 링크 제안[제안](https://github.com/XTLS/Xray-core/issues/91) (beta)을 사용합니다. Qv2ray, V2rayN, V2rayNG 지원.
* [XTLS](https://github.com/XTLS/Xray-core/issues/158) 프로젝트의 제안을 따르며, [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) 표준을 준수하여 사용자 정의 문자열을 VLESS UUID로 매핑할 수 있습니다.
* Reality 설치 안내: [Xray Reality 프로토콜 서버 설정](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi).
* Reality 프로토콜 위험: [Xray Reality 프로토콜 위험](https://hey.run/archives/reality-xie-yi-de-feng-xian).
* Reality 프로토콜을 이용한 서버 가속: [Reality 프로토콜 "취약점"을 이용한 서버 가속](https://hey.run/archives/li-yong-reality-xie-yi-lou-dong-jia-su-fu-wu-qi).
* 부하 분산 구성 추가, 튜토리얼: [XRay 고급 기능 – 백엔드 서버 로드 밸런싱 설정](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng).
* gRPC 프로토콜 지원 추가, 자세히 보기: [Xray 고급 기능 – gRPC 프로토콜 사용](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi).

## Telegram 그룹

* Telegram 대화방: <https://t.me/idleleo_chat>

## 준비 작업

* 중국 외부에서 실행되는 서버, 공인 IP가 필요합니다.
* Reality 프로토콜 설치 시, Xray 요구 사항을 충족하는 도메인이 필요합니다.
* TLS 버전 설치 시, 도메인이 필요하며 A레코드를 추가해야 합니다.
* [Xray 공식 설명서](https://xtls.github.io)를 읽고 Reality TLS WebSocket gRPC 및 Xray 관련 정보를 이해하고, Reality target 도메인 요구 사항을 확인하세요.
* **curl이 설치되어 있어야 합니다**. CentOS 사용자는 `yum install -y curl`을, Debian/Ubuntu 사용자는 `apt install -y curl`을 실행하세요.

## 설치 방법

복사하여 실행:

``` bash
bash <(curl -Ss https://www.idleleo.com/install.sh)
```

## 주의사항

* 스크립트 중 항목별 세부 의미를 모르시다면 필수 입력값 외에는 스크립트 제공 기본값을 사용하세요 (계속 엔터).
* Cloudflare 사용자는 설치 후 CDN 기능을 활성화하세요.
* 이 스크립트를 사용하려면 Linux 기초 지식과 경험, 컴퓨터 네트워크 부분 지식, 컴퓨터 기본 조작 능력이 필요합니다.
* 현재 Debian 9+ / Ubuntu 18.04+ / Centos7+ 를 지원하며 일부 Centos 템플릿에서는 처리하기 어려운 컴파일 문제가 발생할 수 있으므로 문제 발생 시 다른 시스템 템플릿으로 변경하세요.
* 저자는 한정적인 지원만 제공하며 너무 멍청해서요.
* 공유 링크는 실험 버전이며 미래 변경 가능성이 있으니 클라이언트 호환 여부를 스스로 확인하세요.
* 사용자 정의 문자열을 UUIDv5로 매핑하려면 클라이언트가 이를 지원해야 합니다.

## 감사의 말

* 본 스크립트는 <https://github.com/wulabing/V2Ray_ws-tls_bash_onekey> 에서 유래하였으며 여기에 wulabing님에게 감사드립니다.
* 본 스크립트의 TCP 가속 스크립트 프로젝트는 <https://github.com/ylx2016/Linux-NetSpeed> 를 참고하였으며 여기에 ylx2016님에게 감사드립니다.

## 인증서

이미 사용 중인 도메인의 인증서 파일이 있다면 crt와 key 파일을 xray.crt와 xray.key로 이름을 바꾸어 /etc/idleleo/cert 디렉토리 아래에 두세요 (디렉토리가 없으면 먼저 생성하세요). 인증서 파일 권한 및 유효기간을 주의하시고 사용자 정의 인증서 만료 후 재발급해야 합니다.

스크립트는 Let's encrypted 인증서를 자동 생성할 수 있으며 유효기간은 3개월입니다. 이론적으로 자동 생성된 인증서는 자동 갱신됩니다.

## 클라이언트 구성을 확인

`cat /etc/idleleo/xray_info.txt`

## Xray 소개

* Xray는 우수한 오픈 소스 네트워크 프록시 도구로서 인터넷을 원활하게 즐길 수 있도록 돕습니다. 이미 Windows, Mac, Android, IOS, Linux 등 모든 플랫폼에서 사용할 수 있습니다.
* 본 스크립트는 일체형 완전 설정 스크립트로서 모든 절차가 정상적으로 진행되면 출력 결과에 따라 클라이언트를 설정하면 사용할 수 있습니다.
* 주의: 우리는 여전히 전체 프로그램의 작동 과정 및 원리를 전반적으로 이해하도록 강력히 권장합니다.

## 단일 서버에 단일 프록시만 설정하는 것을 권장합니다

* 본 스크립트는 최신 버전의 Xray core를 기본으로 설치합니다.
* 연결 포트로 기본 443 포트 사용을 권장합니다.
* 가짜 내용은 사용자가 교체할 수 있습니다.

## 기타 주의사항

* 순수 환경에서 본 스크립트를 사용하는 것이 좋으며 초보자라면 CentOS 시스템을 사용하지 마세요.
* 본 스크립트가 실제로 작동하는지 확인하기 전까지 생산 환경에 적용하지 마세요.
* 해당 프로그램은 Nginx를 통해 다양한 기능을 구현하는데 의존하므로 [LNMP](https://lnmp.org) 또는 기타 유사한 Nginx 포함 설치 스크립트를 사용한 사용자는 예측 불가능한 오류가 발생할 수 있다는 점에 특히 주의해야 합니다.
* CentOS 사용자는 방화벽에서 프로그램 관련 포트(기본값: 80, 443)를 미리 열어야 합니다.

## 시작 방법

Xray 시작: `systemctl start xray`

Xray 종료: `systemctl stop xray`

Nginx 시작: `systemctl start nginx`

Nginx 종료: `systemctl stop nginx`

## 관련 디렉토리

Xray 서버 설정: `/etc/idleleo/conf/xray/config.json`

Nginx 디렉토리: `/usr/local/nginx`

인증서 파일: `/etc/idleleo/cert/xray.key` 그리고 `/etc/idleleo/cert/xray.crt` 인증서 권한 설정에 주의하세요

구성 정보 파일 등: `/etc/idleleo`