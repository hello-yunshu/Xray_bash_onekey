# Xray 원클릭 설치 스크립트 — Reality / VLESS WebSocket/gRPC+TLS + Nginx

[简体中文](/README.md) | [English](/languages/en/README.md) | [Français](/languages/fr/README.md) | [Русский](/languages/ru/README.md) | [فارسی](/languages/fa/README.md) | 한국어

[![GitHub stars](https://img.shields.io/github/stars/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/stargazers) [![GitHub forks](https://img.shields.io/github/forks/hello-yunshu/Xray_bash_onekey?color=%230885ce)](https://github.com/hello-yunshu/Xray_bash_onekey/network) [![GitHub issues](https://img.shields.io/github/issues/hello-yunshu/Xray_bash_onekey)](https://github.com/hello-yunshu/Xray_bash_onekey/issues)

> JetBrains의 비상업 오픈소스 개발 라이선스 지원에 감사드립니다

## 주요 기능

* `idleleo` 명령어로 스크립트 관리 ([`idleleo` 배경 이야기 보기](https://github.com/hello-yunshu/Xray_bash_onekey/wiki/%EC%95%88%EA%B0%9C-%EB%92%A4%EC%9D%98-%EC%A7%84%EC%8B%A4%EB%90%9C-%EC%96%BC%EA%B5%B4))
* Qwen-MT-Plus AI 기반 정확한 다국어 번역
* Reality 프로토콜 지원, Nginx 프론트엔드 권장 (스크립트 내 설치 가능)
* fail2ban 보호 내장 (스크립트 내 설치 가능)
* [@DuckSoft](https://github.com/DuckSoft)의 공유 링크 [제안](https://github.com/XTLS/Xray-core/issues/91) (beta) 채택, Qv2ray, V2rayN, V2rayNG 호환
* [XTLS](https://github.com/XTLS/Xray-core/issues/158) 프로젝트 제안 채택, [UUIDv5](https://tools.ietf.org/html/rfc4122#section-4.3) 표준 준수, 사용자 정의 문자열을 VLESS UUID로 매핑 지원
* gRPC 프로토콜 지원: [gRPC 프로토콜 사용하기](https://hey.run/archives/xrayjin-jie-wan-fa---shi-yong-grpcxie-yi)
* Reality / ws/gRPC 로드 밸런싱 지원:
  - [Reality 로드 밸런서 배포](https://hey.run/archives/bushu-reality-balance)
  - [백엔드 로드 밸런서 구축](https://hey.run/archives/xrayjin-jie-wan-fa---da-jian-hou-duan-fu-wu-qi-fu-zai-jun-heng)

## 추가 자료

* Reality 설치 가이드: [Xray Reality 서버 구축](https://hey.run/archives/da-jian-xray-reality-xie-yi-fu-wu-qi)
* Reality 프로토콜 위험: [Xray Reality 프로토콜의 위험](https://hey.run/archives/reality-xie-yi-de-feng-xian)
* Reality로 서버 가속: [Reality 프로토콜 "취약점"으로 서버 가속](https://hey.run/archives/use-reality)

## Telegram 그룹

* 토론 그룹: [클릭하여 참여](https://t.me/+48VSqv7xIIFmZDZl)

## 사전 준비

* 공인 IP를 가진 해외 서버
* Reality 프로토콜: Xray 요구사항을 충족하는 대상 도메인 준비
* TLS 버전: 도메인 준비 및 A 레코드 추가
* [Xray 공식 문서](https://xtls.github.io)를 읽고 Reality, TLS, WebSocket, gRPC 및 Xray 관련 개념 이해
* **curl 설치 확인**: CentOS 사용자는 `yum install -y curl` 실행; Debian/Ubuntu 사용자는 `apt install -y curl` 실행

## 빠른 설치

```bash
bash <(curl -Ss https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh)
```

## 주의사항

* 설정의 의미를 모르면 필수 항목 외에는 기본값을 사용하세요 (계속 Enter)
* Cloudflare 사용자는 설치 완료 후에만 CDN을 활성화하세요
* 이 스크립트는 Linux 기초 지식과 컴퓨터 네트워크 기본이 필요합니다
* Debian 12+ / Ubuntu 24.04+ / CentOS Stream 8+ 지원; 일부 CentOS 템플릿에서 컴파일 문제가 발생할 수 있으며, 문제 시 다른 OS로 전환 권장
* 서버당 하나의 프록시만 배포하고 기본 포트 443 사용을 권장합니다
* 사용자 정의 문자열을 UUIDv5로 매핑하려면 클라이언트 지원이 필요합니다
* 깨끗한 환경에서 사용하세요; 초보자는 CentOS를 피하세요
* 이 프로그램은 Nginx에 의존합니다 — [LNMP](https://lnmp.org) 등으로 Nginx를 설치한 사용자는 잠재적 충돌에 주의하세요
* 작동을 확인하기 전까지 프로덕션 환경에 사용하지 마세요
* 작성자는 제한된 지원만 제공합니다 (너무 멍청해서요)

## 감사의 말

* [wulabing/V2Ray_ws-tls_bash_onekey](https://github.com/wulabing/V2Ray_ws-tls_bash_onekey) 기반
* TCP 가속 스크립트 출처: [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed)

## 인증서 설정

**사용자 정의 인증서**: crt 및 key 파일을 `xray.crt`와 `xray.key`로 이름을 변경한 후 `/etc/idleleo/cert` 디렉토리에 넣으세요 (디렉토리가 없으면 생성). 인증서 권한 및 유효기간에 주의하세요 — 사용자 정의 인증서는 만료 후 수동으로 갱신해야 합니다.

**자동 인증서**: 스크립트는 Let's Encrypt 인증서 자동 생성을 지원합니다 (유효기간 3개월), 이론적으로 자동 갱신이 지원됩니다.

## 클라이언트 설정 확인

```bash
cat /etc/idleleo/info/xray_info.inf
```

## Xray 소개

* Xray는 Windows, macOS, Android, iOS, Linux 등을 지원하는 우수한 오픈소스 네트워크 프록시 도구입니다
* 이 스크립트는 원클릭 완전 설정 스크립트입니다 — 모든 프로세스가 정상적으로 완료되면 출력 결과에 따라 클라이언트를 설정하기만 하면 됩니다
* **프로그램의 작동 방식과 원리를 완전히 이해할 것을 강력히 권장합니다**

## 서비스 관리

| 작업 | 명령어 |
|------|--------|
| Xray 시작 | `systemctl start xray` |
| Xray 중지 | `systemctl stop xray` |
| Nginx 시작 | `systemctl start nginx` |
| Nginx 중지 | `systemctl stop nginx` |

## 디렉토리

| 항목 | 경로 |
|------|------|
| Xray 서버 설정 | `/etc/idleleo/conf/xray/config.json` |
| Nginx 디렉토리 | `/usr/local/nginx` |
| 인증서 파일 | `/etc/idleleo/cert/xray.key`, `/etc/idleleo/cert/xray.crt` |
| 설정 정보 등 | `/etc/idleleo` |
