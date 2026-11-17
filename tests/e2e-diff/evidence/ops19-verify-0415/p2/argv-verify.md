# Go argv verification (ops19-verify-0415)

方法：`idleleo <cmd> --help` 只输出总览，无法逐 flag 核实。改用两条硬证据：
1) 未知 flag 会被 checkFlags 拒绝（rc=2, `unknown flag: X`）；
2) `idleleo xray generate` 不写系统路径，能验证 mode/transport 组合。

## M1

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode reality --domain www.cloudflare.com --target www.cloudflare.com --port 443 --container 
```

## M2

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode reality-nginx --domain www.cloudflare.com --target www.cloudflare.com --port 443 --container 
```

## M3

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode reality --transport ws --domain www.cloudflare.com --target www.cloudflare.com --port 443 --container 
```

## M4

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode tls --transport ws --domain example.com --cert /etc/idleleo/cert/xray.crt --cert-key /etc/idleleo/cert/xray.key --port 9000 --public-port 443 --container 
```

## M5

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode tls --transport grpc --domain example.com --container 
```

## M6

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode tls --transport xhttp --domain example.com --container 
```

## M7

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode tls --transport ws+grpc+xhttp --domain example.com --container 
```

## M9

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode none --transport ws --listen 0.0.0.0 --allow-non-loopback --container 
```

## M10

```
install argv: idleleo xray install --role relay --target origin.example.com:443 --listen-port 443 --listen 0.0.0.0 --container 
```

## generate probes

```
### M1
uuid=8fd1c868-e1bc-451e-a784-8b58b90958d4 shortId=c71f73db
share: vless://8fd1c868-e1bc-451e-a784-8b58b90958d4@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=Z5mvXMgfuhq88NWoCoexPOY093iHkgK8ydx2kfXuaXk&sid=c71f73db&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M2
uuid=c326bc1a-0f90-4621-ad18-4eeca4686682 shortId=9241aeec
share: vless://c326bc1a-0f90-4621-ad18-4eeca4686682@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=8I94VItwpFqFT_07B4Y6cci1K-2Y0m2SSJ3Yf3flrGY&sid=9241aeec&type=raw#idleleo-reality-nginx
config: /tmp/g.json
rc=0
### M2-alias
unknown flag: --nginx-bin
rc=2
### M3
uuid=94ed44ff-de72-4b0c-b2e3-22b75471f9f1 shortId=6d993f95
share: vless://94ed44ff-de72-4b0c-b2e3-22b75471f9f1@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=r3NxmRp8B1qB9rih5pUXNeeY781KzILrl6eGKqU3czQ&sid=6d993f95&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M4
uuid=820785f4-4dd2-40af-8c84-5ded9fb77b41 shortId=
share: vless://820785f4-4dd2-40af-8c84-5ded9fb77b41@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
config: /tmp/g.json
rc=0
### M5
uuid=01712471-cb8a-4022-87ca-2027bd13e9a3 shortId=
share: vless://01712471-cb8a-4022-87ca-2027bd13e9a3@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=idleleo-grpc#idleleo-tls
config: /tmp/g.json
rc=0
### M6
share: vless://f2b179b9-cb32-4df4-98df-1fe29df8c6dd@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=/ray/&host=example.com#idleleo-tls
warning=clash-xhttp-unsupported
config: /tmp/g.json
rc=0
### M7
share: vless://9a004d99-fbf9-4694-8fee-da08d848bcfb@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
warning=multi-transport: only the primary inbound share URI is emitted; use 'xray share --inbound' for the others
config: /tmp/g.json
rc=0
### M9
uuid=02bb7aac-15c5-450c-8add-ca4712c7aaeb shortId=
share: vless://02bb7aac-15c5-450c-8add-ca4712c7aaeb@0.0.0.0:10086?encryption=none&security=none&type=ws&path=/ray/&host=0.0.0.0#idleleo-none
config: /tmp/g.json
rc=0
```

## relay conf probe (M10)

```
relay: 0.0.0.0:443 -> origin.example.com:443
nginx: /tmp/relay.conf
# Managed by Xray_bash_onekey (Go). Standalone relay, no Xray/UUID/cert.
stream {
    server {
        listen 0.0.0.0:443;
        proxy_pass origin.example.com:443;
        proxy_connect_timeout 10s;
        proxy_timeout 720m;
        proxy_socket_keepalive on;
    }
}
```

M10 install argv 走真实安装路径验证（见 M10/go/install.rc 与 L4），不在探针容器里拉取 Nginx。
