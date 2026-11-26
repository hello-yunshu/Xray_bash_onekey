# Go argv verification (codex-final-20261126-5528ca7f-M6)

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

## M8

```
install argv: idleleo xray install --binary /usr/local/bin/xray --mode tls --transport ws --domain example.com --cert /etc/idleleo/cert/xray.crt --cert-key /etc/idleleo/cert/xray.key --port 9000 --public-port 443 --container 
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
uuid=a6651100-c123-43d1-b6c1-3ef334d02583 shortId=ed91ae7a
share: vless://a6651100-c123-43d1-b6c1-3ef334d02583@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=rcQLy8eNRTWYYcnbdQOhBpCjqelx6E3DDRXwodFljCo&sid=ed91ae7a&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M2
uuid=64953217-aada-4ba2-a9e9-0fe77cd8f048 shortId=05409f56
share: vless://64953217-aada-4ba2-a9e9-0fe77cd8f048@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=G4Bx4qhORu-XJUtzCzOnFVLmku9vioxezB0ZTEcsnlg&sid=05409f56&type=raw#idleleo-reality-nginx
config: /tmp/g.json
rc=0
### M2-alias
unknown flag: --nginx-bin
rc=2
### M3
uuid=d736d1b9-9a90-4448-8193-f8b10806d526 shortId=03575095
share: vless://d736d1b9-9a90-4448-8193-f8b10806d526@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=5dfvrsQMNmgaBzM0A2GSDtiIHkNuacQcCgk2S-SW9B0&sid=03575095&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M4
uuid=66e8b569-6ab4-47cf-b1ee-f667be3983a5 shortId=
share: vless://66e8b569-6ab4-47cf-b1ee-f667be3983a5@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
config: /tmp/g.json
rc=0
### M5
uuid=23bd8f52-c412-4e19-9dc9-040d0844e755 shortId=
share: vless://23bd8f52-c412-4e19-9dc9-040d0844e755@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=idleleo-grpc#idleleo-tls
config: /tmp/g.json
rc=0
### M6
share: vless://2e291e8e-3dc2-484f-8e3e-5ca1f95489f3@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=/ray/&host=example.com#idleleo-tls
warning=clash-xhttp-unsupported
config: /tmp/g.json
rc=0
### M7
share: vless://0a77db36-a4e0-4f0e-ab1f-e5542c08fa37@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
warning=multi-transport: only the primary inbound share URI is emitted; use 'xray share --inbound' for the others
config: /tmp/g.json
rc=0
### M9
uuid=30c6bea6-32c7-4423-b980-249d6af76db2 shortId=
share: vless://30c6bea6-32c7-4423-b980-249d6af76db2@0.0.0.0:10086?encryption=none&security=none&type=ws&path=/ray/&host=0.0.0.0#idleleo-none
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
