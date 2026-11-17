# Go argv verification (s2-ops-0434)

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
uuid=bde57701-58e3-4f45-a4dd-7e46fdb772f9 shortId=d31cb652
share: vless://bde57701-58e3-4f45-a4dd-7e46fdb772f9@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=HSZjk5HxB6DmqPrpvhl8dSLeytSqrpFHSS_LwRV6AmA&sid=d31cb652&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M2
uuid=fa57a6d3-dd83-4af9-a55d-203d004711d9 shortId=f8808735
share: vless://fa57a6d3-dd83-4af9-a55d-203d004711d9@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=_gmLX65XnExy0-qnMDsAGY4FbrzwEenR4_JMkPgjJyg&sid=f8808735&type=raw#idleleo-reality-nginx
config: /tmp/g.json
rc=0
### M2-alias
unknown flag: --nginx-bin
rc=2
### M3
uuid=8188e917-099c-4714-aa3f-29c2f510552f shortId=11bfb74b
share: vless://8188e917-099c-4714-aa3f-29c2f510552f@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=EaEnQsv9xcujYC-zbxVsfxSpQp3BevA4wxVbls5_7gY&sid=11bfb74b&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M4
uuid=edc2ce8b-07d6-409b-8f4d-7f83db948e09 shortId=
share: vless://edc2ce8b-07d6-409b-8f4d-7f83db948e09@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
config: /tmp/g.json
rc=0
### M5
uuid=c7df526f-0919-47d4-adb9-57d27670bfd1 shortId=
share: vless://c7df526f-0919-47d4-adb9-57d27670bfd1@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=idleleo-grpc#idleleo-tls
config: /tmp/g.json
rc=0
### M6
share: vless://5b1f4257-5d3a-4be5-9ce0-84d3e8a3ff40@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=/ray/&host=example.com#idleleo-tls
warning=clash-xhttp-unsupported
config: /tmp/g.json
rc=0
### M7
share: vless://574ca83a-da3c-49db-a139-2da636dad89b@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
warning=multi-transport: only the primary inbound share URI is emitted; use 'xray share --inbound' for the others
config: /tmp/g.json
rc=0
### M9
uuid=6721acfe-ee6d-40b9-9caa-36b8c5242339 shortId=
share: vless://6721acfe-ee6d-40b9-9caa-36b8c5242339@0.0.0.0:10086?encryption=none&security=none&type=ws&path=/ray/&host=0.0.0.0#idleleo-none
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
