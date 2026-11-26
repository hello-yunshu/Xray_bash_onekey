# Go argv verification (codex-final-20261126-f4deaf77)

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
uuid=2eea39e7-dc9b-46fd-8761-cf30925baf9f shortId=972faa71
share: vless://2eea39e7-dc9b-46fd-8761-cf30925baf9f@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=A3YJMKb-r11HgC8ZMdl-8ev0z7-eDD8GFxc5iMb0uzQ&sid=972faa71&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M2
uuid=ec812efb-322b-44cc-abe4-e1aa421696bd shortId=ae41400b
share: vless://ec812efb-322b-44cc-abe4-e1aa421696bd@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=ZDQbcR33CrRqT_cPZd38R_kxWYHWYQgzw9wqBFw_gTY&sid=ae41400b&type=raw#idleleo-reality-nginx
config: /tmp/g.json
rc=0
### M2-alias
unknown flag: --nginx-bin
rc=2
### M3
uuid=69a34622-d957-4011-aadb-f5dd6d05cca8 shortId=19ac46f4
share: vless://69a34622-d957-4011-aadb-f5dd6d05cca8@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=Gz2AQGl9BJ5XEfTPVwTooOjOfVu9Kk7YjqAk1f1v7VA&sid=19ac46f4&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M4
uuid=b8e5c54f-8de3-486c-8427-3fa4ec791072 shortId=
share: vless://b8e5c54f-8de3-486c-8427-3fa4ec791072@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
config: /tmp/g.json
rc=0
### M5
uuid=4e44bb54-4e86-4cb1-be48-d21309afa302 shortId=
share: vless://4e44bb54-4e86-4cb1-be48-d21309afa302@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=idleleo-grpc#idleleo-tls
config: /tmp/g.json
rc=0
### M6
share: vless://011cf40e-8a04-4e99-82b2-87e256ad023f@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=/ray/&host=example.com#idleleo-tls
warning=clash-xhttp-unsupported
config: /tmp/g.json
rc=0
### M7
share: vless://525c1e33-1939-4661-9655-3b0fd807c181@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
warning=multi-transport: only the primary inbound share URI is emitted; use 'xray share --inbound' for the others
config: /tmp/g.json
rc=0
### M9
uuid=e45897a7-f0a9-41b2-899d-c2f743d3564f shortId=
share: vless://e45897a7-f0a9-41b2-899d-c2f743d3564f@0.0.0.0:10086?encryption=none&security=none&type=ws&path=/ray/&host=0.0.0.0#idleleo-none
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
