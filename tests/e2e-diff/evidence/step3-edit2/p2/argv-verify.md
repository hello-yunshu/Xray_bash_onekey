# Go argv verification (step3-edit2)

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
uuid=3052a7a1-303a-41f9-b421-cec703f77e78 shortId=2a6f55fb
share: vless://3052a7a1-303a-41f9-b421-cec703f77e78@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=Tt05dBlLcVjF1CIEAZUOV_mj-dr_3jSqPdsKQh4QXT4&sid=2a6f55fb&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M2
uuid=92ac2875-8d92-4c7e-b7ba-fa7bec955986 shortId=fc0e8bc5
share: vless://92ac2875-8d92-4c7e-b7ba-fa7bec955986@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=_cn9EEvD4plmFr71sb2E2idRR1LvAxEAIZuiB5JjJ2g&sid=fc0e8bc5&type=raw#idleleo-reality-nginx
config: /tmp/g.json
rc=0
### M2-alias
unknown flag: --nginx-bin
rc=2
### M3
uuid=d2291938-7705-40ba-a4b6-307e0c110d6d shortId=b330b1d9
share: vless://d2291938-7705-40ba-a4b6-307e0c110d6d@www.cloudflare.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.cloudflare.com&fp=chrome&pbk=HeVrDnu14463ERX484qPMC8EypKkMQgu0XNm6aN9OVI&sid=b330b1d9&type=raw#idleleo-reality
config: /tmp/g.json
rc=0
### M4
uuid=86eb8296-28ce-410b-a54a-b814b64f48f9 shortId=
share: vless://86eb8296-28ce-410b-a54a-b814b64f48f9@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
config: /tmp/g.json
rc=0
### M5
uuid=e81d2fd8-21a4-4a7f-b776-1d9740724275 shortId=
share: vless://e81d2fd8-21a4-4a7f-b776-1d9740724275@example.com:443?encryption=none&security=tls&sni=example.com&type=grpc&serviceName=idleleo-grpc#idleleo-tls
config: /tmp/g.json
rc=0
### M6
share: vless://9e34febf-e15d-43f6-b3bb-707235b43c81@example.com:443?encryption=none&security=tls&sni=example.com&type=xhttp&path=/ray/&host=example.com#idleleo-tls
warning=clash-xhttp-unsupported
config: /tmp/g.json
rc=0
### M7
share: vless://3d1f0cec-b718-471f-8571-692722b9c098@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&path=/ray/&host=example.com#idleleo-tls
warning=multi-transport: only the primary inbound share URI is emitted; use 'xray share --inbound' for the others
config: /tmp/g.json
rc=0
### M9
uuid=11892b16-682e-4f54-8f71-8480f6f74afb shortId=
share: vless://11892b16-682e-4f54-8f71-8480f6f74afb@0.0.0.0:10086?encryption=none&security=none&type=ws&path=/ray/&host=0.0.0.0#idleleo-none
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
