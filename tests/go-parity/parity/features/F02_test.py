#!/usr/bin/env python3
"""F02: TLS (Nginx front) ws / gRPC / xHTTP / combined transport executor.

Contract: feature_contracts.json F02. This fixture executes the real Go binary,
validates every generated runtime config with the real `xray -test`, and compares
the artifacts against the fixed Bash TLS baseline (config/vless_tls.json plus the
install.sh functions, executed for real with jq).

Evidence level: CONTAINER_VERIFIED. No real VPS, no public ACME, no client data
plane. The real-certificate `xray install --mode tls` path is recorded as a gap.
"""
import hashlib
import json
import re
import shutil
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

UUID = "bbbbbbbb-2222-4222-8222-222222222222"
DOMAIN = "example.com"
WS_PORT = 12443
GRPC_PORT = 12444
XHTTP_PORT = 12445

BASH_FUNCTIONS = (
    "update_json_config",
    "modify_listen_address",
    "modify_inbound_port",
    "add_ws_inbound",
    "add_grpc_inbound",
    "add_xhttp_inbound",
    "modify_path",
    "modify_email_address",
    "apply_install_profile",
    "transport_choose",
    "nginx_servers_add",
    "modify_nginx_other",
    "modify_nginx_ssl_other",
)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def extract_bash_function(text, name):
    match = re.search(rf"^{re.escape(name)}\s*\(\)\s*\{{\n(.*?)^\}}\s*$",
                      text, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else None


def inbounds(cfg):
    return cfg["inbounds"]


def by_network(cfg):
    return {ib["streamSettings"]["network"]: ib for ib in inbounds(cfg)}


def gen(f, work, name, extra):
    """Run `xray generate --mode tls` into its own directory."""
    case = work / name
    case.mkdir(parents=True, exist_ok=True)
    out = case / "config.json"
    nginx = case / "nginx.conf"
    frags = case / "fragments"
    cmd = [
        f.go, "xray", "generate", "--mode", "tls", "--domain", DOMAIN,
        "--uuid", UUID, "--out", out, "--nginx-out", nginx,
        "--fragments-out", frags, "--json",
    ] + [str(x) for x in extra]
    result = f.run(cmd, timeout=60)
    return {
        "case": case, "out": out, "nginx": nginx, "fragments": frags,
        "result": result,
        "payload": json.loads(result.out) if result.rc == 0 and result.out.strip() else None,
    }


def fragments_of(frags):
    if not frags.is_dir():
        return {}
    return {p.name: p.read_text(encoding="utf-8") for p in frags.iterdir() if p.is_file()}


def share_params(uri):
    parts = urllib.parse.urlsplit(uri)
    return parts, urllib.parse.parse_qs(parts.query)


def one(params, key):
    values = params.get(key) or []
    return values[0] if values else ""


def xray_test(f, xray, path, label, observed):
    Path("/var/log/xray").mkdir(parents=True, exist_ok=True)
    result = f.run([xray, "-test", "-config", str(path)], timeout=90)
    observed.setdefault("xrayTest", {})[label] = {"rc": result.rc, "config": str(path)}
    f.check(result.rc == 0, f"{label}: real xray -test accepts the generated config",
            result.text[-400:])
    return result


def main(f):
    f.need(f.bash_repo is not None,
           "F02 requires --bash-repo for the fixed TLS Bash baseline")
    f.need_root()
    f.need_tool("jq")
    xray = f.xray_bin()

    work = f.evidence / "f02-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    observed = {"generated": {}, "rejections": {}, "environment": {}}

    # ------------------------------------------------------------------ S1 ws
    ws = gen(f, work, "ws", [])
    f.check(ws["result"].rc == 0 and ws["out"].is_file(),
            "S1 tls/ws generate rc=0 and wrote the config", ws["result"].text[:300])
    if ws["payload"] is None:
        return
    ws_cfg = read_json(ws["out"])
    ws_payload = ws["payload"]
    f.check(oct(ws["out"].stat().st_mode & 0o777) == "0o600",
            "S1 runtime config is 0600", oct(ws["out"].stat().st_mode & 0o777))
    f.check(len(inbounds(ws_cfg)) == 1, "S1 exactly one inbound", str(len(inbounds(ws_cfg))))
    ws_in = inbounds(ws_cfg)[0]
    f.check(ws_payload["mode"] == "tls" and ws_payload["transport"] == "ws",
            "S1 payload mode/transport", f"{ws_payload['mode']}/{ws_payload['transport']}")
    f.check(ws_payload["publicPort"] == 443, "S1 public port defaults to 443",
            str(ws_payload["publicPort"]))
    f.check(ws_in["tag"] == "VLESS-ws-in", "S1 ws tag", ws_in["tag"])
    f.check(ws_in["protocol"] == "vless", "S1 protocol is lowercase vless",
            ws_in["protocol"])
    f.check(ws_in["listen"] == "127.0.0.1", "S1 inbound listens on loopback",
            ws_in["listen"])
    f.check(10000 <= ws_in["port"] <= 10999, "S1 ws port comes from the Bash ws pool",
            str(ws_in["port"]))
    f.check(ws_payload["port"] == ws_in["port"], "S1 payload port matches the inbound",
            f"{ws_payload['port']} vs {ws_in['port']}")
    stream = ws_in["streamSettings"]
    f.check(stream["security"] == "none",
            "S1 Nginx terminates TLS; the inbound keeps security=none", stream["security"])
    f.check(stream["wsSettings"]["path"] == "/ray/", "S1 default ws path",
            stream["wsSettings"]["path"])
    f.check(ws_in["settings"]["clients"][0]["email"] == "me@hey.run",
            "S1 primary client email", ws_in["settings"]["clients"][0]["email"])
    rule = ws_cfg["routing"]["rules"][0]
    f.check(rule["inboundTag"] == ["VLESS-ws-in"] and rule["outboundTag"] == "direct",
            "S1 routing rule targets the ws inbound", json.dumps(rule))

    parts, params = share_params(ws_payload["shareUri"])
    f.check(parts.scheme == "vless" and parts.port == 443,
            "S1 share URI is vless on the public port", f"{parts.scheme}:{parts.port}")
    f.check(one(params, "security") == "tls", "S1 share security=tls",
            one(params, "security"))
    f.check(one(params, "type") == "ws", "S1 share type=ws", one(params, "type"))
    f.check(one(params, "sni") == DOMAIN, "S1 share sni", one(params, "sni"))
    f.check(one(params, "host") == DOMAIN, "S1 share host", one(params, "host"))
    f.check(one(params, "path") == "/ray/", "S1 share path", one(params, "path"))
    f.check("path=/ray/" in parts.query,
            "S1 share path is carried verbatim in the query", parts.query[:200])
    f.check(parts.fragment == "idleleo-tls", "S1 share fragment", parts.fragment)

    clash = ws_payload.get("clashYaml") or ""
    f.check("type: vless" in clash and "network: ws" in clash,
            "S1 Clash proxy is vless/ws", clash[:200])
    f.check("tls: true" in clash and f"servername: {DOMAIN}" in clash,
            "S1 Clash enables TLS with the domain SNI", clash[:300])
    f.check("path: /ray/" in clash and f"Host: {DOMAIN}" in clash,
            "S1 Clash ws path/Host", clash[:400])

    nginx = ws["nginx"].read_text(encoding="utf-8")
    f.check(ws["nginx"].is_file(), "S1 nginx conf written", str(ws["nginx"]))
    f.check("listen 443 ssl reuseport;" in nginx, "S1 nginx TLS listener", nginx[:200])
    f.check("listen 443 quic reuseport;" in nginx, "S1 nginx QUIC listener")
    f.check("http2 on;" in nginx, "S1 nginx http2")
    f.check(re.search(r"ssl_certificate\s+/etc/idleleo/cert/xray\.crt;", nginx) is not None,
            "S1 nginx default certificate path")
    f.check(re.search(r"ssl_certificate_key\s+/etc/idleleo/cert/xray\.key;", nginx) is not None,
            "S1 nginx default key path")
    f.check(re.search(r"server_name\s+example\.com;", nginx) is not None,
            "S1 nginx server_name")
    f.check(re.search(r"ssl_protocols\s+TLSv1\.3;", nginx) is not None,
            "S1 nginx pins TLS 1.3")
    f.check("location /ray/ {" in nginx, "S1 nginx ws location")
    f.check("proxy_pass http://xray-ws-server;" in nginx, "S1 nginx ws upstream")
    f.check("location / {\n        return 403;" in nginx,
            "S1 nginx refuses unknown paths")

    frags = fragments_of(ws["fragments"])
    f.check(set(frags) == {"01-xray-80.conf", "02-xray-server.conf",
                           "127.0.0.1.wsServers"},
            "S1 TLS fragment set", json.dumps(sorted(frags)))
    f.check(frags.get("127.0.0.1.wsServers", "").strip()
            == f"server 127.0.0.1:{ws_in['port']} weight=50 max_fails=2 fail_timeout=10;",
            "S1 ws backend fragment matches the inbound port",
            frags.get("127.0.0.1.wsServers", "").strip())
    server_conf = frags.get("02-xray-server.conf", "")
    f.check("upstream xray-ws-server {" in server_conf
            and "include /etc/idleleo/conf/nginx/*.wsServers;" in server_conf,
            "S1 upstream includes the ws backend fragment", server_conf)
    redirect = frags.get("01-xray-80.conf", "")
    f.check("listen 80;" in redirect
            and "location ^~ /.well-known/acme-challenge/" in redirect,
            "S1 port-80 fragment serves ACME", redirect[:300])
    f.check("return 301 https://example.com$request_uri;" in redirect,
            "S1 port-80 fragment redirects to https", redirect)

    xray_test(f, xray, ws["out"], "tls-ws", observed)
    observed["generated"]["ws"] = {
        "port": ws_in["port"], "tag": ws_in["tag"],
        "share": ws_payload["shareUri"], "fragments": sorted(frags),
        "upstream": "xray-ws-server",
    }

    # ---------------------------------------------------------------- S2 gRPC
    grpc = gen(f, work, "grpc", ["--transport", "grpc",
                                 "--service-name", "idleleo-grpc"])
    f.check(grpc["result"].rc == 0, "S2 tls/grpc generate rc=0",
            grpc["result"].text[:300])
    if grpc["payload"] is not None:
        grpc_cfg = read_json(grpc["out"])
        grpc_in = by_network(grpc_cfg)["grpc"]
        grpc_settings = grpc_in["streamSettings"]["grpcSettings"]
        f.check(grpc_in["tag"] == "VLESS-gRPC-in", "S2 gRPC tag", grpc_in["tag"])
        f.check(grpc_in["listen"] == "127.0.0.1", "S2 gRPC listens on loopback",
                grpc_in["listen"])
        f.check(grpc_settings["serviceName"] == "idleleo-grpc",
                "S2 service name", grpc_settings["serviceName"])
        f.check(grpc_settings["multiMode"] is True, "S2 multiMode")
        f.check(grpc_settings["idle_timeout"] == 20, "S2 idle_timeout matches Bash",
                str(grpc_settings["idle_timeout"]))
        f.check(grpc_in["settings"]["clients"][0]["email"] == "me@hey.run",
                "S2 gRPC email parity with Bash",
                grpc_in["settings"]["clients"][0]["email"])
        parts, params = share_params(grpc["payload"]["shareUri"])
        f.check(one(params, "type") == "grpc", "S2 share type=grpc", one(params, "type"))
        f.check(one(params, "serviceName") == "idleleo-grpc",
                "S2 share serviceName", one(params, "serviceName"))
        f.check(one(params, "security") == "tls", "S2 share security=tls")
        f.check("host" not in params, "S2 gRPC share has no ws host parameter")
        clash = grpc["payload"].get("clashYaml") or ""
        f.check("network: grpc" in clash and "grpc-opts:" in clash
                and "grpc-service-name: idleleo-grpc" in clash,
                "S2 Clash gRPC options", clash[:300])
        nginx = grpc["nginx"].read_text(encoding="utf-8")
        f.check("location /idleleo-grpc {" in nginx, "S2 nginx gRPC location")
        f.check("grpc_pass grpc://xray-grpc-server;" in nginx, "S2 nginx gRPC upstream")
        frags = fragments_of(grpc["fragments"])
        f.check(frags.get("127.0.0.1.grpcServers", "").strip()
                == f"server 127.0.0.1:{grpc_in['port']} weight=50 max_fails=2 fail_timeout=10;",
                "S2 gRPC backend fragment", frags.get("127.0.0.1.grpcServers", "").strip())
        f.check("upstream xray-grpc-server {" in frags.get("02-xray-server.conf", ""),
                "S2 gRPC upstream block")
        xray_test(f, xray, grpc["out"], "tls-grpc", observed)
        observed["generated"]["grpc"] = {
            "port": grpc_in["port"], "serviceName": grpc_settings["serviceName"],
            "share": grpc["payload"]["shareUri"],
        }

    # --------------------------------------------------------------- S3 xHTTP
    xhttp = gen(f, work, "xhttp", ["--transport", "xhttp", "--path", "/xhttp/"])
    f.check(xhttp["result"].rc == 0, "S3 tls/xhttp generate rc=0",
            xhttp["result"].text[:300])
    if xhttp["payload"] is not None:
        xhttp_cfg = read_json(xhttp["out"])
        xhttp_in = by_network(xhttp_cfg)["xhttp"]
        xhttp_settings = xhttp_in["streamSettings"]["xhttpSettings"]
        f.check(xhttp_in["tag"] == "VLESS-xhttp-in", "S3 xHTTP tag", xhttp_in["tag"])
        f.check(xhttp_in["listen"] == "127.0.0.1", "S3 xHTTP listens on loopback",
                xhttp_in["listen"])
        f.check(xhttp_settings["path"] == "/xhttp/", "S3 xHTTP path",
                xhttp_settings["path"])
        f.check(xhttp_settings["mode"] == "auto", "S3 xHTTP mode=auto")
        parts, params = share_params(xhttp["payload"]["shareUri"])
        f.check(one(params, "type") == "xhttp", "S3 share type=xhttp", one(params, "type"))
        f.check(one(params, "path") == "/xhttp/", "S3 share path", one(params, "path"))
        f.check(one(params, "host") == DOMAIN, "S3 share host", one(params, "host"))
        f.check(xhttp["payload"].get("clashYaml", "") == "",
                "S3 xHTTP has no Clash proxy")
        f.check("clash-xhttp-unsupported" in (xhttp["payload"].get("warnings") or []),
                "S3 Clash warning is explicit",
                json.dumps(xhttp["payload"].get("warnings") or []))
        nginx = xhttp["nginx"].read_text(encoding="utf-8")
        f.check("location /xhttp/ {" in nginx, "S3 nginx xHTTP location")
        f.check("grpc_pass grpc://xray-xhttp-server;" in nginx,
                "S3 nginx xHTTP upstream")
        frags = fragments_of(xhttp["fragments"])
        f.check(frags.get("127.0.0.1.xhttpServers", "").strip()
                == f"server 127.0.0.1:{xhttp_in['port']} weight=50 max_fails=2 fail_timeout=10;",
                "S3 xHTTP backend fragment",
                frags.get("127.0.0.1.xhttpServers", "").strip())
        f.check("upstream xray-xhttp-server {" in frags.get("02-xray-server.conf", ""),
                "S3 xHTTP upstream block")
        xray_test(f, xray, xhttp["out"], "tls-xhttp", observed)
        observed["generated"]["xhttp"] = {
            "port": xhttp_in["port"], "path": xhttp_settings["path"],
            "share": xhttp["payload"]["shareUri"],
        }

    # The default xHTTP path without --path is /ray/, while Bash defaults to
    # xhttp. Record the observed default instead of guessing.
    xhttp_default = gen(f, work, "xhttp-default", ["--transport", "xhttp"])
    if xhttp_default["payload"] is not None:
        default_path = by_network(read_json(xhttp_default["out"]))["xhttp"][
            "streamSettings"]["xhttpSettings"]["path"]
        observed["generated"]["xhttpDefaultPath"] = default_path

    # ---------------------------------------------------------------- S4 multi
    multi = gen(f, work, "multi-pinned", [
        "--transport", "ws+grpc+xhttp",
        "--ws-port", str(WS_PORT), "--grpc-port", str(GRPC_PORT),
        "--xhttp-port", str(XHTTP_PORT),
    ])
    f.check(multi["result"].rc == 0, "S4 combined generate rc=0",
            multi["result"].text[:300])
    if multi["payload"] is not None:
        multi_cfg = read_json(multi["out"])
        nets = by_network(multi_cfg)
        f.check(set(nets) == {"ws", "grpc", "xhttp"}, "S4 three transports",
                json.dumps(sorted(nets)))
        f.check(nets["ws"]["port"] == WS_PORT, "S4 pinned ws port",
                str(nets["ws"]["port"]))
        f.check(nets["grpc"]["port"] == GRPC_PORT, "S4 pinned gRPC port",
                str(nets["grpc"]["port"]))
        f.check(nets["xhttp"]["port"] == XHTTP_PORT, "S4 pinned xHTTP port",
                str(nets["xhttp"]["port"]))
        f.check(nets["ws"]["listen"] == "127.0.0.1"
                and nets["grpc"]["listen"] == "127.0.0.1"
                and nets["xhttp"]["listen"] == "127.0.0.1",
                "S4 all backends stay on loopback")
        f.check(nets["ws"]["streamSettings"]["wsSettings"]["path"] == "/ray/",
                "S4 ws path")
        f.check(nets["xhttp"]["streamSettings"]["xhttpSettings"]["path"] == "/xhttp/",
                "S4 xHTTP path")
        rule_tags = multi_cfg["routing"]["rules"][0]["inboundTag"]
        f.check(set(rule_tags) == {"VLESS-ws-in", "VLESS-gRPC-in", "VLESS-xhttp-in"},
                "S4 routing covers all three inbounds", json.dumps(rule_tags))
        parts, params = share_params(multi["payload"]["shareUri"])
        f.check(one(params, "type") == "ws" and parts.port == 443,
                "S4 share URI is the ws primary on the public port",
                multi["payload"]["shareUri"])
        f.check(any("multi-transport" in w
                    for w in multi["payload"].get("warnings") or []),
                "S4 combined transport warning", json.dumps(multi["payload"].get("warnings") or []))
        nginx = multi["nginx"].read_text(encoding="utf-8")
        for needle in ("location /ray/ {", "location /idleleo-grpc {",
                       "location /xhttp/ {", "proxy_pass http://xray-ws-server;",
                       "grpc_pass grpc://xray-grpc-server;",
                       "grpc_pass grpc://xray-xhttp-server;"):
            f.check(needle in nginx, f"S4 nginx contains {needle!r}")
        frags = fragments_of(multi["fragments"])
        f.check(set(frags) == {"01-xray-80.conf", "02-xray-server.conf",
                               "127.0.0.1.wsServers", "127.0.0.1.grpcServers",
                               "127.0.0.1.xhttpServers"},
                "S4 combined fragment set", json.dumps(sorted(frags)))
        server_conf = frags.get("02-xray-server.conf", "")
        for upstream in ("xray-ws-server", "xray-grpc-server", "xray-xhttp-server"):
            f.check(f"upstream {upstream} {{" in server_conf,
                    f"S4 upstream {upstream} exists")
        xray_test(f, xray, multi["out"], "tls-multi", observed)
        observed["generated"]["multi"] = {
            "ports": {k: v["port"] for k, v in nets.items()},
            "share": multi["payload"]["shareUri"],
            "clash": (multi["payload"].get("clashYaml") or "").splitlines()[:8],
        }

    auto = gen(f, work, "multi-auto", ["--transport", "ws+grpc+xhttp"])
    f.check(auto["result"].rc == 0, "S4 auto-picked combined generate rc=0",
            auto["result"].text[:300])
    if auto["payload"] is not None:
        auto_nets = by_network(read_json(auto["out"]))
        ports = {k: v["port"] for k, v in auto_nets.items()}
        f.check(len(set(ports.values())) == 3, "S4 auto ports are distinct",
                json.dumps(ports))
        f.check(10000 <= ports["ws"] <= 10999 and 10000 <= ports["grpc"] <= 10999,
                "S4 auto ws/gRPC ports come from the 10000-10999 pool",
                json.dumps(ports))
        f.check(11000 <= ports["xhttp"] <= 11999,
                "S4 auto xHTTP port comes from the 11000-11999 pool",
                json.dumps(ports))
        observed["generated"]["multiAuto"] = ports

    cases = {
        "duplicate ws/grpc port": ["--transport", "ws+grpc+xhttp",
                                   "--ws-port", str(WS_PORT),
                                   "--grpc-port", str(WS_PORT)],
        "grpc port equals the public port": ["--transport", "ws+grpc+xhttp",
                                             "--grpc-port", "443"],
        "ws port out of range": ["--transport", "ws+grpc+xhttp",
                                 "--ws-port", "70000"],
    }
    for label, extra in cases.items():
        bad = gen(f, work, "reject-" + re.sub(r"\W+", "-", label), extra)
        f.check(bad["result"].rc == 2, f"S4 {label} is refused with exit 2",
                f"rc={bad['result'].rc}")
        f.check(not bad["out"].exists() and not bad["fragments"].exists(),
                f"S4 {label} writes nothing")
        observed["rejections"][label] = bad["result"].rc

    # ----------------------------------------------------------- S5 boundaries
    missing_domain = work / "s5-missing-domain"
    missing_domain.mkdir(parents=True, exist_ok=True)
    out = missing_domain / "config.json"
    r = f.run([f.go, "xray", "generate", "--mode", "tls", "--transport", "ws",
               "--out", out, "--json"], timeout=60)
    f.check(r.rc == 2, "S5 tls without --domain is refused", f"rc={r.rc}")
    f.check(not out.exists(), "S5 missing domain writes nothing")
    f.check("tls mode requires --domain" in r.text,
            "S5 missing domain error names the flag", r.text[:200])
    observed["rejections"]["missing domain"] = r.rc

    for label, args in {
        "malformed domain": ["--domain", "bad domain", "--transport", "ws"],
        "reality transport in tls mode": ["--domain", DOMAIN, "--transport", "reality"],
        "unknown transport": ["--domain", DOMAIN, "--transport", "quic"],
    }.items():
        case = work / ("s5-" + re.sub(r"\W+", "-", label))
        case.mkdir(parents=True, exist_ok=True)
        out = case / "config.json"
        r = f.run([f.go, "xray", "generate", "--mode", "tls", "--out", out,
                   "--json"] + args, timeout=60)
        f.check(r.rc == 2, f"S5 {label} is refused with exit 2", f"rc={r.rc}")
        f.check(not out.exists(), f"S5 {label} writes nothing")
        observed["rejections"][label] = r.rc

    # Overwrite protection is checked before writing but after generation.
    overwrite = work / "s5-overwrite"
    overwrite.mkdir(parents=True, exist_ok=True)
    out = overwrite / "config.json"
    first = f.run([f.go, "xray", "generate", "--mode", "tls", "--transport", "ws",
                   "--domain", DOMAIN, "--out", out, "--json"], timeout=60)
    f.check(first.rc == 0, "S5 first generate for overwrite test", f"rc={first.rc}")
    before = out.read_bytes() if out.is_file() else b""
    second = f.run([f.go, "xray", "generate", "--mode", "tls", "--transport", "grpc",
                    "--domain", DOMAIN, "--out", out, "--json"], timeout=60)
    f.check(second.rc == 2, "S5 existing --out without --force is refused",
            f"rc={second.rc}")
    f.check(out.is_file() and out.read_bytes() == before,
            "S5 refused overwrite keeps the original bytes")
    forced = f.run([f.go, "xray", "generate", "--mode", "tls", "--transport", "grpc",
                    "--domain", DOMAIN, "--out", out, "--force", "--json"], timeout=60)
    f.check(forced.rc == 0, "S5 --force overwrites", f"rc={forced.rc}")
    observed["rejections"]["overwrite"] = second.rc

    pub = gen(f, work, "public-port", ["--public-port", "8443"])
    if pub["payload"] is not None:
        pub_in = inbounds(read_json(pub["out"]))[0]
        pub_nginx = pub["nginx"].read_text(encoding="utf-8")
        pub_frags = fragments_of(pub["fragments"])
        f.check("listen 8443 ssl reuseport;" in pub_nginx,
                "S5 --public-port moves the nginx listener")
        f.check("listen 8443 quic reuseport;" in pub_nginx,
                "S5 --public-port moves the QUIC listener")
        f.check("return 301 https://example.com:8443$request_uri;"
                in pub_frags.get("01-xray-80.conf", ""),
                "S5 redirect keeps the non-standard public port")
        f.check(pub_in["port"] != 8443, "S5 the backend port never equals the public port",
                str(pub_in["port"]))
        parts, params = share_params(pub["payload"]["shareUri"])
        f.check(parts.port == 8443, "S5 share URI advertises the public port",
                str(parts.port))
        observed["generated"]["publicPort"] = 8443

    cert = gen(f, work, "cert-pair", ["--cert", "/srv/tls/a.crt",
                                      "--cert-key", "/srv/tls/a.key"])
    if cert["payload"] is not None:
        cert_nginx = cert["nginx"].read_text(encoding="utf-8")
        f.check(re.search(r"ssl_certificate\s+/srv/tls/a\.crt;", cert_nginx) is not None,
                "S5 explicit --cert reaches nginx")
        f.check(re.search(r"ssl_certificate_key\s+/srv/tls/a\.key;", cert_nginx) is not None,
                "S5 explicit --cert-key reaches nginx")

    cert_only = gen(f, work, "cert-only", ["--cert", "/srv/tls/a.crt"])
    cert_only_status = "gap"
    if cert_only["payload"] is not None:
        cert_only_nginx = cert_only["nginx"].read_text(encoding="utf-8")
        cert_only_status = "gap: --cert without --cert-key is accepted at generate time"
        f.check(re.search(r"ssl_certificate_key\s+/etc/idleleo/cert/xray\.key;",
                          cert_only_nginx) is not None,
                "S5 cert-only generation falls back to the default key")
    else:
        cert_only_status = "aligned"
        f.check(cert_only["result"].rc == 2,
                "S5 --cert without --cert-key is refused",
                f"rc={cert_only['result'].rc}")
        f.check(not cert_only["out"].exists(), "S5 refused cert pair writes nothing")

    listen_any = gen(f, work, "listen-any", ["--listen", "0.0.0.0"])
    listen_status = ""
    if listen_any["payload"] is not None:
        listen_in = inbounds(read_json(listen_any["out"]))[0]
        f.check(listen_in["listen"] == "0.0.0.0",
                "S5 explicit --listen is honoured for TLS",
                listen_in["listen"])
        listen_status = ("divergent-guard: Bash forces 127.0.0.1 in TLS mode, "
                         "Go honours an explicit --listen 0.0.0.0")
        observed["generated"]["listenOverride"] = listen_in["listen"]
        listen_multi = gen(f, work, "listen-any-multi",
                           ["--listen", "0.0.0.0", "--transport", "ws+grpc+xhttp"])
        if listen_multi["payload"] is not None:
            lm = by_network(read_json(listen_multi["out"]))
            f.check(lm["ws"]["listen"] == "0.0.0.0"
                    and lm["grpc"]["listen"] == "127.0.0.1"
                    and lm["xhttp"]["listen"] == "127.0.0.1",
                    "S5 combined mode only applies --listen to the primary",
                    json.dumps({k: v["listen"] for k, v in lm.items()}))
    else:
        f.check(listen_any["result"].rc == 2,
                "S5 non-loopback TLS listen is refused",
                f"rc={listen_any['result'].rc}")
        listen_status = "aligned: non-loopback TLS listen refused"

    port_ignored = gen(f, work, "port-ignored", ["--port", "19999"])
    if port_ignored["payload"] is not None:
        ignored_in = inbounds(read_json(port_ignored["out"]))[0]
        f.check(ignored_in["port"] != 19999
                and 10000 <= ignored_in["port"] <= 10999,
                "S5 --port is not the TLS backend port", str(ignored_in["port"]))
        observed["generated"]["portFlagIgnored"] = {
            "requested": 19999, "backend": ignored_in["port"]}

    # ------------------------------------------------------- S6 Bash baseline
    install_sh = f.bash_repo / "install.sh"
    install_text = install_sh.read_text(encoding="utf-8")
    template_path = f.bash_repo / "config/vless_tls.json"
    f.check(template_path.is_file(), "S6 Bash TLS template exists", str(template_path))
    if not template_path.is_file():
        return
    template = read_json(template_path)
    tpl_in = template["inbounds"][0]
    f.check(tpl_in["tag"] == "VLESS-ws-in", "S6 template tag", tpl_in["tag"])
    f.check(tpl_in["port"] == 10086 and tpl_in["listen"] == "127.0.0.1",
            "S6 template pins 127.0.0.1:10086",
            f"{tpl_in['listen']}:{tpl_in['port']}")
    f.check(tpl_in["protocol"] == "VLESS",
            "S6 template spells the protocol uppercase", tpl_in["protocol"])
    f.check(tpl_in["streamSettings"]["security"] == "none"
            and tpl_in["streamSettings"]["network"] == "ws"
            and tpl_in["streamSettings"]["wsSettings"]["path"] == "/ray/",
            "S6 template ws stream settings")
    f.check(template["routing"]["rules"][0]["inboundTag"] == ["VLESS-ws-in"],
            "S6 template routing targets the ws inbound")

    functions = {}
    for name in BASH_FUNCTIONS:
        body = extract_bash_function(install_text, name)
        functions[name] = body
        f.check(body is not None, f"S6 Bash function {name} extracted")
    if any(body is None for body in functions.values()):
        return

    listen_fn = functions["modify_listen_address"]
    f.check('listen_addr="127.0.0.1"' in listen_fn
            and '[[ ${tls_mode} == "TLS" ]]' in listen_fn,
            "S6 Bash forces loopback for TLS")
    ports_fn = functions["modify_inbound_port"]
    f.check('"VLESS-ws-in")).port = $xport' in ports_fn
            and '"VLESS-gRPC-in")).port = $gport' in ports_fn
            and '"VLESS-xhttp-in")).port = $xhttpport' in ports_fn,
            "S6 Bash TLS ports come from xport/gport/xhttpport")
    f.check('"multiMode": true' in functions["add_grpc_inbound"]
            and '"idle_timeout": 20' in functions["add_grpc_inbound"],
            "S6 Bash gRPC template matches the Go stream settings")
    f.check('"mode": "auto"' in functions["add_xhttp_inbound"]
            and 'xhttp_path="/${xhttp_path#/}"' in functions["add_xhttp_inbound"],
            "S6 Bash xHTTP template matches the Go stream settings")
    servers_fn = functions["nginx_servers_add"]
    for name in ("127.0.0.1.wsServers", "127.0.0.1.grpcServers",
                 "127.0.0.1.xhttpServers"):
        f.check(name in servers_fn, f"S6 Bash backend fragment {name}")
    f.check(servers_fn.count("weight=50 max_fails=2 fail_timeout=10") == 3,
            "S6 Bash backend weights match the Go fragments")
    other_fn = functions["modify_nginx_other"]
    f.check("${escaped_path}" in other_fn and "${escaped_serviceName}" in other_fn
            and "${escaped_xhttppath}" in other_fn,
            "S6 Bash nginx locations follow the configured paths")
    f.check("proxy_pass http:\\/\\/xray-ws-server;" in other_fn
            and "grpc_pass" in other_fn,
            "S6 Bash enables the ws/gRPC upstreams")
    f.check("return 301 https:\\/\\/${escaped_domain}\\$request_uri;" 
            in functions["modify_nginx_ssl_other"],
            "S6 Bash port-80 site redirects to https")
    f.check('transport_nginx_tls)' in functions["apply_install_profile"]
            and 'tls_mode="TLS"' in functions["apply_install_profile"],
            "S6 Bash profile maps transport_nginx_tls to TLS")
    f.check('transport_mode="wsgRPCxhttp"' in functions["transport_choose"],
            "S6 Bash menu 5 is ws+gRPC+xHTTP")
    f.check('transport_mode="wsxhttp"' in functions["transport_choose"],
            "S6 Bash menu 4 offers ws+xHTTP (a combination Go does not implement)")

    # Real Bash execution: template copy + extracted functions + jq.
    bash_dir = work / "bash"
    bash_dir.mkdir(parents=True, exist_ok=True)
    bash_config = bash_dir / "config.json"
    shutil.copyfile(template_path, bash_config)
    script = bash_dir / "run-baseline.sh"
    script.write_text("\n".join([
        "set -u",
        'log_echo() { :; }',
        'gettext() { printf "%s" "$1"; }',
        'judge() { :; }',
        'Error=""; RedBG=""; Font=""; OK=""; GreenBG=""; Warning=""; YellowBG=""',
        'is_ws_mode() { return 0; }',
        'is_grpc_mode() { return 0; }',
        'is_xhttp_mode() { return 0; }',
        "resolve_ws_backend_listen_addr() { printf '127.0.0.1'; }",
        functions["update_json_config"],
        functions["modify_listen_address"],
        functions["modify_inbound_port"],
        functions["add_ws_inbound"],
        functions["add_grpc_inbound"],
        functions["add_xhttp_inbound"],
        functions["modify_path"],
        'xray_conf="$WORK/config.json"',
        'xray_install_config_file="$WORK/config.json"',
        'tls_mode="TLS"',
        'reality_add_nginx="on"',
        'reality_add_more="off"',
        'port=19999',
        f'xport={WS_PORT}',
        f'gport={GRPC_PORT}',
        f'xhttpport={XHTTP_PORT}',
        'path="ray/"',
        'serviceName="idleleo-grpc"',
        'xhttppath="xhttp"',
        'add_grpc_inbound 127.0.0.1 "$gport" "$serviceName"',
        'add_xhttp_inbound 127.0.0.1 "$xhttpport" "$xhttppath"',
        f'''jq --arg id "{UUID}" '.inbounds[].settings.clients[].id = $id' "$xray_conf" > "$xray_conf.tmp" && mv "$xray_conf.tmp" "$xray_conf"''',
        'jq \'.inbounds[].listen = "0.0.0.0"\' "$xray_conf" > "$xray_conf.tmp" && mv "$xray_conf.tmp" "$xray_conf"',
        "modify_listen_address",
        "modify_inbound_port",
        "modify_path",
    ]) + "\n", encoding="utf-8")
    env = dict(f.env, WORK=str(bash_dir))
    executed = f.run(["bash", str(script)], timeout=90, env=env)
    f.check(executed.rc == 0, "S6 extracted Bash functions run for real",
            executed.text[-400:])
    bash_cfg = read_json(bash_config) if bash_config.is_file() else None
    f.check(bash_cfg is not None, "S6 Bash baseline config was produced")
    comparison = {}
    if bash_cfg is not None:
        bash_nets = {ib["streamSettings"]["network"]: ib for ib in inbounds(bash_cfg)}
        f.check(set(bash_nets) == {"ws", "grpc", "xhttp"},
                "S6 Bash baseline has three transports",
                json.dumps(sorted(bash_nets)))
        f.check(all(ib["listen"] == "127.0.0.1" for ib in bash_nets.values()),
                "S6 Bash rewrote every listen back to 127.0.0.1",
                json.dumps({k: v["listen"] for k, v in bash_nets.items()}))
        f.check(bash_nets["ws"]["port"] == WS_PORT
                and bash_nets["grpc"]["port"] == GRPC_PORT
                and bash_nets["xhttp"]["port"] == XHTTP_PORT,
                "S6 Bash applied xport/gport/xhttpport",
                json.dumps({k: v["port"] for k, v in bash_nets.items()}))
        f.check(bash_nets["ws"]["streamSettings"]["wsSettings"]["path"] == "/ray/",
                "S6 Bash ws path",
                bash_nets["ws"]["streamSettings"]["wsSettings"]["path"])

        go_multi_cfg = read_json(multi["out"]) if multi["payload"] is not None else {}
        go_nets = by_network(go_multi_cfg) if go_multi_cfg else {}
        if go_nets:
            comparison["ws"] = {
                "go": {"tag": go_nets["ws"]["tag"],
                       "path": go_nets["ws"]["streamSettings"]["wsSettings"]["path"],
                       "listen": go_nets["ws"]["listen"],
                       "port": go_nets["ws"]["port"],
                       "email": go_nets["ws"]["settings"]["clients"][0]["email"],
                       "protocol": go_nets["ws"]["protocol"]},
                "bash": {"tag": bash_nets["ws"]["tag"],
                         "path": bash_nets["ws"]["streamSettings"]["wsSettings"]["path"],
                         "listen": bash_nets["ws"]["listen"],
                         "port": bash_nets["ws"]["port"],
                         "email": bash_nets["ws"]["settings"]["clients"][0]["email"],
                         "protocol": bash_nets["ws"]["protocol"]},
                "goStatus": "divergent-naming: Go emits lowercase vless, Bash VLESS",
            }
            comparison["grpc"] = {
                "go": {"serviceName": go_nets["grpc"]["streamSettings"]["grpcSettings"]["serviceName"],
                       "multiMode": go_nets["grpc"]["streamSettings"]["grpcSettings"]["multiMode"],
                       "idleTimeout": go_nets["grpc"]["streamSettings"]["grpcSettings"]["idle_timeout"],
                       "email": go_nets["grpc"]["settings"]["clients"][0]["email"]},
                "bash": {"serviceName": bash_nets["grpc"]["streamSettings"]["grpcSettings"]["serviceName"],
                         "multiMode": bash_nets["grpc"]["streamSettings"]["grpcSettings"]["multiMode"],
                         "idleTimeout": bash_nets["grpc"]["streamSettings"]["grpcSettings"]["idle_timeout"],
                         "email": bash_nets["grpc"]["settings"]["clients"][0]["email"]},
                "goStatus": "aligned",
            }
            comparison["xhttp"] = {
                "go": {"path": go_nets["xhttp"]["streamSettings"]["xhttpSettings"]["path"],
                       "mode": go_nets["xhttp"]["streamSettings"]["xhttpSettings"]["mode"],
                       "email": go_nets["xhttp"]["settings"]["clients"][0]["email"]},
                "bash": {"path": bash_nets["xhttp"]["streamSettings"]["xhttpSettings"]["path"],
                         "mode": bash_nets["xhttp"]["streamSettings"]["xhttpSettings"]["mode"],
                         "email": bash_nets["xhttp"]["settings"]["clients"][0]["email"]},
                "goStatus": "divergent-trailing-slash: Go /xhttp/ vs Bash /xhttp",
            }
        f.write_json("bash-result.json", {
            "installSha256": hashlib.sha256(install_sh.read_bytes()).hexdigest(),
            "script": script.read_text(encoding="utf-8"),
            "compare": comparison,
        })
        Path("/var/log/xray").mkdir(parents=True, exist_ok=True)
        bash_test = f.run([xray, "-test", "-config", str(bash_config)], timeout=90)
        observed.setdefault("xrayTest", {})["bash-baseline"] = {
            "rc": bash_test.rc, "config": str(bash_config)}
        f.check(bash_test.rc == 0,
                "S6 real xray -test accepts the Bash baseline config",
                bash_test.text[-400:])

    baseline = [
        {"contract": "TLS public port default", "go": 443, "bash": 443,
         "goStatus": "aligned"},
        {"contract": "ws backend default port",
         "go": "ascending free port in 10000-10999",
         "bash": "random port in 10000-10999",
         "goStatus": "divergent-selection: same pool, different strategy"},
        {"contract": "protocol spelling", "go": "vless", "bash": "VLESS",
         "goStatus": "divergent-naming"},
        {"contract": "ws default path", "go": "/ray/",
         "bash": "random hex path when not customised",
         "goStatus": "divergent-default-path"},
        {"contract": "xHTTP path shape", "go": "/xhttp/", "bash": "/xhttp",
         "goStatus": "divergent-trailing-slash"},
        {"contract": "TLS inbound listen",
         "go": "127.0.0.1 by default; --listen 0.0.0.0 honoured",
         "bash": "always forced to 127.0.0.1",
         "goStatus": listen_status},
        {"contract": "--port semantics in TLS mode",
         "go": "--port is ignored; --public-port owns the Nginx port",
         "bash": "port is the Nginx public port",
         "goStatus": "divergent-flag-semantics"},
        {"contract": "certificate pair validation at generate time",
         "go": cert_only_status, "bash": "install checks the pair on disk",
         "goStatus": cert_only_status.split(":")[0]},
        {"contract": "ws+xHTTP combination", "go": "not offered",
         "bash": "menu 4 = wsxhttp", "goStatus": "not-implemented"},
        {"contract": "backend upstream weights", "go": "weight=50 max_fails=2 fail_timeout=10",
         "bash": "weight=50 max_fails=2 fail_timeout=10", "goStatus": "aligned"},
        {"contract": "port-80 ACME + redirect", "go": "01-xray-80.conf",
         "bash": "01-xray-80.conf", "goStatus": "aligned"},
        {"contract": "share URI for combined transports",
         "go": "primary ws only, with a warning",
         "bash": "prints every transport link",
         "goStatus": "divergent-output: Go requires 'xray share --inbound'"},
        {"contract": "Clash for xHTTP", "go": "no proxy + clash-xhttp-unsupported",
         "bash": "not asserted by this fixture",
         "goStatus": "gap: Bash Clash xHTTP rendering not executed"},
        {"contract": "TLS install with a real certificate and host Nginx",
         "go": "generate-only in this fixture",
         "bash": "downloads the pair and installs Nginx",
         "goStatus": "gap: needs host Nginx and a trusted pair; not faked"},
    ]
    f.write_json("observed.json", observed)
    f.write_json("baseline-compare.json", {
        "fixture": "F02", "date": "2026-11-17",
        "installSha256": hashlib.sha256(install_sh.read_bytes()).hexdigest(),
        "comparisons": baseline,
    })
    f.check(True, "S6 baseline-compare.json written")


if __name__ == "__main__":
    raise SystemExit(run_fixture("F02", main))
