#!/usr/bin/env python3
"""F03: no-TLS (transport_only) backend loopback listen executor.

Contract: feature_contracts.json F03. This fixture executes the real Go binary
for `xray generate --mode none`, validates every valid config with the real
`xray -test`, and compares the artifacts against the fixed Bash baseline
(`transport_only` profile, config/vless_tls.json template and the real
install.sh modify_listen_address/modify_inbound_port/add_*_inbound functions
executed with jq).

Evidence level: CONTAINER_VERIFIED. No real VPS, no client data plane. The real
`install_xray_ws_only` service install is recorded as a gap.
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

UUID = "cccccccc-3333-4333-8333-333333333333"
WS_PORT = 12443
GRPC_PORT = 12444
XHTTP_PORT = 12445
PRIMARY_PORT = 12086
NONLOCAL = "10.10.0.5"

BASH_FUNCTIONS = (
    "update_json_config",
    "modify_listen_address",
    "modify_inbound_port",
    "add_ws_inbound",
    "add_grpc_inbound",
    "add_xhttp_inbound",
    "modify_path",
    "modify_email_address",
    "ws_backend_listen_default",
    "is_valid_listen_address",
    "resolve_ws_backend_listen_addr",
    "apply_install_profile",
    "transport_choose",
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
    """Run `xray generate --mode none` into its own directory."""
    case = work / name
    case.mkdir(parents=True, exist_ok=True)
    out = case / "config.json"
    nginx = case / "nginx.conf"
    frags = case / "fragments"
    cmd = [
        f.go, "xray", "generate", "--mode", "none", "--uuid", UUID,
        "--out", out, "--nginx-out", nginx, "--fragments-out", frags, "--json",
    ] + [str(x) for x in extra]
    result = f.run(cmd, timeout=60)
    return {
        "case": case, "out": out, "nginx": nginx, "fragments": frags,
        "result": result,
        "payload": json.loads(result.out) if result.rc == 0 and result.out.strip() else None,
    }


def reject(f, work, name, extra):
    case = work / name
    case.mkdir(parents=True, exist_ok=True)
    out = case / "config.json"
    nginx = case / "nginx.conf"
    frags = case / "fragments"
    cmd = [
        f.go, "xray", "generate", "--mode", "none", "--uuid", UUID,
        "--out", out, "--nginx-out", nginx, "--fragments-out", frags, "--json",
    ] + [str(x) for x in extra]
    return f.run(cmd, timeout=60), out, nginx, frags


def assert_zero_write(f, label, out, nginx, frags):
    f.check(not out.exists(), f"{label}: no runtime config was written", str(out))
    f.check(not nginx.exists(), f"{label}: no Nginx config was written", str(nginx))
    f.check(not frags.exists(), f"{label}: no Nginx fragments were written", str(frags))


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
           "F03 requires --bash-repo for the fixed no-TLS Bash baseline")
    f.need_root()
    f.need_tool("jq")
    xray = f.xray_bin()

    work = f.evidence / "f03-work"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    observed = {"generated": {}, "rejections": {}, "environment": {}}

    # ------------------------------------------------------- S1 default none ws
    ws = gen(f, work, "default-ws", [])
    f.check(ws["result"].rc == 0 and ws["out"].is_file(),
            "S1 none/ws generate rc=0 and wrote the config", ws["result"].text[:300])
    if ws["payload"] is None:
        return
    cfg = read_json(ws["out"])
    payload = ws["payload"]
    f.check(oct(ws["out"].stat().st_mode & 0o777) == "0o600",
            "S1 runtime config is 0600", oct(ws["out"].stat().st_mode & 0o777))
    f.check(len(inbounds(cfg)) == 1, "S1 exactly one inbound", str(len(inbounds(cfg))))
    ib = inbounds(cfg)[0]
    f.check(payload["mode"] == "none" and payload["transport"] == "ws",
            "S1 payload mode/transport", f"{payload['mode']}/{payload['transport']}")
    f.check(payload["port"] == 10086 and payload["publicPort"] == 10086,
            "S1 payload defaults to port/publicPort 10086",
            f"{payload['port']}/{payload['publicPort']}")
    f.check(payload["listen"] == "127.0.0.1", "S1 payload listen is loopback",
            payload["listen"])
    f.check(ib["tag"] == "VLESS-ws-in", "S1 ws tag", ib["tag"])
    f.check(ib["protocol"] == "vless", "S1 protocol is lowercase vless", ib["protocol"])
    f.check(ib["port"] == 10086, "S1 no-TLS inbound keeps the default 10086",
            str(ib["port"]))
    f.check(ib["listen"] == "127.0.0.1", "S1 inbound listens on loopback", ib["listen"])
    stream = ib["streamSettings"]
    f.check(stream["security"] == "none", "S1 no TLS on the inbound", stream["security"])
    f.check(stream["network"] == "ws" and stream["wsSettings"]["path"] == "/ray/",
            "S1 ws path defaults to /ray/",
            f"{stream['network']}/{stream['wsSettings']['path']}")
    f.check(ib["settings"]["clients"][0]["id"] == UUID,
            "S1 client UUID is applied", ib["settings"]["clients"][0]["id"])
    f.check(ib["settings"]["clients"][0]["email"] == "me@hey.run",
            "S1 default email", ib["settings"]["clients"][0]["email"])
    f.check(cfg["routing"]["rules"][0]["inboundTag"] == ["VLESS-ws-in"],
            "S1 routing targets the ws inbound",
            json.dumps(cfg["routing"]["rules"][0]["inboundTag"]))

    parts, params = share_params(payload["shareUri"])
    f.check(parts.scheme == "vless" and parts.port == 10086,
            "S1 share URI port is the inbound port", f"{parts.scheme}/{parts.port}")
    f.check(one(params, "security") == "none", "S1 share security=none",
            one(params, "security"))
    f.check(one(params, "type") == "ws" and one(params, "path") == "/ray/",
            "S1 share ws path", f"{one(params, 'type')}/{one(params, 'path')}")
    f.check(one(params, "host") == "127.0.0.1" and parts.hostname == "127.0.0.1",
            "S1 share host follows the loopback listen", one(params, "host"))

    clash = payload["clashYaml"]
    f.check("network: ws" in clash and "ws-opts:" in clash and "path: /ray/" in clash,
            "S1 Clash proxy describes ws", clash[:300])
    f.check("tls:" not in clash and "servername:" not in clash,
            "S1 Clash does not pretend TLS is enabled", clash[:300])
    f.check(not ws["nginx"].exists() and not ws["fragments"].exists(),
            "S1 no-TLS mode writes no Nginx artifacts",
            f"{ws['nginx'].exists()}/{ws['fragments'].exists()}")
    xray_test(f, xray, ws["out"], "S1 default ws", observed)
    observed["generated"]["default"] = {
        "inbound": {k: ib[k] for k in ("tag", "protocol", "port", "listen")},
        "payload": {k: payload[k] for k in ("mode", "transport", "port", "publicPort", "listen")},
        "share": payload["shareUri"],
    }

    # ------------------------------------------------------- S2 loopback guard
    denied, out, nginx, frags = reject(f, work, "guard-deny", ["--listen", "0.0.0.0"])
    f.check(denied.rc == 2, "S2 non-loopback listen without the flag exits 2",
            f"rc={denied.rc} {denied.text[-300:]}")
    f.check("requires explicit confirmation" in denied.text,
            "S2 refusal names the explicit confirmation requirement", denied.text[-300:])
    assert_zero_write(f, "S2 guard denial", out, nginx, frags)
    observed["rejections"]["guard"] = {"rc": denied.rc, "stderr": denied.text[-300:]}

    allowed = gen(f, work, "guard-allow", ["--listen", "0.0.0.0", "--allow-non-loopback"])
    f.check(allowed["result"].rc == 0 and allowed["payload"] is not None,
            "S2 --allow-non-loopback accepts 0.0.0.0", allowed["result"].text[:300])
    if allowed["payload"] is not None:
        allowed_ib = inbounds(read_json(allowed["out"]))[0]
        f.check(allowed_ib["listen"] == "0.0.0.0",
                "S2 accepted non-loopback listen is written literally",
                allowed_ib["listen"])
        allowed_parts, _ = share_params(allowed["payload"]["shareUri"])
        f.check(allowed_parts.hostname == "0.0.0.0",
                "S2 share host follows the accepted listen", allowed_parts.hostname)
        xray_test(f, xray, allowed["out"], "S2 allow 0.0.0.0", observed)

    v6 = gen(f, work, "ipv6-loopback", ["--listen", "::1"])
    f.check(v6["result"].rc == 0 and v6["payload"] is not None,
            "S2 explicit IPv6 loopback needs no confirmation", v6["result"].text[:300])
    if v6["payload"] is not None:
        v6_ib = inbounds(read_json(v6["out"]))[0]
        f.check(v6_ib["listen"] == "::1", "S2 ::1 is written as-is", v6_ib["listen"])
        v6_parts, v6_params = share_params(v6["payload"]["shareUri"])
        f.check(v6_parts.hostname == "::1" and v6_parts.port == 10086,
                "S2 IPv6 share authority is bracketed",
                f"{v6_parts.hostname}:{v6_parts.port}")
        f.check(one(v6_params, "host") == "::1",
                "S2 IPv6 share host decodes to ::1", one(v6_params, "host"))
        xray_test(f, xray, v6["out"], "S2 ::1", observed)

    v6_deny, out, nginx, frags = reject(
        f, work, "ipv6-guard", ["--listen", "2001:db8::1"])
    f.check(v6_deny.rc == 2,
            "S2 global IPv6 listen is refused without the flag", f"rc={v6_deny.rc}")
    assert_zero_write(f, "S2 ipv6 guard", out, nginx, frags)
    v6_allow = gen(f, work, "ipv6-allow",
                   ["--listen", "2001:db8::1", "--allow-non-loopback"])
    f.check(v6_allow["result"].rc == 0,
            "S2 --allow-non-loopback accepts a global IPv6 listen",
            v6_allow["result"].text[:300])
    if v6_allow["payload"] is not None:
        xray_test(f, xray, v6_allow["out"], "S2 2001:db8::1", observed)

    # Gap: only the loopback rule is checked; the address format is not.
    bad = gen(f, work, "invalid-listen",
              ["--listen", "not-an-ip", "--allow-non-loopback"])
    f.check(bad["result"].rc == 0 and bad["payload"] is not None,
            "S2 invalid listen text is accepted at generate time (recorded gap)",
            bad["result"].text[:300])
    if bad["payload"] is not None:
        observed["generated"]["invalidListen"] = bad["payload"]["listen"]
        bad_test = f.run([xray, "-test", "-config", str(bad["out"])], timeout=90)
        observed["xrayTest"]["S2 invalid listen"] = {
            "rc": bad_test.rc, "config": str(bad["out"])}
        f.check(bad_test.rc != 0,
                "S2 real xray -test rejects the unvalidated listen address",
                bad_test.text[-400:])

    # ------------------------------------------------- S3 transport topologies
    grpc = gen(f, work, "grpc", ["--transport", "grpc"])
    f.check(grpc["result"].rc == 0 and grpc["payload"] is not None,
            "S3 none/grpc generate succeeds", grpc["result"].text[:300])
    if grpc["payload"] is not None:
        g_ib = inbounds(read_json(grpc["out"]))[0]
        gs = g_ib["streamSettings"]
        f.check(g_ib["tag"] == "VLESS-gRPC-in" and gs["network"] == "grpc",
                "S3 gRPC inbound identity", f"{g_ib['tag']}/{gs['network']}")
        f.check(gs["grpcSettings"]["serviceName"] == "idleleo-grpc"
                and gs["grpcSettings"]["multiMode"] is True
                and gs["grpcSettings"]["idle_timeout"] == 20,
                "S3 gRPC stream settings match Bash",
                json.dumps(gs["grpcSettings"]))
        f.check(g_ib["listen"] == "127.0.0.1" and g_ib["port"] == 10086,
                "S3 gRPC keeps loopback and the primary port",
                f"{g_ib['listen']}:{g_ib['port']}")
        _, gp = share_params(grpc["payload"]["shareUri"])
        f.check(one(gp, "type") == "grpc" and one(gp, "serviceName") == "idleleo-grpc",
                "S3 share carries type=grpc and the service name",
                f"{one(gp, 'type')}/{one(gp, 'serviceName')}")
        f.check("network: grpc" in grpc["payload"]["clashYaml"]
                and "tls:" not in grpc["payload"]["clashYaml"],
                "S3 gRPC Clash proxy is cleartext", grpc["payload"]["clashYaml"][:300])
        xray_test(f, xray, grpc["out"], "S3 grpc", observed)

    xhttp = gen(f, work, "xhttp", ["--transport", "xhttp"])
    f.check(xhttp["result"].rc == 0 and xhttp["payload"] is not None,
            "S3 none/xhttp generate succeeds", xhttp["result"].text[:300])
    if xhttp["payload"] is not None:
        x_ib = inbounds(read_json(xhttp["out"]))[0]
        xs = x_ib["streamSettings"]
        f.check(x_ib["tag"] == "VLESS-xhttp-in" and xs["network"] == "xhttp",
                "S3 xHTTP inbound identity", f"{x_ib['tag']}/{xs['network']}")
        f.check(xs["xhttpSettings"]["mode"] == "auto",
                "S3 xHTTP mode is auto", xs["xhttpSettings"]["mode"])
        f.check(xs["xhttpSettings"]["path"] == "/ray/",
                "S3 standalone xHTTP inherits the default /ray/ path",
                xs["xhttpSettings"]["path"])
        _, xp = share_params(xhttp["payload"]["shareUri"])
        f.check(one(xp, "type") == "xhttp" and one(xp, "path") == "/ray/",
                "S3 share carries type=xhttp and the path",
                f"{one(xp, 'type')}/{one(xp, 'path')}")
        f.check(not xhttp["payload"].get("clashYaml")
                and "clash-xhttp-unsupported" in xhttp["payload"]["warnings"],
                "S3 xHTTP refuses to fake a Clash proxy",
                json.dumps(xhttp["payload"]["warnings"]))
        xray_test(f, xray, xhttp["out"], "S3 xhttp", observed)

    multi = gen(f, work, "multi-pinned", [
        "--transport", "ws+grpc+xhttp", "--port", str(PRIMARY_PORT),
        "--ws-port", str(WS_PORT), "--grpc-port", str(GRPC_PORT),
        "--xhttp-port", str(XHTTP_PORT),
    ])
    f.check(multi["result"].rc == 0 and multi["payload"] is not None,
            "S3 multi pinned generate succeeds", multi["result"].text[:300])
    if multi["payload"] is not None:
        nets = by_network(read_json(multi["out"]))
        f.check(set(nets) == {"ws", "grpc", "xhttp"},
                "S3 multi has three transports", json.dumps(sorted(nets)))
        f.check(nets["ws"]["port"] == PRIMARY_PORT,
                "S3 multi ws is the primary inbound and uses --port",
                str(nets["ws"]["port"]))
        f.check(nets["grpc"]["port"] == GRPC_PORT
                and nets["xhttp"]["port"] == XHTTP_PORT,
                "S3 pinned grpc/xhttp ports are honoured",
                f"{nets['grpc']['port']}/{nets['xhttp']['port']}")
        f.check(all(ib["listen"] == "127.0.0.1" for ib in nets.values()),
                "S3 default multi keeps every inbound on loopback",
                json.dumps({k: v["listen"] for k, v in nets.items()}))
        f.check(nets["xhttp"]["streamSettings"]["xhttpSettings"]["path"] == "/xhttp/",
                "S3 added xHTTP uses the /xhttp/ path",
                nets["xhttp"]["streamSettings"]["xhttpSettings"]["path"])
        f.check(any("multi-transport" in w for w in multi["payload"]["warnings"]),
                "S3 multi warns that only the primary share link is emitted",
                json.dumps(multi["payload"]["warnings"]))
        f.check(len(read_json(multi["out"])["routing"]["rules"][0]["inboundTag"]) == 3,
                "S3 routing covers all three inbounds")
        xray_test(f, xray, multi["out"], "S3 multi pinned", observed)
        observed["generated"]["multiPinned"] = {
            k: {"port": v["port"], "listen": v["listen"]} for k, v in nets.items()}
        observed["generated"]["multiPinned"]["wsPortFlagIgnored"] = True

    auto = gen(f, work, "multi-auto", [
        "--transport", "ws+grpc+xhttp", "--port", str(PRIMARY_PORT)])
    f.check(auto["result"].rc == 0 and auto["payload"] is not None,
            "S3 multi auto generate succeeds", auto["result"].text[:300])
    if auto["payload"] is not None:
        anets = by_network(read_json(auto["out"]))
        f.check(anets["ws"]["port"] == PRIMARY_PORT,
                "S3 auto multi ws stays on --port", str(anets["ws"]["port"]))
        f.check(10000 <= anets["grpc"]["port"] <= 10999,
                "S3 auto gRPC port comes from the 10000-10999 pool",
                str(anets["grpc"]["port"]))
        f.check(11000 <= anets["xhttp"]["port"] <= 11999,
                "S3 auto xHTTP port comes from the 11000-11999 pool",
                str(anets["xhttp"]["port"]))
        f.check(len({anets["ws"]["port"], anets["grpc"]["port"],
                     anets["xhttp"]["port"]}) == 3,
                "S3 auto ports are distinct",
                json.dumps({k: v["port"] for k, v in anets.items()}))

    nonlocal_multi = gen(f, work, "multi-nonlocal", [
        "--transport", "ws+grpc+xhttp", "--port", str(PRIMARY_PORT),
        "--grpc-port", str(GRPC_PORT), "--xhttp-port", str(XHTTP_PORT),
        "--listen", NONLOCAL, "--allow-non-loopback",
    ])
    f.check(nonlocal_multi["result"].rc == 0
            and nonlocal_multi["payload"] is not None,
            "S3 multi accepts an explicit non-loopback listen with the flag",
            nonlocal_multi["result"].text[:300])
    if nonlocal_multi["payload"] is not None:
        nnets = by_network(read_json(nonlocal_multi["out"]))
        f.check(all(ib["listen"] == NONLOCAL for ib in nnets.values()),
                "S3 every added transport follows --listen (Bash parity)",
                json.dumps({k: v["listen"] for k, v in nnets.items()}))
        xray_test(f, xray, nonlocal_multi["out"], "S3 multi non-loopback", observed)
        observed["generated"]["multiNonLoopback"] = {
            k: {"port": v["port"], "listen": v["listen"]} for k, v in nnets.items()}
        multi_cfg = nonlocal_multi["out"]

    conflicts = [
        ("grpc-equals-primary", ["--transport", "ws+grpc+xhttp",
                                 "--grpc-port", str(10086)], "already used"),
        ("xhttp-equals-primary", ["--transport", "ws+grpc+xhttp",
                                  "--xhttp-port", str(10086)], "already used"),
        ("grpc-equals-xhttp", ["--transport", "ws+grpc+xhttp",
                               "--grpc-port", str(GRPC_PORT),
                               "--xhttp-port", str(GRPC_PORT)], "already used"),
        ("xhttp-out-of-range", ["--transport", "ws+grpc+xhttp",
                                "--xhttp-port", "70000"], "between 1 and 65535"),
    ]
    for name, extra, needle in conflicts:
        denied, out, nginx, frags = reject(f, work, name, extra)
        f.check(denied.rc == 2, f"S3 {name} exits 2", f"rc={denied.rc}")
        f.check(needle in denied.text, f"S3 {name} explains the refusal",
                denied.text[-300:])
        assert_zero_write(f, f"S3 {name}", out, nginx, frags)

    raw_denied, out, nginx, frags = reject(
        f, work, "raw", ["--transport", "raw"])
    f.check(raw_denied.rc == 2 and "unsupported transport" in raw_denied.text,
            "S3 raw is not a no-TLS transport", raw_denied.text[-200:])
    assert_zero_write(f, "S3 raw", out, nginx, frags)

    # ---------------------------------------------------- S4 public port view
    public = gen(f, work, "public-port", ["--public-port", "8443"])
    f.check(public["result"].rc == 0 and public["payload"] is not None,
            "S4 --public-port generate succeeds", public["result"].text[:300])
    if public["payload"] is not None:
        p_ib = inbounds(read_json(public["out"]))[0]
        f.check(public["payload"]["publicPort"] == 8443
                and public["payload"]["port"] == 10086,
                "S4 publicPort is separate from the inbound port",
                f"{public['payload']['port']}/{public['payload']['publicPort']}")
        f.check(p_ib["port"] == 10086 and p_ib["listen"] == "127.0.0.1",
                "S4 the runtime inbound is unchanged",
                f"{p_ib['listen']}:{p_ib['port']}")
        p_parts, _ = share_params(public["payload"]["shareUri"])
        f.check(p_parts.port == 8443,
                "S4 share URI uses the public port", str(p_parts.port))
        f.check("    port: 8443" in public["payload"]["clashYaml"],
                "S4 Clash uses the public port", public["payload"]["clashYaml"][:300])
        f.check(not public["nginx"].exists() and not public["fragments"].exists(),
                "S4 no-TLS mode still writes no Nginx artifacts")
        xray_test(f, xray, public["out"], "S4 public port", observed)
        observed["generated"]["publicPort"] = {
            "port": public["payload"]["port"],
            "publicPort": public["payload"]["publicPort"],
        }

    # -------------------------------------------------- S5 overwrite and case
    overwrite_dir = work / "overwrite"
    overwrite_dir.mkdir(parents=True, exist_ok=True)
    existing = overwrite_dir / "config.json"
    existing.write_text("keep\n", encoding="utf-8")
    denied = f.run([
        f.go, "xray", "generate", "--mode", "none", "--uuid", UUID,
        "--out", existing, "--json"], timeout=60)
    f.check(denied.rc == 2, "S5 existing output is refused without --force",
            f"rc={denied.rc}")
    f.check(existing.read_text(encoding="utf-8") == "keep\n",
            "S5 refusal leaves the original bytes untouched")
    forced = f.run([
        f.go, "xray", "generate", "--mode", "none", "--uuid", UUID,
        "--out", existing, "--force", "--json"], timeout=60)
    f.check(forced.rc == 0, "S5 --force overwrites the output", forced.text[:300])
    f.check(read_json(existing)["inbounds"][0]["tag"] == "VLESS-ws-in",
            "S5 forced output is a real config")

    upper = gen(f, work, "upper-transport", ["--transport", "GRPC"])
    f.check(upper["result"].rc == 0 and upper["payload"] is not None
            and upper["payload"]["transport"] == "grpc",
            "S5 transport names are case-insensitive",
            upper["result"].text[:200])

    # ------------------------------------------------------ S6 Bash baseline
    install_sh = f.bash_repo / "install.sh"
    install_text = install_sh.read_text(encoding="utf-8")
    template_path = f.bash_repo / "config/vless_tls.json"
    f.check(template_path.is_file(), "S6 Bash template exists", str(template_path))
    if not template_path.is_file():
        return
    template = read_json(template_path)
    tpl_in = template["inbounds"][0]
    f.check(tpl_in["tag"] == "VLESS-ws-in"
            and tpl_in["port"] == 10086
            and tpl_in["listen"] == "127.0.0.1",
            "S6 template pins VLESS-ws-in on 127.0.0.1:10086",
            f"{tpl_in['tag']} {tpl_in['listen']}:{tpl_in['port']}")
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

    f.check("printf '127.0.0.1'" in functions["ws_backend_listen_default"],
            "S6 Bash defaults the no-TLS listen to loopback")
    valid_fn = functions["is_valid_listen_address"]
    f.check('[[ "${addr}" == *:* ]]' in valid_fn
            and '[[ "${addr}" =~ ^([0-9]{1,3})' in valid_fn
            and "<= 255" in valid_fn,
            "S6 Bash validates IPv4 and IPv6 listen addresses")
    resolve_fn = functions["resolve_ws_backend_listen_addr"]
    f.check("ws_backend_listen_default" in resolve_fn
            and "is_valid_listen_address" in resolve_fn,
            "S6 Bash falls back to loopback for an invalid listen address")
    listen_fn = functions["modify_listen_address"]
    f.check('listen_addr="$(resolve_ws_backend_listen_addr)"' in listen_fn
            and '[[ ${tls_mode} == "None" ]]' in listen_fn,
            "S6 Bash resolves the no-TLS listen address")
    for tag in ("VLESS-ws-in", "VLESS-gRPC-in", "VLESS-xhttp-in"):
        f.check(f'select(.tag == "{tag}")).listen = $addr' in listen_fn,
                f"S6 Bash rewrites {tag} to the resolved listen address")
    ports_fn = functions["modify_inbound_port"]
    f.check('"VLESS-ws-in")).port = $xport' in ports_fn
            and '"VLESS-gRPC-in")).port = $gport' in ports_fn
            and '"VLESS-xhttp-in")).port = $xhttpport' in ports_fn,
            "S6 Bash no-TLS ports come from xport/gport/xhttpport")
    f.check('local listen_addr="${1:-127.0.0.1}"' in functions["add_ws_inbound"]
            and '"tag": "VLESS-ws-in"' in functions["add_ws_inbound"],
            "S6 Bash add_ws_inbound defaults to loopback")
    f.check('local listen_addr="${1:-127.0.0.1}"' in functions["add_grpc_inbound"]
            and '"multiMode": true' in functions["add_grpc_inbound"]
            and '"idle_timeout": 20' in functions["add_grpc_inbound"],
            "S6 Bash gRPC template matches the Go stream settings")
    f.check('local listen_addr="${1:-127.0.0.1}"' in functions["add_xhttp_inbound"]
            and '"mode": "auto"' in functions["add_xhttp_inbound"]
            and 'xhttp_path="/${xhttp_path#/}"' in functions["add_xhttp_inbound"],
            "S6 Bash xHTTP template matches the Go stream settings")
    f.check("transport_only)" in functions["apply_install_profile"]
            and 'tls_mode="None"' in functions["apply_install_profile"],
            "S6 Bash transport_only profile is the no-TLS branch")
    f.check('transport_mode="wsgRPCxhttp"' in functions["transport_choose"],
            "S6 Bash menu 5 is ws+gRPC+xHTTP")

    # Real Bash execution: template copy + extracted functions + jq.
    bash_dir = work / "bash"
    bash_dir.mkdir(parents=True, exist_ok=True)
    stubs = [
        "set -u",
        'log_echo() { :; }',
        'gettext() { printf "%s" "$1"; }',
        'judge() { :; }',
        'Error=""; RedBG=""; Font=""; OK=""; GreenBG=""; Warning=""; YellowBG=""',
        'xray_conf="$WORK/config.json"',
        'xray_install_config_file="$WORK/config.json"',
        'tls_mode="None"',
        'reality_add_nginx="off"',
        'reality_add_more="off"',
        f'xport={WS_PORT}',
        f'gport={GRPC_PORT}',
        f'xhttpport={XHTTP_PORT}',
        'path="ray/"',
        'serviceName="idleleo-grpc"',
        'xhttppath="xhttp"',
        functions["update_json_config"],
        functions["ws_backend_listen_default"],
        functions["is_valid_listen_address"],
        functions["resolve_ws_backend_listen_addr"],
        functions["modify_listen_address"],
        functions["modify_inbound_port"],
        functions["add_ws_inbound"],
        functions["add_grpc_inbound"],
        functions["add_xhttp_inbound"],
        functions["modify_path"],
    ]
    uuid_jq = (f"""jq --arg id "{UUID}" '.inbounds[].settings.clients[].id = $id' """
               f'"$xray_conf" > "$xray_conf.tmp" && mv "$xray_conf.tmp" "$xray_conf"')

    def run_bash(name, extra_lines, ws_backend=None):
        case = bash_dir / name
        case.mkdir(parents=True, exist_ok=True)
        config = case / "config.json"
        shutil.copyfile(template_path, config)
        lines = stubs + extra_lines + [uuid_jq]
        if ws_backend is not None:
            lines.insert(4, f'ws_backend_listen_addr="{ws_backend}"')
        script = case / "run-baseline.sh"
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        env = dict(f.env, WORK=str(case))
        executed = f.run(["bash", str(script)], timeout=90, env=env)
        f.check(executed.rc == 0, f"S6 {name}: extracted Bash functions run for real",
                executed.text[-400:])
        return case, config, script, executed

    single_case, single_cfg, single_script, _ = run_bash("single-ws", [
        "is_ws_mode() { return 0; }",
        "is_grpc_mode() { return 1; }",
        "is_xhttp_mode() { return 1; }",
        "modify_listen_address",
        "modify_inbound_port",
        "modify_path",
    ])
    single = read_json(single_cfg) if single_cfg.is_file() else None
    f.check(single is not None, "S6 single-ws Bash config was produced")
    if single is not None:
        s_ib = inbounds(single)[0]
        f.check(s_ib["listen"] == "127.0.0.1",
                "S6 Bash falls back to loopback when no address is chosen",
                s_ib["listen"])
        f.check(s_ib["port"] == WS_PORT, "S6 Bash applies xport to the ws inbound",
                str(s_ib["port"]))
        f.check(s_ib["streamSettings"]["wsSettings"]["path"] == "/ray/",
                "S6 Bash ws path", s_ib["streamSettings"]["wsSettings"]["path"])
        xray_test(f, xray, single_cfg, "S6 bash single ws", observed)

    multi_lines = [
        "is_ws_mode() { return 0; }",
        "is_grpc_mode() { return 0; }",
        "is_xhttp_mode() { return 0; }",
        'add_grpc_inbound 0.0.0.0 "$gport" "$serviceName"',
        'add_xhttp_inbound 0.0.0.0 "$xhttpport" "$xhttppath"',
        "jq '.inbounds[].listen = \"0.0.0.0\"' \"$xray_conf\" > \"$xray_conf.tmp\" && mv \"$xray_conf.tmp\" \"$xray_conf\"",
        "modify_listen_address",
        "modify_path",
        "modify_inbound_port",
    ]
    loop_case, loop_cfg, _, _ = run_bash("multi-loopback", multi_lines)
    loop = read_json(loop_cfg) if loop_cfg.is_file() else None
    f.check(loop is not None, "S6 multi-loopback Bash config was produced")
    if loop is not None:
        lnets = by_network(loop)
        f.check(set(lnets) == {"ws", "grpc", "xhttp"},
                "S6 Bash baseline has three transports", json.dumps(sorted(lnets)))
        f.check(all(ib["listen"] == "127.0.0.1" for ib in lnets.values()),
                "S6 Bash default multi listens on loopback everywhere",
                json.dumps({k: v["listen"] for k, v in lnets.items()}))
        f.check(lnets["ws"]["port"] == WS_PORT
                and lnets["grpc"]["port"] == GRPC_PORT
                and lnets["xhttp"]["port"] == XHTTP_PORT,
                "S6 Bash applies xport/gport/xhttpport",
                json.dumps({k: v["port"] for k, v in lnets.items()}))
        xray_test(f, xray, loop_cfg, "S6 bash multi loopback", observed)

    nonlocal_case, nonlocal_cfg, nonlocal_script, _ = run_bash(
        "multi-nonloopback", multi_lines, ws_backend=NONLOCAL)
    nonlocal_bash = read_json(nonlocal_cfg) if nonlocal_cfg.is_file() else None
    f.check(nonlocal_bash is not None, "S6 multi-nonloopback Bash config was produced")
    comparison = {}
    if nonlocal_bash is not None:
        nnets = by_network(nonlocal_bash)
        f.check(all(ib["listen"] == NONLOCAL for ib in nnets.values()),
                "S6 Bash rewrites every added transport to the chosen address",
                json.dumps({k: v["listen"] for k, v in nnets.items()}))
        xray_test(f, xray, nonlocal_cfg, "S6 bash multi non-loopback", observed)
        if "multi_cfg" in locals():
            go_nets = by_network(read_json(multi_cfg))
            for net in ("ws", "grpc", "xhttp"):
                comparison[net] = {
                    "go": {"tag": go_nets[net]["tag"],
                           "listen": go_nets[net]["listen"],
                           "port": go_nets[net]["port"],
                           "email": go_nets[net]["settings"]["clients"][0]["email"]},
                    "bash": {"tag": nnets[net]["tag"],
                             "listen": nnets[net]["listen"],
                             "port": nnets[net]["port"],
                             "email": nnets[net]["settings"]["clients"][0]["email"]},
                }
            comparison["ws"]["goStatus"] = (
                "divergent-primary-port: Go ws uses --port, Bash rewrites ws to xport")
            comparison["grpc"]["goStatus"] = "aligned"
            comparison["xhttp"]["goStatus"] = (
                "divergent-trailing-slash: Go /xhttp/ vs Bash /xhttp")
        f.write_json("bash-result.json", {
            "installSha256": hashlib.sha256(install_sh.read_bytes()).hexdigest(),
            "scripts": {
                "single": single_script.read_text(encoding="utf-8"),
                "multiNonLoopback": nonlocal_script.read_text(encoding="utf-8"),
            },
            "configs": {
                "single": str(single_cfg),
                "multiLoopback": str(loop_cfg),
                "multiNonLoopback": str(nonlocal_cfg),
            },
            "compare": comparison,
        })

    baseline = [
        {"contract": "no-TLS default listen address",
         "go": "127.0.0.1", "bash": "127.0.0.1", "goStatus": "aligned"},
        {"contract": "non-loopback listen confirmation",
         "go": "refused unless --allow-non-loopback",
         "bash": "interactive prompt accepts any valid address",
         "goStatus": "divergent-guard: Go refuses by default, Bash only warns"},
        {"contract": "added transports follow the listen address",
         "go": "all three inbounds follow --listen",
         "bash": "modify_listen_address rewrites ws/gRPC/xHTTP",
         "goStatus": "aligned (fixed in this fixture; see xraycfg.go)"},
        {"contract": "listen address format validation",
         "go": "gap: only the loopback rule is checked; not-an-ip is accepted",
         "bash": "is_valid_listen_address validates and falls back to 127.0.0.1",
         "goStatus": "gap"},
        {"contract": "no-TLS default inbound port",
         "go": 10086, "bash": "random 10000-10999 (xHTTP 11000-11999)",
         "goStatus": "divergent-default-port"},
        {"contract": "protocol spelling",
         "go": "vless", "bash": "VLESS", "goStatus": "divergent-naming"},
        {"contract": "ws-port flag in a no-TLS multi topology",
         "go": "ignored: ws is the primary inbound and uses --port",
         "bash": "xport owns the ws port",
         "goStatus": "divergent-flag-semantics"},
        {"contract": "ws default path",
         "go": "/ray/", "bash": "/ray/", "goStatus": "aligned"},
        {"contract": "standalone xHTTP default path",
         "go": "/ray/ (multi uses /xhttp/)",
         "bash": "/xhttp", "goStatus": "divergent-trailing-slash"},
        {"contract": "public port semantics",
         "go": "--public-port changes only the share/Clash port",
         "bash": "no public port in the no-TLS branch",
         "goStatus": "divergent-flag-semantics"},
        {"contract": "combined transport naming",
         "go": "ws+grpc+xhttp", "bash": "menu 5 wsgRPCxhttp",
         "goStatus": "aligned-semantics"},
        {"contract": "Clash for xHTTP",
         "go": "no proxy + clash-xhttp-unsupported",
         "bash": "Clash xHTTP rendering not executed",
         "goStatus": "gap"},
        {"contract": "real no-TLS install",
         "go": "generate-only in this fixture",
         "bash": "install_xray_ws_only writes the config and starts the service",
         "goStatus": "gap: install path not executed in the container"},
        {"contract": "interactive wizard functions",
         "go": "not applicable",
         "bash": "ws_listen_address_choose/transport_choose/apply_install_profile",
         "goStatus": "static: asserted by text only; TTY flow not executed",
         "mode": "static"},
    ]
    f.write_json("baseline-compare.json", {
        "fixture": "F03",
        "date": "2026-11-17",
        "installSha256": hashlib.sha256(install_sh.read_bytes()).hexdigest(),
        "comparisons": baseline,
    })
    f.write_json("observed.json", observed)


if __name__ == "__main__":
    raise SystemExit(run_fixture("F03", main))
