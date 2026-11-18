#!/usr/bin/env python3
"""F04: Reality primary/secondary load-balance executor.

Contract: feature_contracts.json F04. This fixture executes the real Go binary
for `xray generate --mode reality-balance --role primary|secondary`, validates
every valid config with the real `xray -test` and every primary stream config
with the real `nginx -t`, and compares the artifacts against the fixed Bash
baseline functions (`apply_install_profile`, `modify_inbound_port`,
`nginx_reality_conf_add`, `nginx_reality_servers_add`,
`nginx_reality_serverNames_add`, `write_isolate_site_config`) executed for
real.

Evidence level: CONTAINER_VERIFIED. No two-host VPS acceptance, no live Nginx
start, no client data plane. Those are registered as gaps in
baseline-compare.json, not papered over.
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

UUID = "eeeeeeee-4444-4444-8444-444444444444"
SERVER = "example.com"
PORT = 8443
SHORT_ID = "abcd1234"

BASH_FUNCTIONS = (
    "update_json_config",
    "is_ws_mode",
    "is_grpc_mode",
    "is_xhttp_mode",
    "apply_install_profile",
    "modify_inbound_port",
    "is_reality_reserved_port",
    "reality_reserved_port_conflict",
    "validate_reality_reserved_ports",
    "_validate_serverNames_fragment",
    "_cleanup_stale_serverNames_fragments",
    "nginx_reality_servers_add",
    "nginx_reality_serverNames_add",
    "add_sni_guard_http_include",
    "write_isolate_site_config",
    "nginx_reality_conf_add",
    "modify_nginx_port",
    "modify_nginx_other",
)

LOCAL_UPSTREAM = "server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;\n"
ISOLATE_CONF = (
    "# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert\n"
    "server {\n"
    "    listen 127.0.0.1:9403 ssl;\n"
    "    ssl_reject_handshake on;\n"
    "    access_log off;\n"
    "    error_log /dev/null;\n"
    "}\n"
)


def extract_bash_function(text, name):
    """Extract a shell function, skipping heredoc bodies.

    The Nginx generator embeds a heredoc whose server block closes with a
    column-zero `}`, so a plain regex stops too early. Tracking the heredoc
    delimiter is enough because every other closing brace is indented.
    """
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\s*\(\)\s*\{{", line):
            start = index
            break
    if start is None:
        return None
    out = [lines[start]]
    heredoc = None
    for line in lines[start + 1:]:
        if heredoc is not None:
            out.append(line)
            if line.strip() == heredoc:
                heredoc = None
            continue
        match = re.search(r"<<-?\s*'?([A-Za-z_][A-Za-z0-9_]*)'?", line)
        if match and not line.lstrip().startswith("#"):
            heredoc = match.group(1)
        if line == "}":
            out.append(line)
            return "\n".join(out)
        out.append(line)
    return None


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def inbounds(cfg):
    return cfg["inbounds"]


def gen(f, work, name, extra=(), server_names=SERVER):
    case = work / name
    case.mkdir(parents=True, exist_ok=True)
    out = case / "config.json"
    nginx = case / "nginx.conf"
    frags = case / "fragments"
    cmd = [
        f.go, "xray", "generate", "--mode", "reality-balance",
        "--uuid", UUID, "--short-id", SHORT_ID,
        "--out", out, "--nginx-out", nginx, "--fragments-out", frags, "--json",
    ]
    if server_names is not None:
        cmd += ["--server-names", server_names]
    cmd += [str(item) for item in extra]
    result = f.run(cmd, timeout=60)
    payload = None
    if result.rc == 0 and result.out.strip():
        payload = json.loads(result.out)
    return {
        "case": case, "out": out, "nginx": nginx, "fragments": frags,
        "result": result, "payload": payload,
    }


def reject(f, work, name, extra=(), server_names=SERVER):
    case = work / name
    case.mkdir(parents=True, exist_ok=True)
    out = case / "config.json"
    nginx = case / "nginx.conf"
    frags = case / "fragments"
    cmd = [
        f.go, "xray", "generate", "--mode", "reality-balance",
        "--uuid", UUID, "--short-id", SHORT_ID,
        "--out", out, "--nginx-out", nginx, "--fragments-out", frags, "--json",
    ]
    if server_names is not None:
        cmd += ["--server-names", server_names]
    cmd += [str(item) for item in extra]
    result = f.run(cmd, timeout=60)
    return result, out, nginx, frags


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


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fragment_names(frags):
    if not frags.is_dir():
        return []
    return sorted(path.name for path in frags.iterdir() if path.is_file())


def xray_test(f, xray, path, label, observed):
    Path("/var/log/xray").mkdir(parents=True, exist_ok=True)
    result = f.run([xray, "-test", "-config", str(path)], timeout=90)
    observed.setdefault("xrayTest", {})[label] = {
        "rc": result.rc, "config": str(path), "tail": result.text[-200:],
    }
    f.check(result.rc == 0, f"{label}: real xray -test accepts the config",
            result.text[-400:])


def nginx_module(nginx):
    """Return (module_args, adaptation) for the stream module in this Nginx."""
    version = subprocess.run([nginx, "-V"], capture_output=True, text=True)
    text = (version.stdout or "") + (version.stderr or "")
    if re.search(r"--with-stream\s", text) and "=dynamic" not in text:
        return [], "static --with-stream"
    candidates = [
        Path("/usr/lib/nginx/modules/ngx_stream_module.so"),
        Path("/usr/lib64/nginx/modules/ngx_stream_module.so"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return ["load_module {};".format(candidate)], "load_module {}".format(candidate)
    return None, text


def nginx_stream_test(f, conf, frags, label, observed):
    """Validate a generated stream config with the real nginx binary.

    The harness only rewrites the managed install paths to a temporary root and
    loads the stream module when the distro ships it dynamically; the stream
    grammar, includes and deny policy are the generated ones.
    """
    nginx = shutil.which("nginx")
    f.need(nginx is not None, "F04 primary validation requires a real nginx binary")
    module_args, adaptation = nginx_module(nginx)
    f.need(module_args is not None,
           f"cannot load the nginx stream module for {nginx}: {adaptation[-300:]}")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", label)
    root = f.evidence / "f04-work" / "nginx-runs" / safe
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    (root / "conf").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    for item in sorted(Path(frags).iterdir()):
        if item.is_file():
            # Evidence filenames must not contain `:` (artifact upload rule);
            # the generated config includes fragments by glob, so renaming the
            # evidence copy does not change what nginx -t parses.
            shutil.copy2(item, root / "conf" / item.name.replace(":", "_"))
    text = Path(conf).read_text(encoding="utf-8")
    text = text.replace("/etc/idleleo/conf/nginx", str(root / "conf"))
    text = text.replace("/usr/local/nginx/logs", str(root / "logs"))
    (root / "gen.conf").write_text(text, encoding="utf-8")
    http_block = []
    isolate = root / "conf" / "03-isolate.conf"
    if isolate.is_file():
        http_block.append("    include {};".format(isolate))
    main = "\n".join(
        module_args + [
            "worker_processes 1;",
            "pid {}/nginx.pid;".format(root),
            "error_log {}/error.log;".format(root),
            "events {}",
            "include {}/gen.conf;".format(root),
            "http {",
        ] + http_block + ["}", ""]
    )
    (root / "main.conf").write_text(main, encoding="utf-8")
    result = f.run([nginx, "-t", "-c", str(root / "main.conf"), "-p", str(root)],
                   timeout=60)
    observed.setdefault("nginxTest", {})[label] = {
        "rc": result.rc,
        "adaptation": adaptation,
        "rewrites": ["/etc/idleleo/conf/nginx", "/usr/local/nginx/logs"],
        "tail": result.text[-300:],
    }
    f.check(result.rc == 0, f"{label}: real nginx -t accepts the generated stream config",
            result.text[-500:])


def bash_baseline(f, work, observed, go_primary_conf, go_reject_conf,
                  go_primary_config, xray):
    """Execute the fixed install.sh functions and compare the artifacts."""
    repo = f.bash_repo
    text = (repo / "install.sh").read_text(encoding="utf-8")
    missing = [name for name in BASH_FUNCTIONS if extract_bash_function(text, name) is None]
    f.check(not missing, "S6 all required Bash baseline functions were found", str(missing))
    if missing:
        return

    base = work / "bash"
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)
    (base / "conf-isolate" / "nginx").mkdir(parents=True, exist_ok=True)
    (base / "conf-reject" / "nginx").mkdir(parents=True, exist_ok=True)
    (base / "nginx" / "conf").mkdir(parents=True, exist_ok=True)
    (base / "nginx" / "logs").mkdir(parents=True, exist_ok=True)
    (base / "nginx" / "conf" / "nginx.conf").write_text("http {\n}\n", encoding="utf-8")

    template = repo / "config" / "vless_reality.json"
    for role in ("primary", "secondary"):
        target = base / "xray-{}.json".format(role)
        shutil.copy2(template, target)
        # Bash's own install replaces these placeholders (modify_uuid,
        # modify_privateKey_shortIds). Use the valid key Go generated so
        # xray -test measures the port semantics, not the placeholder text.
        prepared = f.run([
            "jq", "--arg", "id", UUID,
            "--arg", "key",
            read_json(go_primary_config)["inbounds"][0]["streamSettings"]
            ["realitySettings"]["privateKey"],
            "--arg", "sid", SHORT_ID,
            '.inbounds[0].settings.clients[0].id = $id |'
            ' .inbounds[0].streamSettings.realitySettings.privateKey = $key |'
            ' .inbounds[0].streamSettings.realitySettings.shortIds = [$sid]',
            target,
        ], timeout=30)
        f.check(prepared.rc == 0, f"S6 {role} template placeholders replaced", prepared.text[-200:])
        if prepared.rc == 0:
            target.write_text(prepared.out, encoding="utf-8")

    script = "\n".join(
        ["set -u",
         "judge(){ :; }",
         "log_echo(){ :; }",
         "gettext(){ printf '%s' \"$1\"; }",
         "sni_guard_port_conflicts(){ return 1; }",
         "OK=\"\"; Error=\"\"; RedBG=\"\"; GreenBG=\"\"; Font=\"\"; Warning=\"\"; YellowBG=\"\"",
         "xray_install_config_file=\"\""]
        + [extract_bash_function(text, name) for name in BASH_FUNCTIONS]
        + [r'''
W=__WORK__
B=$W/bash
install_profile=reality_balance_primary
apply_install_profile; echo "profile-primary-rc=$?"
printf 'primary|%s|%s|%s|%s|%s|%s|%s\n' "$tls_mode" "$reality_add_nginx" "$reality_add_balance" "$reality_add_more" "$transport_mode" "$reality_balance_role" "$shell_mode"
install_profile=reality_balance_secondary
apply_install_profile; echo "profile-secondary-rc=$?"
printf 'secondary|%s|%s|%s|%s|%s|%s|%s\n' "$tls_mode" "$reality_add_nginx" "$reality_add_balance" "$reality_add_more" "$transport_mode" "$reality_balance_role" "$shell_mode"

xray_conf=$B/xray-primary.json
tls_mode=Reality; reality_add_nginx=on; reality_add_balance=on
transport_mode=None; port=8443; xport=""; gport=""; xhttpport=""
modify_inbound_port; echo "port-primary-rc=$?"
xray_conf=$B/xray-secondary.json
tls_mode=Reality; reality_add_nginx=off; reality_add_balance=on
transport_mode=None; port=8443; xport=""; gport=""; xhttpport=""
modify_inbound_port; echo "port-secondary-rc=$?"

nginx_dir=$B/nginx
old_config_status=off
serverNames=example.com
port=8443
tls_mode=Reality
reality_add_nginx=on
reality_add_balance=on
xport=""; gport=""; xhttpport=""
save_originconf=Yes

nginx_conf_dir=$B/conf-isolate/nginx
nginx_conf=$nginx_conf_dir/00-xray.conf
unknown_sni_policy=isolate
nginx_reality_conf_add; echo "conf-isolate-rc=$?"
nginx_reality_servers_add; echo "servers-rc=$?"
nginx_reality_serverNames_add; echo "names-rc=$?"
printf 'garbage line\n' > "$nginx_conf_dir/stale.example.serverNames"
nginx_reality_serverNames_add; echo "names-stale-rc=$?"

nginx_conf_dir=$B/conf-reject/nginx
nginx_conf=$nginx_conf_dir/00-xray.conf
unknown_sni_policy=reject
nginx_reality_conf_add; echo "conf-reject-rc=$?"
nginx_reality_servers_add; echo "servers-reject-rc=$?"
nginx_reality_serverNames_add; echo "names-reject-rc=$?"
'''.replace("__WORK__", str(work))])
    script_path = work / "bash-baseline.sh"
    script_path.write_text(script, encoding="utf-8")
    result = f.run(["bash", script_path], timeout=60)
    result_record = {"script": str(script_path), "rc": result.rc, "output": result.text}
    (f.evidence / "bash-result.json").write_text(
        json.dumps(result_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    f.check(result.rc == 0, "S6 Bash baseline script completed", result.text[-800:])

    markers = dict(re.findall(r"^([a-z-]+)-rc=(\d+)$", result.out, re.MULTILINE))
    for marker in ("profile-primary", "profile-secondary", "port-primary",
                   "port-secondary", "conf-isolate", "servers", "names",
                   "names-stale", "conf-reject", "servers-reject",
                   "names-reject"):
        f.check(markers.get(marker) == "0", f"S6 Bash {marker} rc=0",
                markers.get(marker, "missing"))

    profile_lines = dict(
        (line.split("|", 1)[0], line.split("|")[1:])
        for line in result.out.splitlines() if "|" in line and not line.startswith("$")
    )
    primary = profile_lines.get("primary") or []
    secondary = profile_lines.get("secondary") or []
    f.check(primary == ["Reality", "on", "on", "off", "None", "primary",
                        "Nginx+Reality+Balance"],
            "S6 Bash primary profile sets Nginx+Reality+Balance", str(primary))
    f.check(secondary == ["Reality", "off", "on", "off", "None", "secondary",
                          "Reality+Balance"],
            "S6 Bash secondary profile has no Nginx front", str(secondary))

    bash_primary_cfg = read_json(base / "xray-primary.json")
    bash_secondary_cfg = read_json(base / "xray-secondary.json")
    bash_primary_in = inbounds(bash_primary_cfg)[0]
    bash_secondary_in = inbounds(bash_secondary_cfg)[0]
    f.check(bash_primary_in["port"] == 9443 and bash_primary_in["listen"] == "0.0.0.0",
            "S6 Bash primary keeps the 9443/0.0.0.0 backend",
            f"{bash_primary_in['port']}/{bash_primary_in['listen']}")
    f.check(bash_secondary_in["port"] == PORT and bash_secondary_in["listen"] == "0.0.0.0",
            "S6 Bash secondary writes the operator port and keeps 0.0.0.0",
            f"{bash_secondary_in['port']}/{bash_secondary_in['listen']}")
    xray_test(f, xray, base / "xray-primary.json", "S6 bash primary template", observed)
    xray_test(f, xray, base / "xray-secondary.json", "S6 bash secondary template", observed)

    isolate_cfg = base / "conf-isolate" / "nginx"
    reject_cfg = base / "conf-reject" / "nginx"
    f.check((isolate_cfg / "127.0.0.1.realityServers").read_text(encoding="utf-8")
            == LOCAL_UPSTREAM,
            "S6 Bash local realityServers line matches Go byte for byte")
    f.check((isolate_cfg / "example.com.serverNames").read_text(encoding="utf-8")
            == f"{SERVER} reality;\n",
            "S6 Bash serverNames fragment matches Go byte for byte")
    f.check(not (isolate_cfg / "stale.example.serverNames").exists(),
            "S6 Bash removes the corrupt stale serverNames fragment")
    f.check((isolate_cfg / "03-isolate.conf").read_text(encoding="utf-8") == ISOLATE_CONF,
            "S6 Bash isolate site matches the Go fragment byte for byte")
    http_text = (base / "nginx" / "conf" / "nginx.conf").read_text(encoding="utf-8")
    f.check("include {}/03-isolate.conf;".format(isolate_cfg) in http_text,
            "S6 Bash inserts the isolate include into the http block")

    def canonical(path):
        text = Path(path).read_text(encoding="utf-8")
        return (text.replace(str(Path(path).parent), "/etc/idleleo/conf/nginx")
                    .replace(str(base / "nginx" / "logs"), "/usr/local/nginx/logs"))

    bash_stream = canonical(isolate_cfg / "00-xray.conf")
    f.check(bash_stream == Path(go_primary_conf).read_text(encoding="utf-8"),
            "S6 Bash isolate stream config equals the Go primary config byte for byte")
    bash_reject = canonical(reject_cfg / "00-xray.conf")
    f.check(bash_reject == Path(go_reject_conf).read_text(encoding="utf-8"),
            "S6 Bash reject stream config equals the Go reject config byte for byte")

    nginx_stream_test(f, isolate_cfg / "00-xray.conf", isolate_cfg,
                      "S6 bash isolate", observed)
    nginx_stream_test(f, reject_cfg / "00-xray.conf", reject_cfg,
                      "S6 bash reject", observed)

    observed["bash"] = {
        "markers": markers,
        "profiles": {"primary": primary, "secondary": secondary},
        "primaryPort": bash_primary_in["port"],
        "secondaryPort": bash_secondary_in["port"],
        "isolateSha256": sha256(isolate_cfg / "00-xray.conf"),
        "rejectSha256": sha256(reject_cfg / "00-xray.conf"),
        "goPrimarySha256": sha256(go_primary_conf),
        "goRejectSha256": sha256(go_reject_conf),
    }

    f.write_json("baseline-compare.json", {
        "entries": [
            {"contract": "role_to_artifact_set", "status": "aligned",
             "go": "primary keeps the Nginx stream front; secondary writes only the Xray config",
             "bash": "apply_install_profile: primary Nginx+Reality+Balance, secondary Reality+Balance",
             "evidence": "S1/S2/S6 profiles"},
            {"contract": "primary_backend_port", "status": "aligned",
             "go": "inbound 9443, public front 8443",
             "bash": "template 9443 and modify_inbound_port leaves it untouched when add_nginx=on",
             "evidence": "S1/S6"},
            {"contract": "secondary_inbound_port", "status": "aligned",
             "go": "inbound equals --port",
             "bash": "modify_inbound_port writes --port when add_nginx=off",
             "evidence": "S2/S6"},
            {"contract": "listen_address", "status": "aligned",
             "go": "0.0.0.0 for both roles",
             "bash": "template 0.0.0.0; modify_reality_listen_address only runs when add_balance=off",
             "evidence": "S1/S2/S6"},
            {"contract": "single_server_name", "status": "aligned",
             "go": "exactly one server name",
             "bash": "_validate_serverNames_hostname accepts one hostname",
             "evidence": "S5 static"},
            {"contract": "reserved_ports", "status": "aligned",
             "go": "9403/9404/9443/9444 refused for --port and for a Nginx public port",
             "bash": "validate_reality_reserved_ports refuses the same set",
             "evidence": "S5/S6 static"},
            {"contract": "local_upstream_line", "status": "aligned",
             "go": LOCAL_UPSTREAM.strip(),
             "bash": LOCAL_UPSTREAM.strip(), "evidence": "S1/S6"},
            {"contract": "server_names_line", "status": "aligned",
             "go": f"{SERVER} reality;", "bash": f"{SERVER} reality;",
             "evidence": "S1/S6"},
            {"contract": "stream_config", "status": "aligned",
             "go": "nginx.conf byte-identical after canonicalising the temporary bash paths",
             "bash": "00-xray.conf", "evidence": "S6 sha256"},
            {"contract": "isolate_site", "status": "aligned-by-deploy-path",
             "go": "03-isolate.conf fragment; the http include is owned by internal/nginx/install.go",
             "bash": "write_isolate_site_config writes the file and add_sni_guard_http_include edits nginx.conf",
             "evidence": "S6 http include assertion"},
            {"contract": "decoy_policy", "status": "gap",
             "go": "rc=2, the Go generator refuses decoy",
             "bash": "sni_guard_policy_choose can build a self-signed decoy site",
             "evidence": "S3 decoy rejection"},
            {"contract": "stale_server_names_self_heal", "status": "gap",
             "go": "generate does not clean stale fragments",
             "bash": "_cleanup_stale_serverNames_fragments deletes corrupt fragments",
             "evidence": "S6 names-stale"},
            {"contract": "public_port_reserved_conflict", "status": "fixed-in-go",
             "go": "reserved --public-port refused for balance primary and reality-nginx",
             "bash": "no separate public port; the front port passes the reserved check",
             "evidence": "S5 + TestGenerateRejectsReservedPublicPort"},
            {"contract": "two_host_data_plane", "status": "gap",
             "go": "not executed", "bash": "not executed",
             "evidence": "CONTAINER_VERIFIED only"},
            {"contract": "service_install_start", "status": "gap",
             "go": "generate only; no Nginx/Xray service start",
             "bash": "install path not executed",
             "evidence": "out of F04 generate scope"},
            {"contract": "firewall_acl", "status": "out-of-scope",
             "go": "not part of generate", "bash": "install wizard manages the firewall",
             "evidence": "not asserted"},
        ],
        "notes": [
            "nginx -t rewrites the managed paths to a temporary root and loads "
            "ngx_stream_module.so when nginx ships it dynamically; this is a "
            "harness adaptation, not a claim about the real install paths.",
            "Bash configs were prepared with the Go-generated valid Reality key "
            "because config/vless_reality.json ships placeholders that Bash "
            "replaces through modify_uuid/modify_privateKey_shortIds.",
        ],
    })


def main(f):
    f.need(f.bash_repo is not None,
           "F04 requires --bash-repo for the fixed Reality balance baseline")
    f.need_root()
    f.need_tool("jq")
    xray = f.xray_bin()

    # Generated artifacts carry host-named files (an IPv6 backend becomes
    # `2001:db8::2.realityServers`), which the artifact uploader rejects. Keep
    # the scratch tree out of the evidence directory; only the JSON reports
    # below are evidence.
    work = Path(tempfile.mkdtemp(prefix="f04-work-"))
    observed = {"generated": {}, "rejections": {}, "environment": {}}
    version = f.run([xray, "version"], timeout=20)
    observed["environment"] = {
        "xray": version.text.splitlines()[0] if version.text else "",
        "nginx": (f.run(["nginx", "-v"], timeout=20).text or "").strip()
        if shutil.which("nginx") else "absent",
    }

    # --------------------------------------------------- S1 primary default
    primary = gen(f, work, "primary-default",
                  ["--role", "primary", "--port", PORT])
    f.check(primary["result"].rc == 0 and primary["out"].is_file(),
            "S1 primary generate rc=0 and wrote the config", primary["result"].text[:300])
    if primary["payload"] is None:
        return
    payload = primary["payload"]
    cfg = read_json(primary["out"])
    f.check(payload["mode"] == "reality-balance" and payload["transport"] == "raw",
            "S1 payload mode/transport", f"{payload['mode']}/{payload['transport']}")
    f.check(payload["balanceRole"] == "primary", "S1 payload balance role",
            payload["balanceRole"])
    f.check(payload["port"] == 9443 and payload["publicPort"] == PORT,
            "S1 primary ports are backend 9443 / front 8443",
            f"{payload['port']}/{payload['publicPort']}")
    f.check(payload["listen"] == "0.0.0.0", "S1 payload listen is 0.0.0.0",
            payload["listen"])
    f.check(payload["serverName"] == SERVER and payload["target"] == f"{SERVER}:443",
            "S1 serverName and default target", f"{payload['serverName']}/{payload['target']}")
    f.check(payload["warnings"] == [], "S1 a balanced primary reports no warnings",
            str(payload["warnings"]))
    f.check(oct(primary["out"].stat().st_mode & 0o777) == "0o600",
            "S1 runtime config is 0600", oct(primary["out"].stat().st_mode & 0o777))
    f.check(len(inbounds(cfg)) == 1, "S1 exactly one backend inbound",
            str(len(inbounds(cfg))))
    inbound = inbounds(cfg)[0]
    f.check(inbound["tag"] == "VLESS-Reality-in" and inbound["protocol"] == "vless",
            "S1 backend tag/protocol", f"{inbound['tag']}/{inbound['protocol']}")
    f.check(inbound["port"] == 9443 and inbound["listen"] == "0.0.0.0",
            "S1 backend listens on 9443/0.0.0.0",
            f"{inbound['port']}/{inbound['listen']}")
    stream = inbound["streamSettings"]
    f.check(stream["network"] == "raw" and stream["security"] == "reality",
            "S1 raw Reality backend", f"{stream['network']}/{stream['security']}")
    reality = stream["realitySettings"]
    f.check(reality["target"] == f"{SERVER}:443"
            and reality["serverNames"] == [SERVER]
            and reality["shortIds"] == [SHORT_ID],
            "S1 Reality target/serverNames/shortIds",
            json.dumps({k: reality[k] for k in ("target", "serverNames", "shortIds")}))
    client = inbound["settings"]["clients"][0]
    f.check(client["id"] == UUID and client["flow"] == "xtls-rprx-vision",
            "S1 client UUID/flow", f"{client['id']}/{client['flow']}")
    f.check(cfg["routing"]["rules"][0]["inboundTag"] == ["VLESS-Reality-in"],
            "S1 routing targets the Reality inbound")

    parts, params = share_params(payload["shareUri"])
    f.check(parts.scheme == "vless" and parts.hostname == SERVER and parts.port == PORT,
            "S1 share URI uses the server name and the public port",
            f"{parts.scheme}/{parts.hostname}/{parts.port}")
    f.check(one(params, "security") == "reality" and one(params, "sni") == SERVER,
            "S1 share security/sni", f"{one(params, 'security')}/{one(params, 'sni')}")
    f.check(one(params, "flow") == "xtls-rprx-vision"
            and one(params, "sid") == SHORT_ID and one(params, "type") == "raw",
            "S1 share flow/sid/type",
            f"{one(params, 'flow')}/{one(params, 'sid')}/{one(params, 'type')}")
    f.check(one(params, "pbk") == payload["publicKey"] and one(params, "pbk") != "",
            "S1 share carries the generated public key")
    f.check(parts.fragment == "idleleo-reality-balance",
            "S1 share fragment names the mode", parts.fragment)

    clash = payload["clashYaml"]
    for needle in ("type: vless", f"server: {SERVER}", f"port: {PORT}",
                   "network: tcp", "tls: true", f"servername: {SERVER}",
                   "flow: xtls-rprx-vision", "client-fingerprint: chrome",
                   "reality-opts:", f"public-key: {payload['publicKey']}",
                   f"short-id: {SHORT_ID}"):
        f.check(needle in clash, f"S1 Clash contains {needle}", clash[:400])

    conf = primary["nginx"].read_text(encoding="utf-8")
    for needle in ("stream {", "map $ssl_preread_protocol $is_valid_protocol {",
                   "include /etc/idleleo/conf/nginx/*.serverNames;",
                   "include /etc/idleleo/conf/nginx/*.realityServers;",
                   "default deny;", "upstream reality {",
                   "server 127.0.0.1:9403;", "ssl_preread on;",
                   f"listen {PORT} reuseport so_keepalive=on backlog=65535;",
                   "/usr/local/nginx/logs/tls_error.log",
                   "/usr/local/nginx/logs/sni_error.log"):
        f.check(needle in conf, f"S1 stream config contains {needle}", conf[:500])
    f.check("upstream deny {\n        server 127.0.0.1:9403;" in conf,
            "S1 isolate deny upstream is 9403")

    names = fragment_names(primary["fragments"])
    f.check(names == ["03-isolate.conf", "127.0.0.1.realityServers", "example.com.serverNames"],
            "S1 primary writes exactly the isolate fragment set", str(names))
    f.check((primary["fragments"] / "127.0.0.1.realityServers").read_text(encoding="utf-8")
            == LOCAL_UPSTREAM, "S1 local upstream line is byte exact")
    f.check((primary["fragments"] / "example.com.serverNames").read_text(encoding="utf-8")
            == f"{SERVER} reality;\n", "S1 serverNames line is byte exact")
    f.check((primary["fragments"] / "03-isolate.conf").read_text(encoding="utf-8")
            == ISOLATE_CONF, "S1 isolate site is byte exact")
    for name in names:
        mode = oct((primary["fragments"] / name).stat().st_mode & 0o777)
        f.check(mode == "0o644", f"S1 fragment {name} is 0644", mode)
    xray_test(f, xray, primary["out"], "S1 primary config", observed)
    nginx_stream_test(f, primary["nginx"], primary["fragments"], "S1 primary", observed)

    observed["generated"]["primary"] = {
        "ports": [payload["port"], payload["publicPort"]],
        "listen": payload["listen"],
        "fragments": names,
        "nginxSha256": sha256(primary["nginx"]),
        "share": payload["shareUri"],
    }

    # ------------------------------------------------------ S2 secondary
    secondary = gen(f, work, "secondary-default",
                    ["--role", "secondary", "--port", PORT])
    f.check(secondary["result"].rc == 0 and secondary["payload"] is not None,
            "S2 secondary generate rc=0", secondary["result"].text[:300])
    if secondary["payload"] is not None:
        secondary_payload = secondary["payload"]
        secondary_in = inbounds(read_json(secondary["out"]))[0]
        f.check(secondary_payload["port"] == PORT
                and secondary_payload["publicPort"] == PORT,
                "S2 secondary reports the operator port as inbound and public",
                f"{secondary_payload['port']}/{secondary_payload['publicPort']}")
        f.check(secondary_in["port"] == PORT and secondary_in["listen"] == "0.0.0.0",
                "S2 secondary inbound is <port>/0.0.0.0",
                f"{secondary_in['port']}/{secondary_in['listen']}")
        f.check(secondary_in["streamSettings"]["security"] == "reality",
                "S2 secondary keeps the Reality backend")
        parts, params = share_params(secondary_payload["shareUri"])
        f.check(parts.port == PORT and one(params, "security") == "reality",
                "S2 secondary share URI points at the same public port",
                f"{parts.port}/{one(params, 'security')}")
        f.check(not secondary["nginx"].exists() and not secondary["fragments"].exists(),
                "S2 secondary writes no Nginx artifacts",
                f"{secondary['nginx'].exists()}/{secondary['fragments'].exists()}")
        xray_test(f, xray, secondary["out"], "S2 secondary config", observed)
        observed["generated"]["secondary"] = {
            "port": secondary_payload["port"], "listen": secondary_payload["listen"],
            "nginx": False, "share": secondary_payload["shareUri"],
        }

    denied, out, nginx, frags = reject(
        f, work, "secondary-backend",
        ["--role", "secondary", "--port", PORT, "--backend", "10.0.0.2:9443"])
    f.check(denied.rc == 2 and "--backend is primary only" in denied.text,
            "S2 secondary refuses --backend", f"rc={denied.rc} {denied.text[-300:]}")
    assert_zero_write(f, "S2 secondary backend", out, nginx, frags)
    observed["rejections"]["secondary-backend"] = denied.text[-300:]

    # ------------------------------------------------------ S3 SNI policy
    rejected = gen(f, work, "primary-reject",
                   ["--role", "primary", "--port", PORT,
                    "--unknown-sni-policy", "reject"])
    f.check(rejected["result"].rc == 0 and rejected["payload"] is not None,
            "S3 reject policy generates", rejected["result"].text[:300])
    if rejected["payload"] is not None:
        reject_conf = rejected["nginx"].read_text(encoding="utf-8")
        f.check("upstream deny {\n        server 127.0.0.1:9404;" in reject_conf,
                "S3 reject policy points the deny upstream at 9404")
        names = fragment_names(rejected["fragments"])
        f.check(names == ["127.0.0.1.realityServers", "example.com.serverNames"],
                "S3 reject policy writes no isolate site", str(names))
        xray_test(f, xray, rejected["out"], "S3 reject config", observed)
        nginx_stream_test(f, rejected["nginx"], rejected["fragments"],
                          "S3 reject", observed)
        observed["generated"]["reject"] = {
            "fragments": names, "nginxSha256": sha256(rejected["nginx"]),
        }

    decoy, out, nginx, frags = reject(
        f, work, "primary-decoy",
        ["--role", "primary", "--port", PORT, "--unknown-sni-policy", "decoy"])
    f.check(decoy.rc == 2 and "decoy" in decoy.text,
            "S3 decoy is refused with an explicit message",
            f"rc={decoy.rc} {decoy.text[-300:]}")
    assert_zero_write(f, "S3 decoy", out, nginx, frags)
    observed["rejections"]["decoy"] = decoy.text[-300:]

    bogus, out, nginx, frags = reject(
        f, work, "primary-bogus-policy",
        ["--role", "primary", "--port", PORT, "--unknown-sni-policy", "bogus"])
    f.check(bogus.rc == 2, "S3 unknown SNI policy exits 2",
            f"rc={bogus.rc} {bogus.text[-300:]}")
    assert_zero_write(f, "S3 bogus policy", out, nginx, frags)

    # ------------------------------------------------------ S4 backends
    backends = gen(f, work, "primary-backends",
                   ["--role", "primary", "--port", PORT,
                    "--backend", "10.0.0.2:9443",
                    "--backend", "10.0.0.3:9443"])
    f.check(backends["result"].rc == 0 and backends["payload"] is not None,
            "S4 two backends generate", backends["result"].text[:300])
    if backends["payload"] is not None:
        names = fragment_names(backends["fragments"])
        f.check(names == ["03-isolate.conf", "10.0.0.2.realityServers",
                          "10.0.0.3.realityServers",
                          "127.0.0.1.realityServers", "example.com.serverNames"],
                "S4 each backend gets its own fragment file", str(names))
        f.check((backends["fragments"] / "10.0.0.2.realityServers").read_text(encoding="utf-8")
                == "server 10.0.0.2:9443 weight=50 max_fails=2 fail_timeout=10;\n",
                "S4 IPv4 backend line is byte exact")
        f.check((backends["fragments"] / "10.0.0.3.realityServers").read_text(encoding="utf-8")
                == "server 10.0.0.3:9443 weight=50 max_fails=2 fail_timeout=10;\n",
                "S4 second backend line is byte exact")
        f.check((backends["fragments"] / "127.0.0.1.realityServers")
                .read_text(encoding="utf-8") == LOCAL_UPSTREAM,
                "S4 local backend line is preserved")
        xray_test(f, xray, backends["out"], "S4 backends config", observed)
        nginx_stream_test(f, backends["nginx"], backends["fragments"],
                          "S4 backends", observed)
        observed["generated"]["backends"] = {"fragments": names}

    dns_backend = gen(f, work, "primary-dns-backend",
                      ["--role", "primary", "--port", PORT,
                       "--backend", "backend.example.net:9443"])
    f.check(dns_backend["result"].rc == 0 and dns_backend["payload"] is not None,
            "S4 DNS backend generates", dns_backend["result"].text[:300])
    if dns_backend["payload"] is not None:
        dns_file = dns_backend["fragments"] / "backend.example.net.realityServers"
        f.check(dns_file.is_file(), "S4 DNS backend fragment is named by host",
                str(fragment_names(dns_backend["fragments"])))
        if dns_file.is_file():
            f.check(dns_file.read_text(encoding="utf-8")
                    == "server backend.example.net:9443 weight=50 "
                       "max_fails=2 fail_timeout=10;\n",
                    "S4 DNS backend line is byte exact")
        # A DNS name cannot be resolved inside the isolated container, so the
        # nginx -t assertion uses literal addresses; the fragment shape above
        # is still verified byte for byte.

    duplicate = gen(f, work, "primary-duplicate-backend",
                    ["--role", "primary", "--port", PORT,
                     "--backend", "10.0.0.2:9443",
                     "--backend", "10.0.0.2:9443"])
    f.check(duplicate["result"].rc == 0 and duplicate["payload"] is not None,
            "S4 identical duplicate backend is accepted", duplicate["result"].text[:300])
    if duplicate["payload"] is not None:
        f.check(fragment_names(duplicate["fragments"])
                == ["03-isolate.conf", "10.0.0.2.realityServers",
                    "127.0.0.1.realityServers", "example.com.serverNames"],
                "S4 identical duplicate is deduplicated",
                str(fragment_names(duplicate["fragments"])))

    loopback = gen(f, work, "primary-loopback-backend",
                   ["--role", "primary", "--port", PORT,
                    "--backend", "127.0.0.1:9443"])
    f.check(loopback["result"].rc == 0 and loopback["payload"] is not None,
            "S4 explicit local backend is accepted", loopback["result"].text[:300])
    if loopback["payload"] is not None:
        f.check(fragment_names(loopback["fragments"])
                == ["03-isolate.conf", "127.0.0.1.realityServers",
                    "example.com.serverNames"],
                "S4 explicit local backend does not add a second file",
                str(fragment_names(loopback["fragments"])))

    ipv6 = gen(f, work, "primary-ipv6-backend",
               ["--role", "primary", "--port", PORT,
                "--backend", "[2001:db8::2]:9443"])
    f.check(ipv6["result"].rc == 0 and ipv6["payload"] is not None,
            "S4 IPv6 backend is accepted", ipv6["result"].text[:300])
    if ipv6["payload"] is not None:
        ipv6_file = ipv6["fragments"] / "2001:db8::2.realityServers"
        f.check(ipv6_file.is_file(), "S4 IPv6 backend fragment is named by host",
                str(fragment_names(ipv6["fragments"])))
        if ipv6_file.is_file():
            f.check(ipv6_file.read_text(encoding="utf-8")
                    == "server [2001:db8::2]:9443 weight=50 max_fails=2 fail_timeout=10;\n",
                    "S4 IPv6 backend line keeps the brackets")
        nginx_stream_test(f, ipv6["nginx"], ipv6["fragments"], "S4 ipv6", observed)

    bad_backends = [
        ("same-host-two-ports", ["--backend", "10.0.0.2:9443",
                                 "--backend", "10.0.0.2:9444"]),
        ("missing-port", ["--backend", "10.0.0.2"]),
        ("zero-port", ["--backend", "10.0.0.2:0"]),
        ("high-port", ["--backend", "10.0.0.2:70000"]),
        ("slash-host", ["--backend", "bad/host:9443"]),
        ("double-dot-host", ["--backend", "a..b:9443"]),
        ("space-host", ["--backend", "bad host:9443"]),
    ]
    for label, extra in bad_backends:
        result, out, nginx, frags = reject(
            f, work, f"backend-{label}", ["--role", "primary", "--port", PORT] + extra)
        f.check(result.rc == 2, f"S4 invalid backend {label} exits 2",
                f"rc={result.rc} {result.text[-200:]}")
        assert_zero_write(f, f"S4 invalid backend {label}", out, nginx, frags)

    # ------------------------------------------- S5 roles/defaults/guards
    default_primary = gen(f, work, "primary-default-port", ["--role", "primary"])
    if default_primary["payload"] is not None:
        f.check(default_primary["payload"]["port"] == 9443
                and default_primary["payload"]["publicPort"] == 443,
                "S5 primary defaults to front 443 / backend 9443",
                f"{default_primary['payload']['port']}/{default_primary['payload']['publicPort']}")
        f.check(f"listen 443 reuseport so_keepalive=on backlog=65535;"
                in default_primary["nginx"].read_text(encoding="utf-8"),
                "S5 primary default stream listens on 443")
    default_secondary = gen(f, work, "secondary-default-port", ["--role", "secondary"])
    if default_secondary["payload"] is not None:
        f.check(default_secondary["payload"]["port"] == 443
                and default_secondary["payload"]["publicPort"] == 443,
                "S5 secondary defaults to 443",
                f"{default_secondary['payload']['port']}/{default_secondary['payload']['publicPort']}")

    missing_role, out, nginx, frags = reject(f, work, "missing-role", ["--port", PORT])
    f.check(missing_role.rc == 2 and "requires --role" in missing_role.text,
            "S5 missing role exits 2", f"rc={missing_role.rc} {missing_role.text[-300:]}")
    assert_zero_write(f, "S5 missing role", out, nginx, frags)
    bogus_role, out, nginx, frags = reject(f, work, "bogus-role",
                                           ["--role", "bogus", "--port", PORT])
    f.check(bogus_role.rc == 2 and "requires --role" in bogus_role.text,
            "S5 invalid role exits 2", f"rc={bogus_role.rc} {bogus_role.text[-300:]}")
    assert_zero_write(f, "S5 bogus role", out, nginx, frags)

    for reserved in (9403, 9404, 9443, 9444):
        blocked, out, nginx, frags = reject(
            f, work, f"port-{reserved}", ["--role", "primary", "--port", str(reserved)])
        f.check(blocked.rc == 2 and "reserved for Reality internals" in blocked.text,
                f"S5 --port {reserved} is refused",
                f"rc={blocked.rc} {blocked.text[-200:]}")
        assert_zero_write(f, f"S5 reserved port {reserved}", out, nginx, frags)

    for reserved in (9443, 9403):
        blocked, out, nginx, frags = reject(
            f, work, f"public-port-{reserved}",
            ["--role", "primary", "--port", PORT, "--public-port", str(reserved)])
        f.check(blocked.rc == 2 and "public port" in blocked.text,
                f"S5 public port {reserved} is refused for a primary front",
                f"rc={blocked.rc} {blocked.text[-250:]}")
        assert_zero_write(f, f"S5 reserved public port {reserved}", out, nginx, frags)

    base_dir = work / "reality-nginx-public"
    base_dir.mkdir(parents=True, exist_ok=True)
    rn = f.run([
        f.go, "xray", "generate", "--mode", "reality-nginx",
        "--domain", SERVER, "--port", PORT, "--public-port", "9443",
        "--out", base_dir / "config.json", "--nginx-out", base_dir / "nginx.conf",
        "--json",
    ], timeout=60)
    f.check(rn.rc == 2 and "public port" in rn.text,
            "S5 reality-nginx also refuses a reserved public port",
            f"rc={rn.rc} {rn.text[-250:]}")
    f.check(not (base_dir / "config.json").exists()
            and not (base_dir / "nginx.conf").exists(),
            "S5 rejected reality-nginx public port writes nothing")

    normal_public = gen(f, work, "primary-public-port",
                        ["--role", "primary", "--port", PORT, "--public-port", "8444"])
    f.check(normal_public["result"].rc == 0 and normal_public["payload"] is not None,
            "S5 a normal public port is accepted", normal_public["result"].text[:300])
    if normal_public["payload"] is not None:
        f.check(normal_public["payload"]["port"] == 9443
                and normal_public["payload"]["publicPort"] == 8444,
                "S5 parse-public-port keeps backend 9443 and front 8444",
                f"{normal_public['payload']['port']}/{normal_public['payload']['publicPort']}")
        nginx_stream_test(f, normal_public["nginx"], normal_public["fragments"],
                          "S5 public port", observed)

    secondary_public = gen(f, work, "secondary-public-port",
                           ["--role", "secondary", "--port", PORT,
                            "--public-port", "9443"])
    f.check(secondary_public["result"].rc == 0
            and secondary_public["payload"] is not None,
            "S5 secondary --public-port only shapes the client view",
            secondary_public["result"].text[:300])
    if secondary_public["payload"] is not None:
        f.check(secondary_public["payload"]["port"] == PORT
                and secondary_public["payload"]["publicPort"] == 9443,
                "S5 secondary inbound stays 8443 while the share port is 9443",
                f"{secondary_public['payload']['port']}/{secondary_public['payload']['publicPort']}")

    for transport in ("ws", "grpc", "xhttp", "ws+grpc+xhttp"):
        blocked, out, nginx, frags = reject(
            f, work, "transport-" + transport.replace("+", "-"),
            ["--role", "primary", "--port", PORT, "--transport", transport])
        f.check(blocked.rc == 2 and "does not support transport" in blocked.text,
                f"S5 balance refuses transport {transport}",
                f"rc={blocked.rc} {blocked.text[-200:]}")
        assert_zero_write(f, f"S5 transport {transport}", out, nginx, frags)

    two_names, out, nginx, frags = reject(
        f, work, "two-server-names",
        ["--role", "primary", "--port", PORT], server_names="a.com,b.com")
    f.check(two_names.rc == 2 and "exactly one" in two_names.text,
            "S5 two server names are refused",
            f"rc={two_names.rc} {two_names.text[-250:]}")
    assert_zero_write(f, "S5 two server names", out, nginx, frags)

    # ------------------------------------------------ S6 Bash baseline
    bash_baseline(f, work, observed, primary["nginx"], rejected["nginx"],
                  primary["out"], xray)

    f.write_json("observed.json", observed)


if __name__ == "__main__":
    raise SystemExit(run_fixture("F04", main))
