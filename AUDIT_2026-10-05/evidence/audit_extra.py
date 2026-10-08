import ast,collections,json,pathlib,re,subprocess,sys,tempfile
from audit_tools import BASE,REPOS,shell,posix
results=[]
cf=REPOS/'luci-app-cloudflare-ip'
fixture=BASE/'work/empty-tls.yaml'
fixture.write_text('proxies:\n  - name: sample\n    type: vless\n    server: example.com\n    network: ws\n    ws-opts:\n      headers:\n        Host: example.com\n',encoding='utf-8')
script=cf/'package/luci-app-cloudflare-ip/root/usr/libexec/cf-ip/openclash-readback.sh'
r=shell(f'''source '{posix(script)}'; while IFS=$'\\t' read -r name type server tls network servername host; do printf 'CFI-06 parsed tls=%s network=%s servername=%s host=%s\\n' "$tls" "$network" "$servername" "$host"; cfip_openclash_protocol_supported "$type" "$tls" "$network"; printf 'CFI-06 eligibility rc=%s\\n' "$?"; done < <(cfip_openclash_mapping_tsv '{posix(fixture)}')''',cf)
print(r.stdout+r.stderr)
manifest=BASE/'work/noneligible.json';manifest.write_text(json.dumps({'schemaVersion':1,'commit':'a'*40,'releaseEligible':False,'qualificationState':'failed'}))
r=subprocess.run([sys.executable,str(cf/'scripts/validate-qualification-evidence.py'),str(manifest),'--commit','a'*40,'--require-assets','2'],capture_output=True,text=True)
print('CFI-04 release validation rc=',r.returncode,r.stdout.strip())
text=(REPOS/'Xray_bash_onekey/scripts/geo_update.sh').read_text(encoding='utf-8')
function=re.search(r'^download_geo_file\(\) \{.*?^\}',text,re.M|re.S).group()
r=shell(function+'''\ncurl() { return 0; }; mv() { return 1; }; geo_dir='''+posix(BASE/'work')+'''; geo_remote=https://example.com; log_file=/dev/null; download_geo_file audit-nonempty; printf 'XRA-06 move failure function rc=%s\\n' "$?"''',BASE)
# The nonempty downloaded candidate is a controlled fixture.
if 'Downloaded' in r.stdout+r.stderr or 'rc=1' in r.stdout:
    file=BASE/'work'/f'audit-nonempty.tmp';
    command=function+f'''\ncurl() {{ while [[ "$1" != -o ]]; do shift; done; printf x > "$2"; }}; mv() {{ return 1; }}; geo_dir='{posix(BASE/'work')}'; geo_remote=https://example.com; log_file=/dev/null; download_geo_file audit-nonempty; printf 'XRA-06 move failure function rc=%s\\n' "$?"'''
    r=shell(command,BASE)
print(r.stdout+r.stderr)
for name in ['luci-app-cloudflare-ip','rill-ml','Xray_bash_onekey']:
    root=REPOS/name; files=subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines(); counts=collections.Counter(); failures=[]
    for s in files:
        p=root/s
        try:
            if p.suffix=='.json':json.loads(p.read_text(encoding='utf-8-sig'));counts['json']+=1
            elif p.suffix=='.py':ast.parse(p.read_text(encoding='utf-8-sig'),filename=s);counts['python_ast']+=1
            elif p.suffix=='.sh' or p.name in ['cf-ip-auto-v2','cf-ip-auto-legacy','cf_ip','cf_ip_publisher']:
                rc=shell(f"/usr/bin/sh -n '{posix(p)}'",root)
                counts['bash_syntax']+=1
                if rc.returncode:failures.append({'file':s,'error':rc.stderr})
        except Exception as e: failures.append({'file':s,'error':str(e)})
    results.append({'repo':name,'counts':dict(counts),'failures':failures})
(BASE/'work/syntax-checks.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(results,ensure_ascii=False,indent=2))
