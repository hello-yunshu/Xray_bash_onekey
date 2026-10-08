import pathlib, sys, subprocess, json, time, os, re
BASE = pathlib.Path(__file__).resolve().parents[1]
REPOS = BASE / 'outputs'
SH = pathlib.Path(r'C:\Users\hello\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\usr\bin\sh.exe')
def posix(p):
    return '/' + str(p)[0].lower() + str(p)[2:].replace('\\', '/')
def shell(command, cwd, timeout=60):
    setup = f'export PATH={posix(BASE / "work/bin")}:/usr/bin:$PATH; '
    return subprocess.run([str(SH), '-c', setup+command], cwd=cwd, text=True, capture_output=True, timeout=timeout)
if __name__ == '__main__':
    mode=sys.argv[1]
    if mode=='read':
        root=REPOS/sys.argv[2]
        for spec in sys.argv[3:]:
            parts=spec.split('@'); p=root/parts[0]; lines=p.read_text(encoding='utf-8').splitlines()
            start,end=(map(int,parts[1].split(':')) if len(parts)>1 else (1,len(lines)))
            print(f'=== {p.relative_to(root)} ({len(lines)} lines) ===')
            for n in range(start,min(end,len(lines))+1): print(f'{n:4}: {lines[n-1]}')
    elif mode=='inventory':
        for name in sys.argv[2:]:
            root=REPOS/name
            paths=subprocess.check_output(['git','ls-files'],cwd=root,text=True).splitlines()
            out=[]
            for s in paths:
                p=root/s
                if p.suffix in ['.sh','.rs','.py','.js','.yml','.yaml','.toml','.json','.lua'] or p.name in ['Makefile','install.sh','cf-ip-auto-v2','cf-ip-auto-legacy','cf_ip','cf_ip_publisher']:
                    out.append({'file':s,'lines':len(p.read_bytes().splitlines()),'bytes':p.stat().st_size})
            (BASE/'work'/f'{name}-inventory.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
            print(name,len(paths),'files,',sum(x['lines'] for x in out),'code/config lines')
    elif mode=='cf-tests':
        root=REPOS/'luci-app-cloudflare-ip'; results=[]
        for p in sorted((root/'tests').glob('*.sh')):
            if p.name in ['cfst-real-smoke.sh','package-migration.sh','rill-real-runtime-full-lifecycle.sh','rill-continuous-qualification.sh','release-asset-contract.sh','evidence-manifest.sh']: continue
            started=time.monotonic()
            try:
                r=shell(f'bash tests/{p.name}',root,55)
                entry={'test':p.name,'rc':r.returncode,'seconds':round(time.monotonic()-started,2),'output':r.stdout+r.stderr}
            except subprocess.TimeoutExpired as e:
                entry={'test':p.name,'rc':'TIMEOUT','seconds':55,'output':str(e)}
            results.append(entry)
            (BASE/'work/cf-tests.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
            print(p.name,entry['rc'],flush=True)
