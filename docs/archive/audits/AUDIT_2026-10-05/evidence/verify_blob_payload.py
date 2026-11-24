import hashlib,json,pathlib,subprocess
from audit_tools import BASE,REPOS
x=REPOS/'Xray_bash_onekey'; c=REPOS/'rill-xray-agent'
manifest=json.loads(subprocess.check_output(['git','show','HEAD:integrations/xray_bash_onekey/CANONICAL_MANIFEST.json'],cwd=c))
failures=[];count=0
for rel,expected in manifest['files'].items():
    if not rel.startswith('repository_files/'):continue
    path=rel[len('repository_files/'):]
    if path.split('/')[0] not in ['rill_payload','scripts','systemd','assets']:continue
    blob=subprocess.check_output(['git','show','HEAD:'+path],cwd=x)
    count+=1
    if hashlib.sha256(blob).hexdigest()!=expected: failures.append(path)
bundle=subprocess.check_output(['git','show','HEAD:assets/rill-xray-agent-xray-bundle.tar.gz'],cwd=x)
if hashlib.sha256(bundle).hexdigest()!=manifest['bundleSha256']:failures.append('bundleSha256')
pin=json.loads((x/'repository_files/rill_integration/RILL_CANONICAL_PIN.json').read_text())
if pin['canonicalDigest']!=manifest['canonicalDigest']:failures.append('canonicalDigest')
result={'checkedGitBlobFiles':count,'bundleSha256':hashlib.sha256(bundle).hexdigest(),'canonicalDigest':manifest['canonicalDigest'],'failures':failures,'note':'Git blob bytes bypass core.autocrlf=true checkout conversion; no tracked files rewritten.'}
(BASE/'work/xray-blob-check.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
