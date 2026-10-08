import importlib, io, json, pathlib, sys, tempfile, time, types, unittest.mock as mock, zipfile
BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'outputs/Xray_bash_onekey/rill_payload/python'))
# grp is a Linux-only dependency; none of these isolated cases exercises DAC.
sys.modules.setdefault('grp',types.ModuleType('grp'))
from rill_xray_agent import rillml_artifact as a, backup, safe_fs

class SlowReader:
    def readline(self): time.sleep(.2); return b'{"ok":true}\n'
p=types.SimpleNamespace(stdin=io.BytesIO(),stdout=SlowReader())
t=time.monotonic(); a._ipc_call(p,{'method':'health'},timeout=.01)
print('XRA-01 requested timeout=.01, returned after',round(time.monotonic()-t,3),'seconds')

class Response:
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def geturl(self): return 'https://example.com/artifact'
    def read(self,*args):
        print('XRA-02 response.read arguments:',args)
        return b'x'*100
with mock.patch.object(a.urllib.request,'urlopen',return_value=Response()):
    try: a._http_get('https://example.com/artifact',timeout=1,attempts=1,max_bytes=10)
    except a.RillMLDownloadError: print('XRA-02 rejected only after complete read')

with tempfile.TemporaryDirectory() as td:
    root=pathlib.Path(td); manager=a.RillMLRuntimeManager(root)
    manager.current_dir.mkdir(); (manager.current_dir/'rill-runtime').write_bytes(b'previous-good')
    stage=root/'candidate'; stage.write_bytes(b'candidate')
    replace=a.os.replace
    def fail_candidate(src,dst,*args,**kw):
        if pathlib.Path(src)==stage: raise OSError('injected candidate rename failure')
        return replace(src,dst,*args,**kw)
    with mock.patch.object(a.os,'replace',side_effect=fail_candidate):
        try: manager._activate({'version':'1.5.6'},stage,{})
        except OSError: pass
    print('XRA-03 after failed activation: current exists=',manager._current_binary().exists(),', previous-good in rollback=',(manager.rollback_dir/'rill-runtime').exists())
    manager.current_dir.mkdir(exist_ok=True); manager._current_binary().write_bytes(b'corrupted')
    manager.state_path.write_text(json.dumps({'version':'1.5.6','artifactId':'rill-runtime','targetOs':'linux','targetArch':'x86_64','targetLibc':'glibc'}))
    with mock.patch.object(a,'detect_platform',return_value={'os':'linux','arch':'x86_64','libc':'glibc'}):
        print('XRA-04 corrupted binary native_status=',json.dumps(manager.native_status()))
    manifest=root/'oversized-manifest.zip'
    with zipfile.ZipFile(manifest,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('MANIFEST.json',b' '*(backup.MAX_MEMBER+1)+b'{"entries":[]}')
    print('XRA-08 oversized manifest accepted=',backup.verify_backup(manifest))
    content=b'a'*(2097152+1)+b' vless://synthetic-credential'
    print('XRA-09 secret after 2MiB classified safe=',backup.safe_content(root/'timeline.json',content))

# Exercise real write_beneath control flow with mocked POSIX dirfd syscalls.
calls=[]
with mock.patch.object(safe_fs,'reject_ancestor_symlinks'),mock.patch.object(safe_fs.os,'open',return_value=10),mock.patch.object(safe_fs.os,'close'),mock.patch.object(safe_fs.os,'fsync'),mock.patch.object(safe_fs.os,'replace',side_effect=lambda *x,**k:calls.append('published')),mock.patch.object(safe_fs.os,'write',side_effect=lambda fd,data:(calls.append(len(data)) or 2)):
    safe_fs.write_beneath(pathlib.Path('unused'),'file.json',b'abcdef')
print('XRA-07 write requested6 returned2; calls=',calls)
