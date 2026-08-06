from __future__ import annotations
import argparse,json,socket,uuid
from pathlib import Path
from .canonical import canonical_bytes

def call(socket_path:Path,method:str,body:dict|None=None)->dict:
    envelope={'schemaVersion':3,'requestId':str(uuid.uuid4()),'capability':'route','method':method,'body':body or {}}
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(5);client.connect(str(socket_path));client.sendall(canonical_bytes(envelope)+b'\n');data=b''
        while b'\n' not in data and len(data)<=1_048_576:
            chunk=client.recv(65_536)
            if not chunk:break
            data+=chunk
    if not data:raise RuntimeError('empty Runtime response')
    return json.loads(data.split(b'\n',1)[0])

def main(argv=None)->int:
    parser=argparse.ArgumentParser(prog='rill-xray-agent')
    parser.add_argument('--socket',type=Path,default=Path('/run/rill-xray-agent/agent.sock'))
    parser.add_argument('--json',action='store_true')
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('status','health','metrics','config','snapshot'):sub.add_parser(name)
    mode=sub.add_parser('mode');mode.add_argument('value',choices=['normal','observe-only','safe-disabled'])
    inspect=sub.add_parser('inspect');inspect.add_argument('decision_id')
    args=parser.parse_args(argv)
    method={'status':'health','health':'health','metrics':'metrics','config':'config','snapshot':'snapshot','mode':'mode','inspect':'inspect'}[args.command]
    body={}
    if args.command=='mode':body={'mode':args.value}
    elif args.command=='inspect':body={'decisionId':args.decision_id}
    try:response=call(args.socket,method,body)
    except Exception as exc:response={'schemaVersion':3,'requestId':'local','ok':False,'error':{'code':'runtimeUnavailable','message':str(exc)[:256]}}
    print(json.dumps(response if args.json or not response.get('ok') else response.get('result'),ensure_ascii=False,sort_keys=True,indent=2))
    return 0 if response.get('ok') else 1
if __name__=='__main__':raise SystemExit(main())
