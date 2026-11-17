#!/usr/bin/env python3
"""L0 differential harness. Only the controlled Go SOURCE BUILD may count as native.

Never treats self-reported JSON, an arbitrary executable path, or L0 green as
release certification. Production qualification is a separate, red-by-default job.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PIN = '3b2a5045fec4535e189a0b25ca27dc534945bab5'


def run(cmd, **kwargs):
    return subprocess.run([str(x) for x in cmd], capture_output=True, text=True, timeout=120, **kwargs)


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def clean_pinned_bash(repo):
    """Pin exact Git object AND actual file bytes, not merely the name of HEAD."""
    repo = repo.resolve()
    if not (repo / 'install.sh').is_file():
        raise ValueError('full Bash repository lacks install.sh')
    head = run(['git', '-C', repo, 'rev-parse', 'HEAD'])
    if head.returncode or head.stdout.strip() != PIN:
        raise ValueError('Bash HEAD is not the required fixed commit')
    diff = run(['git', '-C', repo, 'status', '--porcelain', '--untracked-files=all', '--', 'install.sh'])
    if diff.returncode or diff.stdout.strip():
        raise ValueError('Bash install.sh is dirty or untracked; reject mutable oracle')
    blob = subprocess.run(['git', '-C', str(repo), 'show', f'{PIN}:install.sh'], capture_output=True, timeout=120)
    if blob.returncode or hashlib.sha256(blob.stdout).hexdigest() != sha256(repo / 'install.sh'):
        raise ValueError('Bash install.sh bytes differ from pinned Git object')
    return {'git_commit': PIN, 'install_sh_sha256': sha256(repo / 'install.sh'), 'clean_file': True}


def check_bash_oracle_environment():
    """Fail fast instead of reporting 0/83 on hosts that cannot source install.sh."""
    if not Path('/etc/os-release').is_file():
        raise ValueError('/etc/os-release is required: install.sh sources it at load time')
    bash = shutil.which('bash')
    if not bash:
        raise ValueError('bash not found in PATH')
    probe = run([bash, '-c', 'printf "%s" "${BASH_VERSINFO[0]:-0}"'])
    if probe.returncode or not probe.stdout.strip().isdigit() or int(probe.stdout) < 4:
        raise ValueError(f'bash >= 4 required (found {probe.stdout.strip() or "unknown"}); install.sh uses declare -A')


def clean_native_source(path):
    path = path.resolve()
    head = run(['git', '-C', path, 'rev-parse', 'HEAD'])
    status = run(['git', '-C', path, 'status', '--porcelain', '--untracked-files=all'])
    top = run(['git', '-C', path, 'rev-parse', '--show-toplevel'])
    if any(x.returncode for x in (head, status, top)) or status.stdout.strip():
        raise ValueError('native Go source must be a clean Git checkout')
    if not path.is_relative_to(Path(top.stdout.strip()).resolve()):
        raise ValueError('native Go source not inside its own checkout')
    return head.stdout.strip()


def build_native(path, target, required_package, output):
    """Only source-built Go code with a listed production package dependency.

    CI review/branch protection remains essential: a source build cannot prove
    that an adapter *calls* a package for every operation.
    """
    if not required_package or '/internal/' not in required_package:
        raise ValueError('--require-package must name an exact production internal Go package')
    commit = clean_native_source(path)
    module = run(['go', 'list', '-m'], cwd=path)
    deps = run(['go', 'list', '-deps', '-f', '{{.ImportPath}}', target], cwd=path)
    if module.returncode or deps.returncode:
        raise ValueError(f'go list failed: {module.stderr} {deps.stderr}')
    mod = module.stdout.strip()
    if not required_package.startswith(mod + '/internal/') or required_package not in deps.stdout.splitlines():
        raise ValueError('native adapter does not import the declared production internal package')
    build = run(['go', 'build', '-trimpath', '-buildvcs=true', '-o', output, target], cwd=path)
    if build.returncode:
        raise ValueError(f'native adapter build failed: {build.stderr}')
    return {'mode': 'SOURCE_BUILT_NATIVE_GO_L0', 'source_commit': commit, 'module': mod,
            'required_package': required_package, 'target': target, 'binary_sha256': sha256(output),
            'warning': 'compile-time import does not prove runtime use; CI reviews required'}


def snapshot(root):
    result = {}
    for f in root.rglob('*'):
        if f.is_symlink() or not f.is_file():
            continue
        result[str(f.relative_to(root))] = sha256(f)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bash-repo', type=Path)
    p.add_argument('--require-live', action='store_true')
    p.add_argument('--native-go-dir', type=Path)
    p.add_argument('--native-package', default='./cmd/parity-adapter')
    p.add_argument('--require-package', help='exact production internal package imported by adapter')
    p.add_argument('--require-native-l0', action='store_true')
    p.add_argument('--go-binary', type=Path, help='UNTRUSTED demo executable, never accepted for native qualification')
    p.add_argument('--require-release', action='store_true', help='retired: L0 alone must never be a release gate')
    p.add_argument('--evidence', type=Path)
    a = p.parse_args()
    if a.require_release:
        print('BLOCKED: --require-release has been retired; run the separate CI release qualification.', file=sys.stderr)
        return 3
    if (a.require_live or a.require_native_l0) and not a.bash_repo:
        print('BLOCKED: pinned full Bash checkout required', file=sys.stderr)
        return 3
    if a.require_native_l0 and (not a.native_go_dir or not a.require_package or a.go_binary):
        print('BLOCKED: native L0 requires --native-go-dir and --require-package; arbitrary --go-binary forbidden',file=sys.stderr)
        return 3
    if a.go_binary and a.native_go_dir:
        print('BLOCKED: choose source build or untrusted binary experiment, not both',file=sys.stderr)
        return 3
    try:
        baseline = clean_pinned_bash(a.bash_repo) if a.bash_repo else None
        if a.bash_repo:
            check_bash_oracle_environment()
    except (ValueError, OSError) as e:
        print('BLOCKED Bash oracle:', str(e), file=sys.stderr)
        return 3
    cases = json.loads((ROOT/'cases/functional_cases.json').read_text())
    output = a.evidence or ROOT/'evidence'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='idleleo-l0-') as d:
        scratch = Path(d)
        adapter = scratch/'adapter'
        if a.native_go_dir:
            try:
                provenance = build_native(a.native_go_dir, a.native_package, a.require_package, adapter)
            except (ValueError, OSError) as e:
                print('BLOCKED native Go adapter:', str(e), file=sys.stderr)
                return 3
        elif a.go_binary:
            adapter = a.go_binary.resolve()
            if not adapter.is_file():
                print('BLOCKED: arbitrary Go demo binary not found', file=sys.stderr)
                return 3
            provenance = {'mode': 'UNTRUSTED_BINARY_DEMO', 'binary_sha256': sha256(adapter)}
        else:
            build = run(['go','build','-o',adapter,'.'], cwd=ROOT/'go')
            if build.returncode:
                print('Go demo build failed:', build.stderr, file=sys.stderr)
                return 2
            provenance = {'mode': 'BUNDLED_TOY_GO_DEMO', 'binary_sha256': sha256(adapter)}
        rows=[]
        for index, obj in enumerate(cases):
            opts=[obj['op'], *obj['args']]
            bdir=scratch/f'b-{index}';gdir=scratch/f'g-{index}'
            bdir.mkdir();gdir.mkdir()
            env=os.environ.copy();env.update({'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8'})
            if a.bash_repo:env['BASH_REPO']=str(a.bash_repo.resolve())
            else:env.pop('BASH_REPO',None)
            benv={**env,'HOME':str(bdir),'TMPDIR':str(bdir)}
            genv={**env,'HOME':str(gdir),'TMPDIR':str(gdir)}
            b=run(['bash',ROOT/'oracle/run_function.sh',*opts],cwd=bdir,env=benv)
            g=run([adapter,*opts],cwd=gdir,env=genv)
            bside=snapshot(bdir);gside=snapshot(gdir)
            same=(b.returncode==g.returncode and b.stdout==g.stdout and b.stderr==g.stderr and not bside and not gside)
            rows.append({'case':obj['id'],'feature':obj['feature'], 'op':obj['op'], 'match':same,
                 'bash':{'rc':b.returncode,'stdout':b.stdout,'stderr':b.stderr,'unexpected_files':bside},
                 'go':{'rc':g.returncode,'stdout':g.stdout,'stderr':g.stderr,'unexpected_files':gside}})
        bad=[x for x in rows if not x['match']]
        live=bool(baseline)
        native=provenance['mode']=='SOURCE_BUILT_NATIVE_GO_L0'
        report={'schema_version':2,'baseline_commit':PIN,'pinned_bash':baseline,
             'oracle_mode':'LIVE_PINNED_CLEAN' if live else 'EXTRACTED_SNAPSHOT',
             'go_provenance':provenance,'native_l0_only':native and live and not bad,
             'release_certified':False,'total':len(rows),'passed':len(rows)-len(bad),
             'failed':len(bad),'rows':rows,'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'scope_limit':'Only 7 pure function contracts; FS snapshot limited to CWD/HOME/TMPDIR; no host isolation'}
        (output/'functional_parity.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
        (output/'functional_parity.md').write_text(f'# L0差分报告\n\n- Oracle: {report["oracle_mode"]}\n- Go: {provenance["mode"]}\n- 对照: {report["passed"]}/{report["total"]}\n- Release认证: **否**\n- 限制: {report["scope_limit"]}\n')
        print(f'{report["oracle_mode"]}: {report["passed"]}/{report["total"]} MATCH; {provenance["mode"]}; release_certified=False')
        if bad:
            for x in bad[:5]:print('MISMATCH',x['case'],file=sys.stderr)
            return 1
        return 0

if __name__=='__main__': sys.exit(main())
