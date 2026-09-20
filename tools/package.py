#!/usr/bin/env python3
"""Package only the upstream-owned module and reviewable diagnostic documents."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = 'c15d659600760ac83151e38660c468244176c5b0'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sd', type=Path, default=ROOT / 'out/sd')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variant', choices=['nim-only-v2'], default='nim-only-v2')
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    title = re.search(r'^TITLE_ID\s*:=\s*([0-9A-Fa-f]{16})$', (ROOT/'Makefile').read_text(), re.M)[1]
    npdm_title = json.loads((ROOT/'network_mitm/network_mitm.json').read_text())['title_id']
    assert int(title,16) == int(npdm_title,16), 'Makefile / NPDM program ID mismatch'
    contents = Path('atmosphere/contents')/title
    files = {}
    for leaf in ['exefs.nsp','mitm.lst','flags/boot2.flag']:
        rel = contents/leaf
        files[str(rel)] = (args.sd/rel).read_bytes()
    assert files[str(contents/'mitm.lst')].splitlines() == [b'ssl', b'ssl:s']
    for name in ['README.md','INVESTIGATION.md','README-TEST.md','README-ROLLBACK.md','BUILD-REPORT.md','EVIDENCE-v2.md','LICENSE']:
        files['network_mitm/docs/'+name] = (ROOT/name).read_bytes()
    files['network_mitm/docs/nim-only.ini.example'] = (ROOT/'config/nim-only.ini.example').read_bytes()
    # The patch must match the actual binary's recorded source revision.
    patch = subprocess.check_output(['git','diff','--binary',UPSTREAM,args.source_commit], cwd=ROOT)
    files['network_mitm/docs/PATCH.diff'] = patch
    manifest = {
        'variant': args.variant,
        'source_commit': git('rev-parse', args.source_commit),
        'documentation_commit': git('rev-parse','HEAD'),
        'upstream_commit': UPSTREAM,
        'atmosphere_libs_commit': git('rev-parse',args.source_commit+':Atmosphere-libs'),
        'target': {'hos':'22.5.0','atmosphere':'1.11.2','environment':'emuMMC'},
        'hardware_verified': False,
        'fallback_default_enabled': False,
        'default_allowlist': [],
        'targeted_mode_default': True,
        'recommended_mitm_program_ids': ['0100000000000025'],
        'recommended_fallback_program_ids': ['0100000000000025'],
        'original_result_trigger': '0x0000167B',
        'scope': 'ISslContextForSystem only',
        'files': {name: hashlib.sha256(data).hexdigest() for name,data in files.items()},
    }
    files['network_mitm/docs/BUILD-MANIFEST.json'] = (json.dumps(manifest,indent=2)+'\n').encode()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(args.output,'w',zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(files.items()): archive.writestr(name,data)
    with zipfile.ZipFile(args.output) as archive:
        assert archive.testzip() is None
        assert not any('/hosts/' in n or n.endswith('system_settings.ini') for n in archive.namelist())
        assert set(archive.namelist()) == set(files)
    print(hashlib.sha256(args.output.read_bytes()).hexdigest(),args.output)

if __name__ == '__main__': main()
