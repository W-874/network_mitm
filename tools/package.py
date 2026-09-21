#!/usr/bin/env python3
"""Package a checked account-link diagnostic build; never bless stale output."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = 'c15d659600760ac83151e38660c468244176c5b0'
MANIFEST_INPUT = ROOT / 'BUILD-MANIFEST.json'

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def load_manifest_input():
    """Load reviewable source metadata; package hashes are generated later."""
    data = json.loads(MANIFEST_INPUT.read_text())
    required = {
        'variant', 'target', 'hardware_verified', 'fallback_default_enabled',
        'default_allowlist', 'targeted_mode_default',
        'recommended_mitm_program_ids', 'recommended_fallback_program_ids',
        'original_result_trigger', 'scope', 'mitm_ports', 'server_resources',
        'ordinary_ssl_diagnostic', 'system_ssl_fallback',
    }
    missing = required.difference(data)
    if missing:
        raise ValueError(f'manifest input missing: {sorted(missing)}')
    if 'files' in data:
        raise ValueError('source manifest input must not contain package or binary hashes')
    if data['variant'] != 'account-link-fallback-v2':
        raise ValueError('wrong manifest input variant')
    if data['mitm_ports'] != ['ssl:s']:
        raise ValueError('wrong manifest input ports')
    fallback = data['system_ssl_fallback']
    if fallback != {
        'program_ids': ['0100000000000025', '010000000000001E', '010000000000002F'],
        'type': 1,
        'trigger': '0x0000167B',
        'original_first': True,
        'real_pki_id_only': True,
        'account_hardware_verified': True,
        'npns_hardware_observed': True,
        'npns_fallback_hardware_verified': True,
    }:
        raise ValueError('wrong system SSL fallback manifest scope')
    return data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sd', type=Path, default=ROOT / 'out/sd')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--variant', choices=['account-link-fallback-v2'], default='account-link-fallback-v2')
    parser.add_argument('--source-commit')
    parser.add_argument('--check-input', action='store_true',
                        help='validate only the clean-tree manifest input; do not read or package out/sd')
    args = parser.parse_args()
    manifest_input = load_manifest_input()
    if args.check_input:
        print(f"PASS: manifest input {MANIFEST_INPUT.name} variant={manifest_input['variant']}")
        return
    if args.output is None or args.source_commit is None:
        parser.error('--output and --source-commit are required when packaging')
    if git('status', '--porcelain'):
        raise ValueError('refusing to package from a dirty source tree')
    if git('rev-parse', args.source_commit) != git('rev-parse', 'HEAD'):
        raise ValueError('source-commit must be the clean checked-out HEAD')
    subprocess.run(['python3', str(ROOT/'tools/check-binary.py'), '--sd', str(args.sd)], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    title = re.search(r'^TITLE_ID\s*:=\s*([0-9A-Fa-f]{16})$', (ROOT/'Makefile').read_text(), re.M)[1]
    npdm_title = json.loads((ROOT/'network_mitm/network_mitm.json').read_text())['title_id']
    assert int(title,16) == int(npdm_title,16), 'Makefile / NPDM program ID mismatch'
    contents = Path('atmosphere/contents')/title
    files = {}
    for leaf in ['exefs.nsp','mitm.lst','flags/boot2.flag']:
        rel = contents/leaf
        files[str(rel)] = (args.sd/rel).read_bytes()
    assert files[str(contents/'mitm.lst')].splitlines() == [b'ssl:s']
    for name in ['README.md','INVESTIGATION.md','README-TEST.md','README-ROLLBACK.md','BUILD-REPORT.md','EVIDENCE-v2.md','CRASH-ANALYSIS.md','LICENSE']:
        files['network_mitm/docs/'+name] = (ROOT/name).read_bytes()
    files['network_mitm/docs/account-link-diagnostic.ini.example'] = (ROOT/'config/account-link-diagnostic.ini.example').read_bytes()
    # The patch must match the actual binary's recorded source revision.
    patch = subprocess.check_output(['git','diff','--binary',UPSTREAM,args.source_commit], cwd=ROOT)
    files['network_mitm/docs/PATCH.diff'] = patch
    manifest = {
        'variant': args.variant,
        'source_commit': git('rev-parse', args.source_commit),
        'documentation_commit': git('rev-parse','HEAD'),
        'upstream_commit': UPSTREAM,
        'atmosphere_libs_commit': git('rev-parse',args.source_commit+':Atmosphere-libs'),
        **manifest_input,
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
