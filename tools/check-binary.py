#!/usr/bin/env python3
"""Validate the actual packaged NSP, program identity and static memory budget."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def read_nsp(path):
    data = path.read_bytes()
    if data[:4] != b'PFS0':
        raise ValueError('not a PFS0 NSP')
    count, string_size = struct.unpack_from('<II', data, 4)
    strings = 16 + count * 24
    body = strings + string_size
    files = {}
    for i in range(count):
        offset, size, name_offset = struct.unpack_from('<QQI', data, 16 + i * 24)
        name = data[strings + name_offset:strings + string_size].split(b'\0', 1)[0].decode()
        if body + offset + size > len(data):
            raise ValueError('truncated PFS0 entry')
        files[name] = data[body + offset:body + offset + size]
    nso = files['main']
    if nso[:4] != b'NSO0':
        raise ValueError('main is not an NSO')
    sizes = [struct.unpack_from('<I', nso, o)[0] for o in (0x18, 0x28, 0x38)]
    bss = struct.unpack_from('<I', nso, 0x3c)[0]
    data_va = struct.unpack_from('<I', nso, 0x34)[0]
    npdm = files['main.npdm']
    aci, acid = npdm.index(b'ACI0'), npdm.index(b'ACID')
    program = struct.unpack_from('<Q', npdm, aci + 16)[0]
    lo, hi = struct.unpack_from('<QQ', npdm, acid + 16)
    if program != lo or program != hi:
        raise ValueError('NPDM program ID mismatch')
    return {'nsp_sha256': hashlib.sha256(data).hexdigest(), 'program_id': f'{program:016X}',
            'nso_build_id': nso[0x40:0x60].hex(), 'nso_segment_bytes': sizes, 'nso_bss_bytes': bss,
            'mapped_image_end_page_aligned': (data_va + sizes[2] + bss + 4095) & ~4095}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sd', type=Path, default=Path('out/sd'))
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    module = args.sd / 'atmosphere/contents/4200000000000666'
    report = read_nsp(module / 'exefs.nsp')
    if report['program_id'] != '4200000000000666':
        raise ValueError('wrong module identity')
    if (module / 'mitm.lst').read_bytes().splitlines() != [b'ssl', b'ssl:s']:
        raise ValueError('account-link diagnostic must reserve exactly ssl and ssl:s')
    if not (module / 'flags/boot2.flag').is_file():
        raise ValueError('missing boot flag')
    if report['nso_bss_bytes'] >= 3 * 1024 * 1024:
        raise ValueError('account-link diagnostic static-memory budget exceeded')
    report['variant'] = 'account-link-diagnostic-v1'
    report['mitm_ports'] = ['ssl', 'ssl:s']
    if args.baseline:
        before = read_nsp(args.baseline)
        report['baseline'] = before
        report['bss_saved_bytes'] = before['nso_bss_bytes'] - report['nso_bss_bytes']
        report['mapped_image_saved_bytes'] = before['mapped_image_end_page_aligned'] - report['mapped_image_end_page_aligned']
        if report['bss_saved_bytes'] < 8 * 1024 * 1024:
            raise ValueError('less than 8 MiB recovered compared with v2')
    output = json.dumps(report, indent=2) + '\n'
    if args.output:
        args.output.write_text(output)
    print(output, end='')


if __name__ == '__main__':
    main()
