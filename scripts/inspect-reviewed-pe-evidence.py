#!/usr/bin/env python3
"""Hash-pinned bytes for manually reviewed PE callsites, no code execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import uuid

spec = importlib.util.spec_from_file_location('pe', Path(__file__).with_name('inspect-mitoken-contract-evidence.py'))
pe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pe)
CASES = {
    'MiTokenDxe': {'guids': [0x90a8], 'instructions': [0x1ae4,0x1afc,0x1ac4]},
    'Ebl': {'guids': [0x1d188,0x1d1e8,0x1b7d0],
            'instructions': [0x10c94,0x10ca8,0x10cac,0x10d58,0x10d5c,
                             0xe104,0xe114,0xe150,0xe154,0x136b4,0x136fc]},
    'QcomBds': {'guids': [0x1e248],
                'instructions': [0x1d94,0x1da4,0x1da8,0x1e14,0x1e18,
                                 0xf630,0xf634,0xf65c,0xf664]},
    'TzDxeLA': {'guids': [0xf108,0xf128], 'words': list(range(0xf250,0xf290,8)),
                'instructions': [0x1ed4,0x1e40,0x1e44,0x1e50,0x1e58,
                                 0x37ec,0x37f0,0x37f4,0x3834,0x3838,
                                 0x3844,0x384c,0x3850,0x3854,0x3860,0x3868,
                                 0x387c,0x3880,0x3884,0x388c,0x3994,0x39a8,
                                 0x39d0,0x4218,0x4318,0x433c,0x4350,0x9228,0x9234]},
}


def main():
    census = json.loads(Path('docs/mitoken-provider-census.json').read_text())['matches']
    report = []
    for name, case in CASES.items():
        source = Path('work/provider-census') / (name+'.pe')
        if source.stat().st_size > 4*1024*1024:
            raise ValueError('PE exceeds audit read limit')
        data = source.read_bytes()
        expected = next(row for row in census if row['name'] == name)
        if hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise ValueError('PE hash mismatch: '+name)
        row = dict(name=name, sha256=expected['sha256'], ffs=expected['ffs'],
                   outer=expected['outer'], guids=[], instructions=[])
        for address in case['guids']:
            raw = pe.read_rva(data,address,16)
            row['guids'].append(dict(rva=hex(address), bytes=raw.hex(' '),
                                     guid=str(uuid.UUID(bytes_le=raw))))
        for address in case['instructions']:
            row['instructions'].append(dict(rva=hex(address), bytes=pe.read_rva(data,address,4).hex(' ')))
        if case.get('words'):
            row['words'] = [dict(rva=hex(a), value=hex(int.from_bytes(pe.read_rva(data,a,8),'little')))
                            for a in case['words']]
        report.append(row)
    Path('docs/reviewed-pe-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Verified',len(report),'PEs; selected original GUIDs and instruction bytes')


if __name__ == '__main__':
    main()
