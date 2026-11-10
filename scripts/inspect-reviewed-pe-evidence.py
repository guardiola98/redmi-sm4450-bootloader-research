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
    'DxeCore': {'guids': [], 'words': [0x2a5b8, 0x2a5c0],
                'instructions': [0xff3c,0xff4c,0xff74,0xff98,0xffac,0xffb0,
                                 0xfff8,0x100d0,0x10128,0x1012c,0x104a8,0x104b0]},
    'ArmCpuDxe': {'guids': [],
                  'instructions': [0x3038,0x3040,0x3048,0x3050,0x44d0,0x44f0,
                                   0x4528,0x7268,0x726c,0x7270,0x7c50,0x7c54]},
    'MiTokenDxe': {'guids': [0x90a8], 'instructions': [0x1ae4,0x1afc,0x1ac4]},
    'VerifiedBootDxe': {'guids': [0xd0f8],
                        'instructions': [0x16b4,0x16b8,0x16c8,0x16cc,
                                         0x16f4,0x1724,0x173c,0x1740,0x1744]},
    'Ebl': {'guids': [0x1d188,0x1d1e8,0x1b7d0],
            'instructions': [0x10c94,0x10ca8,0x10cac,0x10d58,0x10d5c,
                             0xe104,0xe114,0xe150,0xe154,0x136b4,0x136fc]},
    'QcomBds': {'guids': [0x1e248],
                'instructions': [0x1d94,0x1da4,0x1da8,0x1e14,0x1e18,
                                 0xf630,0xf634,0xf65c,0xf664]},
    'TzDxeLA': {'guids': [0xf108,0xf128,0xf148,0xf158],
                'words': list(range(0xf250,0xf290,8))+list(range(0xf2d0,0xf2f8,8))+
                         [0xf4c0,0xf4c8,0xf568,0xf588],
                'instructions': [0x1ed4,0x1e40,0x1e44,0x1e50,0x1e58,
                                 0x1e48,0x1ef0,0x1efc,0x1f00,0x1f08,
                                 0x1f44,0x1f4c,0x1f64,0x1f74,0x1f80,0x1f8c,0x1f98,
                                 0x216c,0x25c8,0x28c4,0x29f8,0x2a24,
                                 0x14f8,0x1504,0x21b4,0x2488,0x255c,0x25ec,
                                 0x2bc4,0x2c08,0x2c30,0x2d08,0x2d10,
                                 0x2e38,0x2e40,0x2e48,0x2f54,
                                 0x2fd8,0x2ff0,0x2ff4,0x3000,0x3004,0x3008,
                                 0x301c,0x3024,0x303c,0x3044,0x3078,0x30b0,
                                 0x3108,0x310c,0x3128,0x312c,0x3140,0x318c,
                                 0x3190,0x324c,0x3258,0x3358,0x335c,0x3370,
                                 0x42f0,0x4304,0x4308,0x4310,0x43bc,
                                 0x3488,0x34e4,0x3548,0x3590,0x35b4,0x35c0,
                                 0x3840,0x38b8,0x3920,0x3a18,0x3fdc,
                                 0x37ec,0x37f0,0x37f4,0x3834,0x3838,
                                 0x3844,0x384c,0x3850,0x3854,0x3860,0x3868,
                                 0x387c,0x3880,0x3884,0x388c,0x3994,0x39a8,
                                 0x39d0,0x4218,0x4318,0x433c,0x4350,0x9228,0x9234]},
    'ScmDxeLA': {'guids': [0xd038,0xd088,0xd098],
                 'words': [0xd110,0xd168,0xd188,0xd190,0xd198,
                           0xd438,0xd440,0xd450,0xd460,0xd468,0xd488],
                 'instructions': [0x14f8,0x1500,0x1504,0x1508,0x1524,0x1528,
                                  0x1550,0x1554,0x1564,0x1570,0x158c,0x17e4,
                                  0x3780,0x3784,0x37b0,0x37d0,0x37dc,0x37f8,
                                  0x3804,0x3814,0x381c,0x384c,0x3864,
                                  0x36e4,0x36fc,0x38c8,0x38cc,0x4570,0x4580,
                                  0x47d8,0x47dc,0x47e0,0x4808,0x4810,0x4818,
                                  0x4828,0x482c,0x48dc,0x48e0,0x48e4,0x4a60,
                                  0x4ba0,0x4c78,0x4c7c,0x4cc8,0x4ccc,
                                  0x5814,0x5820,0x5824,0x582c,0x583c,
                                  0x4ce8,0x4cec,0x4cfc,0x5840,0x5844,0x5848,
                                  0x6aec,0x6af0,0x6af8,0x6b00,0x6b08,0x6b20,
                                  0x6b98,0x6b9c,0x6bd4,
                                  0x6da0,0x731c,0x7320,0x7324]},
    'ShmBridgeDxe': {'guids': [0x7068], 'words': [0x70a8,0x70b0,0x70b8],
                     'instructions': [0x14e4,0x1514,0x1518,0x151c,0x1520,
                                      0x1530,0x1534,0x2950,0x2b7c,0x2b94,0x2bb0,
                                      0x2bb4,0x2bf4,0x2bf8,0x2c08,0x2c18,
                                      0x2b4c,0x2b68,0x2b6c,0x2b80,0x2b88,0x2b8c,
                                      0x2c20,0x2c24,0x460c,0x4610]},
}


def main():
    census = json.loads(Path('docs/mitoken-provider-census.json').read_text())['matches']
    report = []
    for name, case in CASES.items():
        source = Path('work/provider-census') / (name+'.pe')
        if source.stat().st_size > 4*1024*1024:
            raise ValueError('PE exceeds audit read limit')
        data = source.read_bytes()
        expected = next((row for row in census if row['name'] == name), None)
        if expected is None:
            # New functional review of an already inventoried PE: reuse its
            # provenance; do not run another GUID scan or unpack the firmware.
            metadata = json.loads(Path('docs/consumer-dependencies.json').read_text())
            candidates = [(module, executable) for image in metadata
                          for module in image['ffs_metadata'] if name in module['names']
                          for executable in module['executables'] if executable['type'] == 'PE']
            if len(candidates) != 1:
                raise ValueError('Ambiguous metadata: '+name)
            module, executable = candidates[0]
            expected = dict(sha256=executable['sha256'], ffs=module['ffs'],
                            outer=executable['path'][1].split(':')[1].split('@')[0])
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
