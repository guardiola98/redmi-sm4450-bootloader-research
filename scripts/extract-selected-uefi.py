#!/usr/bin/env python3
"""Extract named, already inventoried direct PE sections; no GUID scan/execution.

Uses the existing provenance manifest and bounded FV/GZIP parser. Outputs stay
in ignored work/provider-census; refuses a differing existing file.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import uuid

spec = importlib.util.spec_from_file_location(
    'fv', Path(__file__).with_name('locate-uefi-protocol-modules.py'))
fv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fv)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('names', nargs='+')
    args = parser.parse_args()
    source = Path('work/uefi-provider-source.elf')
    if source.stat().st_size > fv.LIMIT:
        raise ValueError('Source exceeds read limit')
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != fv.EXPECTED_SHA256:
        raise ValueError('Unexpected source hash')
    metadata = json.loads(Path('docs/consumer-dependencies.json').read_text())
    decoded = {}
    for name in args.names:
        if not name or not all(c.isascii() and (c.isalnum() or c in '-_') for c in name):
            raise ValueError('Invalid module name')
        matches = [e for image in metadata for m in image['ffs_metadata']
                   if name in m['names'] for e in m['executables']
                   if e['type'] == 'PE' and e['path'][0] == 'uefi.elf']
        if len(matches) != 1:
            raise ValueError('Expected one inventoried PE: '+name)
        entry = matches[0]
        route = entry['path']
        if len(route) != 7 or not route[3].startswith('decoded:'+str(fv.GZIP_GUID)+':'):
            raise ValueError('Only direct PE in known GZIP FV supported')
        outer = uuid.UUID(route[1].split(':')[1].split('@')[0])
        if outer not in decoded:
            fv.TARGET_FFS_GUID = outer
            decoded[outer] = fv.decoded_first_fv(data)
        blob = decoded[outer]
        if hashlib.sha256(blob).hexdigest() != route[3].split(':')[2]:
            raise ValueError('Decoded container hash mismatch')
        at = int(route[-1].split('@')[1], 16)
        a, b, typ, hs = next(fv.sections(blob, at, len(blob)))
        body = blob[a+hs:b]
        if (typ != 0x10 or len(body) != entry['size'] or
                hashlib.sha256(body).hexdigest() != entry['sha256']):
            raise ValueError('PE provenance mismatch')
        output = Path('work/provider-census') / (name+'.pe')
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() and output.read_bytes() != body:
            raise ValueError('Refusing to replace differing file: '+str(output))
        if not output.exists():
            output.write_bytes(body)
        print(name, len(body), entry['sha256'])


if __name__ == '__main__':
    main()
