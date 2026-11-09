#!/usr/bin/env python3
"""Extract only the two protocol PE sections from the hash-pinned archive."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('locator', Path(__file__).with_name('locate-uefi-protocol-modules.py'))
loc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loc)
TARGETS = {'068aae46-bdc6-4073-85d5-31c5eef19a15': 'MiTokenDxe',
           'a25f5839-4d55-428f-8f0b-5ce1d565f53e': 'VerifiedBootDxe'}

def extract(data):
    result = {}
    for pos, end, typ, hs in loc.sections(data, 0, len(data)):
        if typ != 0x17:
            continue
        start, stop, _ = loc.parse_fv(data, pos + hs, end)
        for at, last, begin, guid, ft in loc.ffs_files(data, start, stop):
            name = TARGETS.get(str(guid))
            if not name:
                continue
            ss = list(loc.sections(data, begin, last))
            names = [data[a+h:b].decode('utf-16le').rstrip('\0') for a,b,t,h in ss if t == 0x15]
            images = [(a,h,data[a+h:b]) for a,b,t,h in ss if t == 0x10]
            if names != [name] or len(images) != 1 or name in result:
                raise ValueError('Ambiguous module identity')
            offset, header, pe = images[0]
            if len(pe) < 64 or pe[:2] != b'MZ':
                raise ValueError('Missing DOS header')
            p = struct.unpack_from('<I', pe, 60)[0]
            if p+26 > len(pe) or pe[p:p+4] != b'PE\0\0':
                raise ValueError('Missing PE header')
            machine = struct.unpack_from('<H', pe, p+4)[0]
            magic = struct.unpack_from('<H', pe, p+24)[0]
            if machine != 0xaa64 or magic != 0x20b:
                raise ValueError('Unexpected architecture or format')
            result[name] = (pe, dict(ffs_guid=str(guid), ffs_offset=hex(at), pe_payload_offset=hex(offset+header), size=len(pe), sha256=hashlib.sha256(pe).hexdigest(), machine='ARM64', format='PE32+'))
    if len(result) != 2:
        raise ValueError('Missing target modules')
    return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('archive', type=Path)
    args = ap.parse_args()
    result = extract(loc.decoded_first_fv(loc.read_uefi(args.archive)))
    out = Path('work/protocols')
    out.mkdir(parents=True, exist_ok=True)
    for name, (pe, meta) in result.items():
        path = out / (name + '.pe')
        if path.exists():
            if path.read_bytes() != pe:
                raise ValueError('Refusing different existing output')
        else:
            with path.open('xb') as f:
                f.write(pe)
    print(json.dumps({n:m for n,(_,m) in result.items()}, indent=2))

if __name__ == '__main__':
    main()
