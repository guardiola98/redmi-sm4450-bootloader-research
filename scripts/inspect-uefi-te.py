#!/usr/bin/env python3
"""Bounded TE structure from the newly inventoried outer UEFI section; read-only."""
import hashlib
import json
from pathlib import Path
import struct
import uuid

SOURCE = '0543144c7f583d7e870019d95206be2b864eae1fff878dcf9bcee52c063ecc50'
DIGEST = '064e33de95ebb586b0f103cfa03510a5459bca6068318294981673af8b4e9ed0'


def inspect(data):
    if len(data) < 40:
        raise ValueError('Truncated TE header')
    sig, machine, count, subsystem, stripped, entry, code, base = struct.unpack_from('<HHBBHIIQ',data)
    if sig != 0x5a56 or machine != 0xaa64 or not 1 <= count <= 96:
        raise ValueError('Not a bounded ARM64 TE')
    if stripped < 40 or 40+40*count > len(data):
        raise ValueError('Invalid stripped/header size')
    delta = stripped-40
    rows = []
    for n in range(count):
        name, vs, va, rs, rp = struct.unpack_from('<8sIIII',data,40+40*n)
        offset = rp-delta
        if rs and (offset < 40+40*count or offset+rs > len(data)):
            raise ValueError('Section outside TE file')
        rows.append(dict(name=name.rstrip(b'\0').decode('ascii'), virtual_size=vs,
                         rva=va, raw_size=rs, original_raw_pointer=rp,
                         te_offset=offset if rs else None))
    matches = [r for r in rows if r['rva'] <= entry < r['rva']+r['raw_size']]
    if len(matches) != 1:
        raise ValueError('Entry not uniquely file-backed')
    offset = matches[0]['te_offset']+entry-matches[0]['rva']
    return dict(machine=hex(machine), subsystem=subsystem, image_base=hex(base),
                stripped_size=stripped, stripped_delta=delta, entry_rva=hex(entry),
                entry_va=hex(base+entry), entry_file_offset=hex(offset),
                entry_prefix=data[offset:offset+16].hex(' '), sections=rows)


def main():
    p = Path('work/uefi-provider-source.elf')
    if p.stat().st_size > 16*1024*1024:
        raise ValueError('Source too large')
    source = p.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE:
        raise ValueError('Source hash mismatch')
    data = source[0x2f38:0x2f38+286920]
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('TE hash mismatch')
    result = inspect(data)
    token = uuid.UUID('0c00a314-11a1-4d7a-a5c8-70bd5f88e7df').bytes_le
    result.update(source_sha256=SOURCE, sha256=DIGEST, source_offset='0x2f38', size=len(data),
                  mitoken_literal_present=token in data,
                  limitation='New TE only; no functional consumer exclusion, no execution')
    Path('docs/uefi-te-structure.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Validated ARM64 TE:',len(result['sections']),'sections; entry',result['entry_va'])


if __name__ == '__main__':
    main()
