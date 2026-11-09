#!/usr/bin/env python3
"""Hash-pinned offline ELF64 map and candidate service-table words, not dispatch proof."""
import hashlib
import json
from pathlib import Path
import struct

DIGEST = 'f7d943b1de872d239468fe30cc4fab92c5acb0405203e9f9e38436cefd7e1a76'


def segments(data):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Not ELF64 LE')
    if struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('Not AArch64')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or offset + count*size > len(data):
        raise ValueError('Invalid program header bounds')
    rows = []
    for i in range(count):
        typ, flags, off, va, pa, fs, ms, align = struct.unpack_from('<II6Q', data, offset+i*size)
        if off > len(data) or fs > len(data)-off or (typ == 1 and fs > ms):
            raise ValueError('Invalid segment bounds')
        rows.append(dict(index=i, type=typ, flags=flags, offset=off, va=va, filesz=fs, memsz=ms, align=align))
    return rows


def map_offset(rows, offset):
    return [r['va']+offset-r['offset'] for r in rows if r['type']==1 and r['offset'] <= offset < r['offset']+r['filesz']]


if __name__ == '__main__':
    data = Path('work/audit-images/tz.mbn').read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('Hash mismatch')
    rows = segments(data)
    hits = []
    for value in (0x1401, 0x02001401, 0x42001401):
        needle = struct.pack('<I', value)
        at = data.find(needle)
        while at >= 0:
            hits.append(dict(value=hex(value), offset=hex(at), va=[hex(x) for x in map_offset(rows,at)], aligned=at%4==0))
            at = data.find(needle, at+1)
    report = dict(sha256=DIGEST, entry=hex(struct.unpack_from('<Q',data,24)[0]), segments=rows, candidate_words=hits, limitation='Literal words are not verified service registrations; flags do not prove runtime page permissions')
    Path('docs/tz-structure.json').write_text(json.dumps(report,indent=2)+'\n')
    print('segments',len(rows),'LOAD',sum(r['type']==1 for r in rows),'candidate words',len(hits))
    print(hits[:20])
