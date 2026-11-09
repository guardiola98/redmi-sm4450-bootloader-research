#!/usr/bin/env python3
"""Hash-pinned EL3 vectors, dispatch tables and selected original instructions.

Only reads the local ELF; does not execute/emulate firmware or read a device.
The output records static evidence, not runtime selection of this monitor.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
spec = importlib.util.spec_from_file_location('tz', Path(__file__).with_name('inspect-tz-structure.py'))
tz = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tz)


def main():
    source = Path('work/audit-images/tz.mbn')
    if source.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Input exceeds 8 MiB audit limit')
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != tz.DIGEST:
        raise ValueError('Hash mismatch')
    rows = tz.segments(data)

    def read(va, size):
        if not 0 < size <= 4096:
            raise ValueError('Invalid bounded read size')
        matches = [r for r in rows if r['type'] == 1 and r['va'] <= va and va+size <= r['va']+r['filesz']]
        if len(matches) != 1:
            raise ValueError('Ambiguous or unmapped bytes')
        off = matches[0]['offset'] + va - matches[0]['va']
        return off, data[off:off+size]

    literals = []
    for va in (0x14680218, 0x14684b20):
        off, raw = read(va, 8)
        base = struct.unpack('<Q', raw)[0]
        if base != 0x14680800:
            raise ValueError('Unexpected vector base')
        literals.append(dict(va=hex(va), offset=hex(off), value=hex(base)))
    handlers = []
    for va, expected in ((0x14680c68, 0x1c00ec78), (0x14680d70, 0x1c00ee70),
                         (0x14680e58, 0x1c00ec78), (0x14680f60, 0x1c00ee70),
                         (0x1c00ee60, 0x1c01c058)):
        off, raw = read(va, 8)
        target = struct.unpack('<Q', raw)[0]
        if target != expected:
            raise ValueError('Unexpected handler/global literal')
        handlers.append(dict(va=hex(va), offset=hex(off), bytes=raw.hex(' '),
                             target=hex(target)))
    slots = []
    for i in range(16):
        va = 0x14680800 + i*128
        off, raw = read(va, 12)
        slots.append(dict(index=i, va=hex(va), offset=hex(off), prefix=raw.hex(' ')))
    tables = []
    for name, va, base, count, fmt, scale in (
            ('secure_command_1_to_69', 0x1c0157c0, 0x1c00ff40, 69, '<i', 1),
            ('command_1_subtype_1_to_7', 0x1c0158e8, 0x1c01003c, 7, '<i', 1),
            ('context_selector_0_to_3', 0x1c015904, 0x1c010aa0, 4, '<B', 4)):
        entries = []
        width = struct.calcsize(fmt)
        for index in range(count):
            off, raw = read(va + index*width, width)
            relative = struct.unpack(fmt, raw)[0]
            target = base + scale*relative
            read(target, 4)  # Every decoded target must be file-backed.
            entries.append(dict(index=index, offset=hex(off), bytes=raw.hex(' '),
                                relative=relative, target=hex(target)))
        tables.append(dict(name=name, va=hex(va), base=hex(base), entries=entries))
    if tables[0]['entries'][0]['target'] != '0x1c01001c':
        raise ValueError('Unexpected command 1 target')
    if tables[1]['entries'][2]['target'] != '0x1c010520':
        raise ValueError('Unexpected subtype 3 target')
    instructions = []
    for va in (
            0x146800d8, 0x146849e0, 0x14680c10, 0x14680c14, 0x14680c5c,
            0x14681000, 0x14681048,
            0x1c00ec7c, 0x1c00ec80, 0x1c00ec8c, 0x1c00ec94, 0x1c00ec98,
            0x1c00ed48, 0x1c00ed58, 0x1c00ed6c, 0x1c00ede0, 0x1c00edf0,
            0x1c00fa40, 0x1c00fa70, 0x1c00fb48, 0x1c00fb74,
            0x1c00fc3c, 0x1c00fcac, 0x1c00fcb0,
            0x1c00ff44, 0x1c010020, 0x1c010040, 0x1c010554,
            0x1c01055c, 0x1c010560, 0x1c010b2c, 0x1c0105bc, 0x1c0105d4,
            0x1c00f884, 0x1c00f89c, 0x1c00f8ac, 0x1c00f8bc,
            0x1c00f8c0, 0x1c00f8cc, 0x1c00f9a8, 0x1c00f9b8, 0x1c00f9d4,
            0x1c00fbc0, 0x1c00fcec, 0x1c00fd00, 0x1c00fd0c, 0x1c00fd80,
            0x1c010934, 0x1c010984, 0x1c010988,
            0x1c010e18, 0x1c010e28, 0x1c010e68,
            0x1c01106c, 0x1c01107c, 0x1c011080, 0x1c011084,
            0x1c011154, 0x1c00f084, 0x1c00f088):
        off, raw = read(va, 4)
        instructions.append(dict(va=hex(va), offset=hex(off), bytes=raw.hex(' ')))
    report = dict(sha256=tz.DIGEST, literals=literals, handlers=handlers,
                  slots=slots, tables=tables, instructions=instructions,
                  scope='Static EL3 route under initialized contexts; not live reachability')
    Path('docs/tz-monitor.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Verified vector literals, 16 prefixes, 80 table entries and instruction bytes')

if __name__ == '__main__':
    main()
