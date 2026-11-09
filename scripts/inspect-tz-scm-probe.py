#!/usr/bin/env python3
"""Read hash-pinned lookup table and SCM selector bytes; never execute firmware."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    tz = load_module('tz', 'inspect-tz-structure.py')
    pe = load_module('pe', 'inspect-mitoken-contract-evidence.py')
    data = Path('work/audit-images/tz.mbn').read_bytes()
    if hashlib.sha256(data).hexdigest() != tz.DIGEST:
        raise ValueError('TZ hash mismatch')
    rows = tz.segments(data)

    def read_va(va, size):
        matches = [r for r in rows if r['type'] == 1 and
                   r['va'] <= va and va + size <= r['va'] + r['filesz']]
        if size < 0 or len(matches) != 1:
            raise ValueError('Non-unique or non-file-backed VA')
        r = matches[0]
        offset = r['offset'] + va - r['va']
        return offset, data[offset:offset+size]

    entries = []
    for index in range(10):
        va = 0x1c13fb00 + 2*index
        off, raw = read_va(va, 2)
        displacement = struct.unpack('<H', raw)[0]
        entries.append(dict(identifier=hex(0x02000601+index), va=hex(va),
                            offset=hex(off), bytes=raw.hex(' '),
                            branch_target=hex(0x1c09a1dc+4*displacement)))
    evidence = []
    for va in (0x1c09a1e8, 0x1c09a1ec, 0x1c09b350, 0x1c077804,
               0x1c07780c, 0x1c077810, 0x1c07782c, 0x1c038280,
               0x1c038288, 0x1c059b8c, 0x1c0779f0, 0x1c077af8,
               0x1c077850, 0x1c077864, 0x1c0778a8, 0x1c0778ac,
               0x1c0778b0, 0x1c0778b4, 0x1c07795c):
        offset, raw = read_va(va, 4)
        evidence.append(dict(va=hex(va), offset=hex(offset), bytes=raw.hex(' ')))
    scm_data = Path('work/provider-census/ScmDxeLA.pe').read_bytes()
    scm_hash = hashlib.sha256(scm_data).hexdigest()
    if scm_hash != 'bf446081b8d1156f7de9c1b329dcd774f9df427d890d2ca67f6259f6a985d77d':
        raise ValueError('ScmDxeLA hash mismatch')
    selector = [dict(rva=hex(a), bytes=pe.read_rva(scm_data,a,4).hex(' '))
                for a in (0x4558,0x455c,0x4560,0x4564,0x4580,0x4588,0x458c,0x14fc,0x1500,
                          0x180c,0x1814,0x1820,0x1838,0x183c,0x1840,
                          0x45d4,0x45d8,0x45dc,0x45e0)]
    report = dict(tz_sha256=tz.DIGEST, scm_sha256=scm_hash,
                  lookup_table=entries, tz_instructions=evidence,
                  scm_instructions=selector,
                  scope='Static table/bytes; no claim of monitor routing or live selection')
    Path('docs/tz-scm-probe.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Verified 10 table entries and selected instruction bytes')


if __name__ == '__main__':
    main()
