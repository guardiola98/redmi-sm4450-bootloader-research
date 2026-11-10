#!/usr/bin/env python3
"""Hash-pinned evidence for outer TE config callbacks and the SCM HOB bridge.

Selected instruction bytes/addresses and table entries only. No disassembler,
firmware execution, external lookup or repeated GUID census.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import uuid


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


te = module('te', 'inspect-uefi-te.py')
pe = module('pe', 'inspect-mitoken-contract-evidence.py')


def read_va(data, layout, address, size):
    if size < 0:
        raise ValueError('Negative read size')
    rva = address - int(layout['image_base'], 16)
    matches = [s for s in layout['sections'] if s['rva'] <= rva and
               rva + size <= s['rva'] + s['raw_size']]
    if len(matches) != 1:
        raise ValueError('VA not uniquely file-backed')
    s = matches[0]
    offset = s['te_offset'] + rva - s['rva']
    return offset, data[offset:offset+size]


def main():
    source = Path('work/uefi-provider-source.elf')
    if source.stat().st_size > 16*1024*1024:
        raise ValueError('Source exceeds limit')
    outer = source.read_bytes()
    if hashlib.sha256(outer).hexdigest() != te.SOURCE:
        raise ValueError('Source hash mismatch')
    data = outer[0x2f38:0x2f38+286920]
    if hashlib.sha256(data).hexdigest() != te.DIGEST:
        raise ValueError('TE hash mismatch')
    layout = te.inspect(data)
    locations = [
        0xa700f324,0xa700f330,0xa700f34c,0xa7012440,0xa70125e8,
        0xa7012a48,0xa7012a54,0xa7012af4,0xa7012af8,0xa7012b08,
        0xa7012bd8,0xa7012c08,0xa7012c54,0xa7012dac,0xa7012db4,
        0xa7012dc8,0xa7012e70,0xa7014568,0xa7014598,0xa70145b0,
        0xa7018ce8,0xa7018d4c,
        0xa701d588,0xa701d58c,0xa701d590,0xa701d594,0xa701d598,
        0xa701d59c,0xa701d5a8,0xa701d5dc,0xa701d5e4,0xa701d618,
        0xa701d61c,0xa701d6f4,0xa701d6fc,0xa701d71c,0xa701d720,
        0xa701d724,0xa701d790,0xa701d7a8,0xa701d7b8,0xa701d7bc,0xa701d7c0,
    ]
    instructions = []
    for address in locations:
        offset, raw = read_va(data, layout, address, 4)
        instructions.append(dict(va=hex(address), te_offset=hex(offset),
                                 source_offset=hex(0x2f38+offset), bytes=raw.hex(' ')))
    tables = []
    for start, count in ((0xa703c3d0, 3), (0xa703c428, 5)):
        entries = []
        for address in range(start, start+8*count, 8):
            offset, raw = read_va(data, layout, address, 8)
            entries.append(dict(va=hex(address), te_offset=hex(offset),
                                value=hex(int.from_bytes(raw, 'little'))))
        tables.append(entries)
    scm = Path('work/provider-census/ScmDxeLA.pe').read_bytes()
    scm_sha = 'bf446081b8d1156f7de9c1b329dcd774f9df427d890d2ca67f6259f6a985d77d'
    if hashlib.sha256(scm).hexdigest() != scm_sha:
        raise ValueError('SCM hash mismatch')
    _, guid = read_va(data, layout, 0xa703c2f0, 16)
    if pe.read_rva(scm, 0xd048, 16) != guid:
        raise ValueError('Shared-library HOB GUID mismatch')
    report = dict(source_sha256=te.SOURCE, te_sha256=te.DIGEST,
                  te_source_offset='0x2f38', address_kind='TE preferred VA; not runtime addresses',
                  shared_library_hob=dict(guid=str(uuid.UUID(bytes_le=guid)),
                      te_va='0xa703c2f0', scm_rva='0xd048', scm_sha256=scm_sha),
                  tables=tables, instructions=instructions,
                  scope='Manually reviewed config path only; no full TE audit or effective runtime snapshot')
    Path('docs/uefi-config-contract.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Verified config TE layout, shared HOB identity and', len(instructions), 'instruction sites')


if __name__ == '__main__':
    main()
