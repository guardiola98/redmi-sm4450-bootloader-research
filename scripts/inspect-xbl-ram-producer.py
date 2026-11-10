#!/usr/bin/env python3
"""Pinned XBL RAM producer evidence; ELF metadata and selected original bytes.

Includes selected ChipInfo family provenance to constrain a QSEE consumer.
Reuses the authorized local image. No SMEM construction, device commands,
firmware execution, GUID census or arbitrary firmware downloads.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SOURCE_SHA = 'cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1'
ARM_SHA = '426cc7176df1b5417d97ee3269841db14012fc455da7c645f8435eac80c99128'
LIMIT = 16 * 1024 * 1024


def component(data, start):
    if start < 0 or start + 16 > len(data) or data[start:start+4] != b'\x7fELF':
        raise ValueError('Missing ELF header')
    cls, endian = data[start+4:start+6]
    if cls not in (1, 2) or endian != 1:
        raise ValueError('Unsupported ELF encoding')
    fmt = '<HHIQQQIHHHHHH' if cls == 2 else '<HHIIIIIHHHHHH'
    hsize = 16 + struct.calcsize(fmt)
    if start + hsize > len(data):
        raise ValueError('Truncated ELF header')
    h = struct.unpack_from(fmt, data, start+16)
    phfmt = '<IIQQQQQQ' if cls == 2 else '<IIIIIIII'
    phsize = struct.calcsize(phfmt)
    if h[7] < hsize or not 0 < h[9] <= 64 or h[8] < phsize:
        raise ValueError('Invalid ELF header dimensions')
    table_end = h[4] + h[8] * h[9]
    if h[4] < hsize or start + table_end > len(data):
        raise ValueError('Program headers out of bounds')
    end = max(h[7], table_end)
    segments = []
    for i in range(h[9]):
        p = struct.unpack_from(phfmt, data, start+h[4]+i*h[8])
        if cls == 2:
            typ, flags, off, va, pa, size, mem, align = p
        else:
            typ, off, va, pa, size, mem, flags, align = p
        if start + off + size > len(data) or (typ == 1 and size > mem):
            raise ValueError('Segment out of bounds')
        end = max(end, off + size)
        segments.append(dict(type=typ, offset=off, va=va, pa=pa,
                             file_size=size, memory_size=mem, flags=flags))
    if start + end > len(data):
        raise ValueError('Component out of bounds')
    return dict(offset=start, size=end, elf_class=cls, machine=h[1],
                entry=h[3], segments=segments,
                sha256=hashlib.sha256(data[start:start+end]).hexdigest())


def read_va(data, layout, address, size):
    if size < 0:
        raise ValueError('Negative read')
    matches = [s for s in layout['segments'] if s['type'] == 1 and
               s['va'] <= address and address + size <= s['va'] + s['file_size']]
    if len(matches) != 1:
        raise ValueError('Address not uniquely file-backed')
    s = matches[0]
    offset = layout['offset'] + s['offset'] + address - s['va']
    return offset, data[offset:offset+size]


def inspect(data):
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Unexpected XBL source hash')
    layouts, start = [], 0
    while start < len(data):
        layout = component(data, start)
        layouts.append(layout)
        start += layout['size']
    if [(c['offset'], c['elf_class'], c['machine']) for c in layouts] != [
            (0, 1, 1), (0x1c2f4, 1, 243), (0x4af94, 2, 183)]:
        raise ValueError('Unexpected component layout')
    arm = layouts[2]
    if arm['sha256'] != ARM_SHA or arm['entry'] != 0x14819fa8:
        raise ValueError('AArch64 component mismatch')
    sites = [
        0x148578c4,0x148578d0,0x148578e4,0x148578ec,0x148578f0,
        0x148578f8,0x148578fc,0x14857904,0x14857908,0x1485790c,
        0x14857918,0x14857928,0x14857938,0x1485793c,
        0x1481bfc0,0x1481bfc8,0x1481bfd0,0x1481c064,0x1481c068,0x1481c074,
        0x1485c5b4,0x1485c5c0,0x1485c5c4,0x1485c5cc,0x1485c5e4,0x1485c5f8,
        0x1485c608,0x1485c650,0x1485c654,0x1485c658,0x1485c65c,
        0x1485c6c8,0x1485c6d0,0x1485c6f4,0x1485c6fc,0x1485c718,0x1485c738,0x1485c740,
        0x1485c7ac,0x1485c7b0,0x1485c7bc,0x1485c7d4,0x1485c7dc,0x1485c7e0,
        0x1485c7e8,0x1485c7ec,0x1485c7f0,0x1485c860,0x1485c868,0x1485c874,
        0x1485c894,0x1485c898,0x1485c89c,0x1485c8b0,0x1485c8b4,0x1485c8b8,
        0x1485c8bc,0x1485c8c0,0x1485c8c8,
        0x1485c98c,0x1485c994,0x1485c9bc,0x1485c9c4,0x1485c9c8,
        0x1485ca3c,0x1485ca4c,0x1485ca60,0x1485ca64,0x1485ca78,0x1485ca80,
        0x1485cb10,0x1485cb38,
    ]
    instructions = []
    for address in sites:
        offset, raw = read_va(data, arm, address, 4)
        instructions.append(dict(va=hex(address), source_offset=hex(offset),
                                 component_offset=hex(offset-arm['offset']), bytes=raw.hex(' ')))
    words = []
    for address in [0x148b6928,0x148b6930,0x148c3b60,0x148c3b68,
                    0x148c38b8,0x148c38d0,0x148c7bd0,0x148c7be0,0x148c7be8]:
        offset, raw = read_va(data, arm, address, 8)
        words.append(dict(va=hex(address), source_offset=hex(offset),
                          value=hex(int.from_bytes(raw, 'little'))))
    if int(words[1]['value'],16) != 0xaf9ec4e29da5e0a8:
        raise ValueError('RAM signatures mismatch')
    # Fixed stage label, no arbitrary strings or firmware-wide string dump.
    _, raw = read_va(data, arm, 0x148b02a5, 32)
    if raw.split(b'\0')[0] != b'boot_update_ram_partition_table':
        raise ValueError('Stage label mismatch')
    chip_sites = [0x14825384,0x14825388,0x14825a3c,0x14825a48,
                  0x14825a64,0x14825a68,0x14825aec,0x14825af4,0x14825af8,
                  0x14832220,0x1483222c,0x148322b4,0x148322c0,
                  0x148322d0,0x148322dc,0x148322e4,0x148322f4,
                  0x14832314,0x14832318,0x14832330,0x14832334,
                  0x1483237c,0x14832380,0x148323c4,0x148acd18,
                  0x148acd28,0x148aceb8,0x148acec4]
    chip_instructions = []
    for address in chip_sites:
        offset, raw = read_va(data, arm, address, 4)
        chip_instructions.append(dict(va=hex(address), source_offset=hex(offset), bytes=raw.hex(' ')))
    _, raw = read_va(data, arm, 0x148c70d8, 32)
    chip_table, chip_count, family_table, family_count = struct.unpack('<QQQQ', raw)
    if (chip_table,chip_count,family_table,family_count) != (0x148b3180,20,0x148b3360,8):
        raise ValueError('Unexpected ChipInfo table dimensions')
    families = []
    for i in range(family_count):
        address = family_table+i*16
        _, raw = read_va(data, arm, address, 16)
        major, minor, family, fallback_id = struct.unpack('<IIII', raw)
        families.append(dict(va=hex(address), major=major, minor=minor,
                             family=family, fallback_soc_id=fallback_id))
    _, raw = read_va(data, arm, 0x148b32b8, 24)
    name, soc_id, raw_part, modem, padding = struct.unpack('<QIIII', raw)
    _, name_bytes = read_va(data, arm, name, 32)
    if soc_id != 568 or name_bytes.split(b'\0')[0] != b'SM_CLARENCE':
        raise ValueError('Unexpected selected ChipInfo row')
    chip_words = []
    for address in (0x148bbbf8,0x148bbc08,0x148bbc80):
        offset, raw = read_va(data, arm, address, 8)
        chip_words.append(dict(va=hex(address), value=hex(int.from_bytes(raw, 'little'))))
    chip_evidence = dict(instructions=chip_instructions, family_rows=families, selected_words=chip_words,
                        selected_chip=dict(va='0x148b32b8', soc_id=soc_id, raw_part=raw_part,
                                           name='SM_CLARENCE'),
                        note='Family uses hardware family fields; raw-part ID lookup does not alone prove family')
    ddr_sites = [0x14821b54,0x14821b58,0x14821b70,0x14821b78,0x14821b84,0x14821b8c,0x14821b90,
                 0x14821c14,0x14821c24,0x14821c2c,0x14821c54,0x14821c78,
                 0x14821c7c,0x14821cc8,0x14821dbc,
                 0x14821e00,0x14821e10,0x14821e20,0x14821e24,0x14821e28,
                 0x14821e70,0x14821e74,0x14821e78,0x14821e84,
                 0x1484f028,0x1484f02c,0x1484f040,0x1484f048,
                 0x1484f11c,0x1484f124,0x1484f1a8,0x1484f1ac,
                 0x14851464,0x14851468,0x1485146c,0x1485147c,0x14851480,
                 0x148514cc,0x148514d4,0x148514e8,0x148514ec,0x148514f0,
                 0x1485152c,0x14851534,0x1485154c,0x14851550,0x14851558,0x14851580,
                 0x1485c770,0x1485c774]
    ddr_instructions = []
    for address in ddr_sites:
        offset, raw = read_va(data, arm, address, 4)
        ddr_instructions.append(dict(va=hex(address), source_offset=hex(offset), bytes=raw.hex(' ')))
    ddr_words = []
    for address in [0x148c3408,0x148c3420,0x148c3468,0x148c3480,
                    0x148c4f20,0x148c4f30,0x148c4f38,0x148c4f40,
                    0x148c4ee8,0x148c4ef0,0x148c4f10,0x148c7b60]:
        offset, raw = read_va(data, arm, address, 8)
        ddr_words.append(dict(va=hex(address), source_offset=hex(offset),
                              value=hex(int.from_bytes(raw, 'little'))))
    ddr_evidence = dict(instructions=ddr_instructions, selected_words=ddr_words,
                        scope='DDR getter initialization, metadata source and exclusion gate; no runtime DDR values')
    report = dict(source_sha256=SOURCE_SHA, components=layouts,
                  address_kind='Preferred ELF VA, not observed runtime addresses',
                  stage_name='boot_update_ram_partition_table',
                  instructions=instructions, selected_words=words, chip_family=chip_evidence,
                  ddr_providers=ddr_evidence,
                  scope='Identified RAM producer/updater and selected ChipInfo provenance; no complete XBL audit or runtime SMEM capture')
    return report, data[arm['offset']:arm['offset']+arm['size']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extract', action='store_true', help='Write the verified ELF component in ignored work/')
    args = parser.parse_args()
    path = Path('work/audit-images/xbl_s.melf')
    if path.stat().st_size > LIMIT:
        raise ValueError('Source exceeds read limit')
    report, arm = inspect(path.read_bytes())
    if args.extract:
        output = Path('work/audit-images/xbl-aarch64.elf')
        if output.exists() and output.read_bytes() != arm:
            raise ValueError('Refusing differing existing output')
        if not output.exists():
            output.write_bytes(arm)
    Path('docs/xbl-ram-producer-evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Verified 3 consecutive ELF components and',len(report['instructions']),'producer/updater instruction sites,',len(report['chip_family']['instructions']),'ChipInfo sites and',len(report['ddr_providers']['instructions']),'DDR provider sites')


if __name__ == '__main__':
    main()
