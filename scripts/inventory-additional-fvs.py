#!/usr/bin/env python3
"""Bounded offline recursive census of hash-pinned imagefv/tools; no execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import uuid


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

loc = module('loc', 'locate-uefi-protocol-modules.py')
codec = module('codec', 'inspect-compressed-uefi.py')
# Deliberate bounded increase from previous 32 MiB experiment.
codec.OUT_LIMIT = 128 * 1024 * 1024
TOKEN = uuid.UUID('0c00a314-11a1-4d7a-a5c8-70bd5f88e7df')


def decode_depex(body):
    """Validate a bounded DXE dependency expression, not a runtime evaluator."""
    if not body or len(body) > 65536:
        raise ValueError('Empty or oversized DEPEX')
    refs, ops, depth, at = [], [], 0, 0
    while at < len(body):
        op = body[at]
        at += 1
        ops.append(op)
        if op in (0, 1, 2):
            if at + 16 > len(body):
                raise ValueError('Truncated GUID operand')
            refs.append(dict(opcode=op, guid=str(uuid.UUID(bytes_le=body[at:at+16]))))
            at += 16
            if op in (0, 1):
                if len(ops) != 1 or body[at:] != b'\x08':
                    raise ValueError('Invalid BEFORE/AFTER expression')
                return dict(opcodes=ops+[8], references=refs, ordering_only=True)
            depth += 1
        elif op in (3, 4):
            if depth < 2:
                raise ValueError('Binary operator stack underflow')
            depth -= 1
        elif op == 5:
            if depth < 1:
                raise ValueError('NOT stack underflow')
        elif op in (6, 7):
            depth += 1
        elif op == 8:
            if at != len(body) or depth != 1:
                raise ValueError('Invalid END or final stack')
            return dict(opcodes=ops, references=refs, ordering_only=False)
        elif op == 9:
            if len(ops) != 1:
                raise ValueError('SOR must be first')
        else:
            raise ValueError('Unknown DEPEX opcode')
    raise ValueError('Missing END')


def census(data, base, label, *, scan_guids=True, collect_metadata=False):
    rows, gaps = [], []
    raw = []
    types = {}
    names = []
    metadata = []
    budget = [256 * 1024 * 1024]

    def sections(blob, start, end, path, depth, owner=None):
        if depth > 12:
            gaps.append({'path': path, 'reason': 'depth limit'})
            return
        for a, b, typ, hs in loc.sections(blob, start, end):
            route = path + [f'section:{typ:02x}@{a:x}']
            body = blob[a+hs:b]
            types[hex(typ)] = types.get(hex(typ), 0) + 1
            if typ == 0x15:
                name = body.decode("utf-16le", errors="replace").rstrip("\0")
                names.append(name)
                if owner is not None:
                    owner['names'].append(name)
            if typ == 0x13 and owner is not None:
                dep = dict(path=route, size=len(body), sha256=hashlib.sha256(body).hexdigest())
                try:
                    dep.update(decode_depex(body))
                except ValueError as exc:
                    dep['error'] = str(exc)
                owner['depex'].append(dep)
            if typ == 0x19:
                raw.append(dict(path=route, size=len(body), sha256=hashlib.sha256(body).hexdigest(), signature=body[:4].hex(), token_present=TOKEN.bytes_le in body if scan_guids else None))
            if typ in (0x10, 0x12):
                row = dict(path=route, type='PE' if typ == 0x10 else 'TE', size=len(body), sha256=hashlib.sha256(body).hexdigest(), token_offsets=[hex(i) for i in range(len(body)-15) if body[i:i+16] == TOKEN.bytes_le] if scan_guids else None)
                rows.append(row)
                if owner is not None:
                    owner['executables'].append(row)
            elif typ == 0x17:
                volume(blob, a+hs, b, route, depth+1)
            elif typ == 2 and len(body) >= 20:
                guid = uuid.UUID(bytes_le=body[:16])
                offset = struct.unpack_from('<H', body, 16)[0]
                if not hs+20 <= offset <= b-a:
                    gaps.append(dict(path=route, reason='invalid guided offset'))
                    continue
                decoded, error = codec.decompress_limited(blob[a+offset:b], guid)
                if error:
                    gaps.append(dict(path=route, reason=error, guid=str(guid)))
                elif len(decoded) > budget[0]:
                    gaps.append(dict(path=route, reason='cumulative budget'))
                else:
                    budget[0] -= len(decoded)
                    sections(decoded, 0, len(decoded), route+[f'decoded:{guid}:{hashlib.sha256(decoded).hexdigest()}'], depth+1, owner)
            elif typ == 1:
                gaps.append(dict(path=route, reason='standard compression not decoded'))

    def volume(blob, offset, end, path, depth):
        start, stop, _ = loc.parse_fv(blob, offset, end)
        for a, b, begin, guid, ft in loc.ffs_files(blob, start, stop):
            if ft in (0x01, 0xf0):
                if ft == 0x01:
                    gaps.append(dict(path=path+[str(guid)], reason='raw FFS'))
                continue
            owner = None
            if collect_metadata:
                owner = dict(ffs=str(guid), file_type=ft, names=[], executables=[], depex=[])
                metadata.append(owner)
            sections(blob, begin, b, path+[f'ffs:{guid}@{a:x}'], depth, owner)

    volume(data, base, len(data), [label], 0)
    result = dict(image=label, sha256=hashlib.sha256(data).hexdigest(), modules=rows, raw_sections=raw, gaps=gaps, section_types=types, ui_names=names, parser_limit='Existing FV/FFS readers can stop at malformed/trailing data; no PI checksum validation')
    if collect_metadata:
        result['ffs_metadata'] = metadata
    return result


if __name__ == '__main__':
    report = []
    for name in ('imagefv.elf', 'tools.fv'):
        data = (Path('work/audit-images') / name).read_bytes()
        digest, base = codec.IMAGES[name]
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Hash mismatch')
        result = census(data, base, name)
        report.append(result)
        print(name, 'modules', len(result['modules']), 'gaps', len(result['gaps']), 'token matches', sum(bool(r['token_offsets']) for r in result['modules']))
    Path('docs/additional-fv-census.json').write_text(json.dumps(report, indent=2)+'\n')
