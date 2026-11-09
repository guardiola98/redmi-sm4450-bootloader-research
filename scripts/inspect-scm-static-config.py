#!/usr/bin/env python3
"""Bounded, hash-pinned view of SCM-related keys in the local raw config.

Reports only selected keys and provenance, not the proprietary config body.
This is an artifact inspection, not proof of the effective runtime config.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    'fv', Path(__file__).with_name('locate-uefi-protocol-modules.py'))
fv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fv)
CONFIG_FFS = 'dde58710-41cd-4306-dbfb-3fa90bb1d2dd'
CONFIG_SHA = 'aece4446b3ea41615b0c7aadc79fd2f4c9173fb7a92d241647bd26ed6b62aa37'
KEYS = ('SecurityFlag', 'SmcInvokeConfig')


def main():
    source = Path('work/uefi-provider-source.elf')
    if source.stat().st_size > fv.LIMIT:
        raise ValueError('Source exceeds read limit')
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != fv.EXPECTED_SHA256:
        raise ValueError('Unexpected source hash')
    start, end, _ = fv.parse_fv(data, 0x1000, len(data))
    rows = []
    for at, last, begin, guid, _ in fv.ffs_files(data, start, end):
        if str(guid) != CONFIG_FFS:
            continue
        for ss, se, typ, hs in fv.sections(data, begin, last):
            if typ != 0x19:
                continue
            raw = data[ss+hs:se]
            if hashlib.sha256(raw).hexdigest() != CONFIG_SHA:
                raise ValueError('Unexpected raw config hash')
            values = {key: [] for key in KEYS}
            for line in raw.decode('ascii').splitlines():
                key, sep, value = line.partition('=')
                if sep and key.strip() in values:
                    values[key.strip()].append(value.strip())
            rows.append(dict(ffs=str(guid), ffs_offset=hex(at), section=hex(ss),
                             section_type=hex(typ), data_offset=hex(ss+hs),
                             size=len(raw), sha256=CONFIG_SHA, selected_keys=values))
    if len(rows) != 1:
        raise ValueError('Expected one raw config')
    report = dict(source=str(source), sha256=fv.EXPECTED_SHA256, config=rows[0],
                  scope='Static resource only; effective library values/overrides not established')
    Path('docs/scm-static-config.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Verified raw config; selected keys:', rows[0]['selected_keys'])


if __name__ == '__main__':
    main()
