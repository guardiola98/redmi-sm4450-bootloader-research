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
KEYS = ('SecurityFlag', 'SmcInvokeConfig', 'ConfigParameterCount',
        'PlatConfigFileName', 'OsTypeString', 'ChipID_RegAddr',
        'SharedIMEMBaseAddr', 'OverRideSharedImemBootCfg', 'DDRInfoNotifyFlag',
        'EnableMultiThreading', 'DecompressionRequired', 'SecPagePoolCount',
        'MaxCoreCnt', 'EarlyInitCoreCnt', 'EnableMultiCoreFvDecompression')


def summarize_text(raw):
    """Line-level resource inventory, not execution/emulation of its parser."""
    values = {key: [] for key in KEYS}
    sections, rows = [], []
    section = None
    for number, line in enumerate(raw.decode('ascii').splitlines(), 1):
        text = line.strip()
        if not text or text.startswith(('#', ';')):
            continue
        if text.startswith('[') and text.endswith(']'):
            section = text[1:-1]
            sections.append(section)
            continue
        key, sep, value = text.partition('=')
        if not sep:
            continue
        key = key.strip()
        if key in values:
            values[key].append(value.strip())
        if section == 'ConfigParameters':
            rows.append((key, number))
    names = [key.casefold() for key, _ in rows]
    return dict(selected_keys=values, section_names=sections,
                config_parameter_declarations=sum(key == 'ConfigParameterCount' for key, _ in rows),
                config_parameter_value_rows=sum(key != 'ConfigParameterCount' for key, _ in rows),
                duplicate_parameter_names=sorted({key for key in names if names.count(key) > 1}),
                casefold_selected_counts={key: names.count(key.casefold()) for key in KEYS},
                selected_key_lines={key: [line for name, line in rows if name == key] for key in KEYS})


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
            rows.append(dict(ffs=str(guid), ffs_offset=hex(at), section=hex(ss),
                             section_type=hex(typ), data_offset=hex(ss+hs),
                             size=len(raw), sha256=CONFIG_SHA, **summarize_text(raw)))
    if len(rows) != 1:
        raise ValueError('Expected one raw config')
    metadata = json.loads(Path('docs/consumer-dependencies.json').read_text())
    names = [name for image in metadata for module in image['ffs_metadata'] for name in module['names']]
    report = dict(source=str(source), sha256=fv.EXPECTED_SHA256, config=rows[0],
                  named_resource_counts={name: names.count(name) for name in ('uefiplat.cfg', 'uefiplatLA.cfg')},
                  name_inventory_scope='Existing uefi.elf/tools.fv FFS metadata only',
                  scope='Static resource; traced library predicts values conditionally, not a runtime snapshot')
    Path('docs/scm-static-config.json').write_text(json.dumps(report, indent=2)+'\n')
    print('Verified raw config; selected keys:', rows[0]['selected_keys'])


if __name__ == '__main__':
    main()
