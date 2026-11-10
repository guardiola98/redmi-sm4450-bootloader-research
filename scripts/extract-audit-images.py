#!/usr/bin/env python3
"""Extract selected hash-pinned public firmware images to ignored work/ only."""
import argparse
import hashlib
import json
import runpy
from pathlib import Path
import tarfile

NAMES = {'tz.mbn', 'imagefv.elf', 'tools.fv'}
ALLOWED = NAMES | {'xbl_s.melf', 'xbl_config.elf'}
LIMIT = 64 * 1024 * 1024


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('archive', type=Path)
    ap.add_argument('--images', nargs='+', choices=sorted(ALLOWED), default=sorted(NAMES))
    args = ap.parse_args()
    names = set(args.images)
    records = {r['name']: r for r in json.loads(Path('bootchain-local.json').read_text())['images'] if r['name'] in names}
    for name, (digest, _) in runpy.run_path('scripts/inspect-compressed-uefi.py')['IMAGES'].items():
        if name in names and name not in records:
            records[name] = {'sha256': digest}
    if set(records) != names:
        raise ValueError('Missing pinned metadata')
    output = Path('work/audit-images')
    output.mkdir(exist_ok=True)
    seen = set()
    with tarfile.open(args.archive, 'r|gz') as archive:
        for member in archive:
            name = Path(member.name).name
            if name not in names:
                continue
            if name in seen or not member.isfile() or not 0 < member.size <= LIMIT:
                raise ValueError('Duplicate, nonregular or oversized image')
            seen.add(name)
            record = records[name]
            if 'size' in record and member.size != record['size']:
                raise ValueError('Size mismatch: ' + name)
            with archive.extractfile(member) as stream:
                data = stream.read(LIMIT + 1)
            if hashlib.sha256(data).hexdigest() != record['sha256']:
                raise ValueError('Hash mismatch: ' + name)
            target = output / name
            if target.exists():
                if target.read_bytes() != data:
                    raise ValueError('Different existing output: ' + name)
            else:
                with target.open('xb') as stream:
                    stream.write(data)
            print(name, len(data), record['sha256'], flush=True)
    if seen != names:
        raise ValueError('Missing images')

if __name__ == '__main__':
    main()
