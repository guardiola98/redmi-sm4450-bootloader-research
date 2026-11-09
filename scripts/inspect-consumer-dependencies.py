#!/usr/bin/env python3
"""Read local DEPEX via the existing bounded census; do not repeat PE GUID scans."""
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('fv', Path(__file__).with_name('inventory-additional-fvs.py'))
fv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fv)


def main():
    images = []
    for name, path in (('uefi.elf', 'work/uefi-provider-source.elf'),
                       ('tools.fv', 'work/audit-images/tools.fv')):
        source = Path(path)
        if source.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('Input exceeds 16 MiB limit')
        data = source.read_bytes()
        expected, base = fv.codec.IMAGES[name]
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Source hash mismatch')
        result = fv.census(data, base, name, scan_guids=False, collect_metadata=True)
        # Preserve provenance without duplicating executable rows in the report.
        result.pop('modules')
        result.pop('raw_sections')
        deps = [d for m in result['ffs_metadata'] for d in m['depex']]
        hits = [m['names'] for m in result['ffs_metadata'] for d in m['depex']
                if any(r['guid'] == str(fv.TOKEN) for r in d.get('references', []))]
        print(name, 'executables', sum(len(m['executables']) for m in result['ffs_metadata']),
              'depex', len(deps), 'errors', sum('error' in d for d in deps), 'MiToken dependencies', hits)
        images.append(result)
    Path('docs/consumer-dependencies.json').write_text(json.dumps(images, indent=2)+'\n')


if __name__ == '__main__':
    main()
