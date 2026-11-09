"""Read-only PE evidence; no firmware execution. Run from repository root."""
import hashlib
from pathlib import Path
import struct
import uuid


def read_rva(data, rva, size):
    pe = struct.unpack_from('<I', data, 60)[0]
    n = struct.unpack_from('<H', data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from('<H', data, pe + 20)[0]
    for i in range(n):
        _, _, va, raw_size, offset = struct.unpack_from('<8sIIII', data, table + 40*i)
        if va <= rva and rva + size <= va + raw_size:
            return data[offset+rva-va:offset+rva-va+size]
    raise ValueError('RVA outside file-backed sections')


if __name__ == '__main__':
    data = Path('work/protocols/MiTokenDxe.pe').read_bytes()
    assert hashlib.sha256(data).hexdigest() == '5960ae5e4b2ae712f8ef1e854cb37e3fcaf0ecb1427aa40eeebd733829be68b9'
    for rva in (0x9078, 0x9098, 0x90a8):
        print(hex(rva), uuid.UUID(bytes_le=read_rva(data, rva, 16)))
    print('table', [hex(x) for x in struct.unpack('<4Q', read_rva(data, 0x9648, 32))])
    for rva in (0x1b70, 0x1b84, 0x1bac, 0x1bc8, 0x1c00, 0x1c04, 0x1c18, 0x1c28, 0x1c74, 0x1ca4, 0x2c44):
        print(hex(rva), read_rva(data, rva, 4).hex(' '))
    for path in [*Path('work/protocols').glob('*.pe'), *Path('work/uefi-extracted').rglob('*.pe')]:
        blob = path.read_bytes()
        print(path, 'MiToken GUID file offsets', [hex(i) for i in range(len(blob)-15) if blob[i:i+16] == read_rva(data, 0x90a8, 16)])
