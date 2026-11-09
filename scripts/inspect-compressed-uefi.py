#!/usr/bin/env python3
"""Safely inspect inner UEFI sections in validated firmware images, read-only.

Recognizes Qualcomm GZIP GUID and standard UEFI LZMA guided sections.
Reads matching images from existing TGZ, hashes them, decompresses in memory
with strict output limit, inventories nested FFS/sections and scans two
protocol GUIDs. It does not execute, flash or extract files to disk.
"""
import argparse
import hashlib
import lzma
from pathlib import Path
import struct
import tarfile
import uuid
import zlib

IMAGES = {
    "uefi.elf": ("0543144c7f583d7e870019d95206be2b864eae1fff878dcf9bcee52c063ecc50", 0x1000),
    "imagefv.elf": ("51220103d9d5f2c8e11f3bfe8a221db9cba2bd0478902037175067e182c94332", 0x1000),
    "tools.fv": ("d7f0c4034bb3236e3878dfd56116217dc34afd5b3d41e7a1f1e71fddbf77a002", 0),
}
GZIP_GUID = uuid.UUID("1d301fe9-be79-4353-91c2-d23bc959ae0c")
LZMA_GUID = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf")
SEARCH = {
    "token": uuid.UUID("0c00a314-11a1-4d7a-a5c8-70bd5f88e7df"),
    "verifiedboot": uuid.UUID("8e5eff91-21b6-47d3-af2b-c15a01e020ec"),
}
OUT_LIMIT = 32 * 1024 * 1024


def decompress_limited(data, compression):
    if compression == GZIP_GUID:
        for fmt in (31, 47):  # gzip first, then gzip/zlib autodetect
            try:
                obj = zlib.decompressobj(fmt)
                result = obj.decompress(data, OUT_LIMIT + 1)
                if len(result) > OUT_LIMIT:
                    return None, "decompressed size exceeds limit"
                result += obj.flush(OUT_LIMIT + 1 - len(result))
                if obj.eof and len(result) <= OUT_LIMIT:
                    return result, None
            except zlib.error:
                pass
        return None, "gzip/zlib decoding failed"
    if compression == LZMA_GUID:
        try:
            obj = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO, memlimit=128 * 1024 * 1024)
            result = obj.decompress(data, max_length=OUT_LIMIT + 1)
            if len(result) > OUT_LIMIT:
                return None, "decompressed size exceeds limit"
            if not obj.eof:
                return None, "incomplete or oversized lzma stream"
            return result, None
        except (lzma.LZMAError, EOFError):
            return None, "lzma decoding failed"
    return None, "unknown compression GUID"


def hits(data):
    out = []
    for name, guid in SEARCH.items():
        for enc, needle in (("UEFI", guid.bytes_le), ("network", guid.bytes)):
            indices = []
            start = 0
            while len(indices) < 10:
                p = data.find(needle, start)
                if p < 0:
                    break
                indices.append(f"0x{p:x}")
                start = p + 1
            if indices:
                out.append(f"{name}/{enc}={','.join(indices)}")
    return out


def parse_sections(data, start, end, depth, budget):
    if depth > 4:
        print("  " * depth + "Maximum nesting depth reached")
        return
    pos = start
    num = 0
    while pos + 4 <= end and num < 1000:
        pos = (pos + 3) & ~3
        if pos + 4 > end or data[pos:pos + 4] in (b"\xff" * 4, b"\x00" * 4):
            break
        size = int.from_bytes(data[pos:pos + 3], "little")
        typ = data[pos + 3]
        hs = 4
        if size == 0xffffff:
            if pos + 8 > end:
                break
            size = struct.unpack_from("<I", data, pos + 4)[0]
            hs = 8
        if size < hs or pos + size > end:
            break
        prefix = "  " * depth
        if typ == 0x15:
            raw = data[pos + hs:pos + size]
            try:
                name = raw.decode("utf-16le").split("\x00", 1)[0][:100]
            except UnicodeDecodeError:
                name = "<invalid UTF16>"
            print(f"{prefix}UI name: {name!r}")
        elif typ in (0x10, 0x12):
            kind = "PE32" if typ == 0x10 else "TE"
            print(f"{prefix}{kind} section, payload={size - hs} bytes")
        elif typ == 0x17:
            print(f"{prefix}Nested FV image, bytes={size - hs}")
        elif typ == 0x02 and size >= hs + 20:
            guid = uuid.UUID(bytes_le=data[pos + hs:pos + hs + 16])
            offset, flags = struct.unpack_from("<HH", data, pos + hs + 16)
            if offset < hs + 20 or offset > size:
                print(f"{prefix}Malformed guided offset={offset}, section size={size}")
            else:
                body = data[pos + offset:pos + size]
                print(f"{prefix}GUID-defined {guid}, payload={len(body)}, flags=0x{flags:x}")
                if guid in (GZIP_GUID, LZMA_GUID):
                    decoded, error = decompress_limited(body, guid)
                    if error:
                        print(f"{prefix}  Decompression: {error}")
                    elif budget[0] < len(decoded):
                        print(f"{prefix}  Cumulative decompression budget exceeded")
                    else:
                        budget[0] -= len(decoded)
                        print(f"{prefix}  Decoded {len(decoded)} bytes (in memory).")
                        for h in hits(decoded):
                            print(f"{prefix}  GUID match: {h}")
                        if decoded.startswith(b"_FVH"):
                            print(f"{prefix}  Decoded bytes begin with FV signature (unusual)")
                        else:
                            parse_sections(decoded, 0, len(decoded), depth + 1, budget)
                else:
                    print(f"{prefix}  Unknown guided encoding; not decoding")
        num += 1
        pos = (pos + size + 3) & ~3


def inspect(data, base, label):
    if data[base + 0x28:base + 0x2c] != b"_FVH":
        raise ValueError("Invalid FV signature")
    length = struct.unpack_from("<Q", data, base + 0x20)[0]
    hs = struct.unpack_from("<H", data, base + 0x30)[0]
    if not (0x38 <= hs <= length <= len(data) - base):
        raise ValueError("Invalid FV bounds")
    print(f"=== {label}: FV length 0x{length:x} ===")
    pos = (base + hs + 7) & ~7
    end = base + length
    count = 0
    budget = [64 * 1024 * 1024]
    while pos + 24 <= end and count < 500:
        h = data[pos:pos + 24]
        if h == b"\xff" * 24:
            break
        if h == b"\x00" * 24:
            pos += 8
            continue
        length = int.from_bytes(h[20:23], "little")
        hs = 24
        if length == 0xffffff and pos + 32 <= end:
            length = struct.unpack_from("<Q", data, pos + 24)[0]
            hs = 32
        if length < hs or length > end - pos:
            print(f"Stopping: invalid FFS header at 0x{pos:x}")
            break
        guid = uuid.UUID(bytes_le=h[:16])
        print(f"FFS #{count}: guid={guid}, type=0x{h[18]:02x}, offset=0x{pos:x}")
        parse_sections(data, pos + hs, pos + length, 1, budget)
        pos = (pos + length + 7) & ~7
        count += 1
    print(f"FFS files inspected: {count}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if not args.archive.is_file():
        parser.error("Archive not found")
    seen = set()
    with tarfile.open(args.archive, "r|gz") as archive:
        for member in archive:
            name = Path(member.name).name
            if name not in IMAGES or not member.isfile():
                continue
            if name in seen or member.size > 16 * 1024 * 1024:
                parser.error(f"Duplicate or oversized image: {name}")
            seen.add(name)
            stream = archive.extractfile(member)
            if stream is None:
                parser.error(f"Unable to read: {name}")
            data = stream.read()
            digest, base = IMAGES[name]
            if hashlib.sha256(data).hexdigest() != digest:
                parser.error(f"SHA256 mismatch: {name}")
            inspect(data, base, name)
    if seen != set(IMAGES):
        parser.error("Missing images: " + ", ".join(sorted(set(IMAGES) - seen)))
    print("Read-only. No firmware saved or executed; no phone accessed.")


if __name__ == "__main__":
    main()
