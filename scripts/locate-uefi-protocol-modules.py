#!/usr/bin/env python3
"""Locate the two known protocol GUIDs within decompressed UEFI FFS files.

Only reads verified uefi.elf from the owner-downloaded Xiaomi Fastboot TGZ.
Decompresses the first known Qualcomm GZIP guided section in memory, validates
nested FV/FFS bounds, and reports containing FFS module and section for each
literal GUID. Does not execute, extract to disk or modify firmware.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import tarfile
import uuid
import zlib

EXPECTED_SHA256 = "0543144c7f583d7e870019d95206be2b864eae1fff878dcf9bcee52c063ecc50"
TARGET_FFS_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792")
GZIP_GUID = uuid.UUID("1d301fe9-be79-4353-91c2-d23bc959ae0c")
TARGETS = {
    "token-candidate": uuid.UUID("0c00a314-11a1-4d7a-a5c8-70bd5f88e7df"),
    "verifiedboot": uuid.UUID("8e5eff91-21b6-47d3-af2b-c15a01e020ec"),
}
LIMIT = 16 * 1024 * 1024


def align(v, n):
    return (v + n - 1) & ~(n - 1)


def parse_fv(data, base, end_limit):
    if base + 0x38 > end_limit or data[base + 0x28:base + 0x2c] != b"_FVH":
        raise ValueError(f"No _FVH at 0x{base:x}")
    length = struct.unpack_from("<Q", data, base + 0x20)[0]
    hs = struct.unpack_from("<H", data, base + 0x30)[0]
    if not (0x38 <= hs <= length <= end_limit - base):
        raise ValueError(f"Invalid FV lengths at 0x{base:x}")
    return align(base + hs, 8), base + length, length


def sections(data, start, stop):
    at = start
    count = 0
    while at + 4 <= stop and count < 2048:
        at = align(at, 4)
        if at + 4 > stop or data[at:at + 4] in (b"\xff" * 4, b"\x00" * 4):
            break
        size = int.from_bytes(data[at:at + 3], "little")
        typ = data[at + 3]
        hs = 4
        if size == 0xffffff:
            if at + 8 > stop:
                break
            size = struct.unpack_from("<I", data, at + 4)[0]
            hs = 8
        if size < hs or size > stop - at:
            break
        yield at, at + size, typ, hs
        at += size
        count += 1


def ffs_files(data, start, stop):
    at = start
    count = 0
    while at + 24 <= stop and count < 5000:
        h = data[at:at + 24]
        if h == b"\xff" * 24:
            break
        if h == b"\x00" * 24:
            at += 8
            continue
        size = int.from_bytes(h[20:23], "little")
        hs = 24
        if size == 0xffffff:
            if at + 32 > stop:
                break
            size = struct.unpack_from("<Q", data, at + 24)[0]
            hs = 32
        if size < hs or size > stop - at:
            print(f"Warning: stopped at malformed FFS 0x{at:x}")
            break
        guid = uuid.UUID(bytes_le=bytes(h[:16]))
        yield at, at + size, at + hs, guid, h[18]
        at = align(at + size, 8)
        count += 1


def read_uefi(tgz):
    found = []
    with tarfile.open(tgz, "r|gz") as archive:
        for entry in archive:
            if entry.isfile() and Path(entry.name).name == "uefi.elf":
                if entry.size > LIMIT or found:
                    raise ValueError("Duplicate or oversized uefi.elf")
                stream = archive.extractfile(entry)
                if stream is None:
                    raise ValueError("Cannot read uefi.elf")
                found.append(stream.read())
    if len(found) != 1:
        raise ValueError("Missing uefi.elf")
    data = found[0]
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"Unrecognized uefi.elf SHA256: {digest}")
    return data


def decoded_first_fv(data):
    start, end, _ = parse_fv(data, 0x1000, len(data))
    for at, last, begin, guid, typ in ffs_files(data, start, end):
        if guid != TARGET_FFS_GUID:
            continue
        for ss, se, section_type, hs in sections(data, begin, last):
            if section_type != 0x02 or se - ss < hs + 20:
                continue
            section_guid = uuid.UUID(bytes_le=bytes(data[ss + hs:ss + hs + 16]))
            offset, _attrs = struct.unpack_from("<HH", data, ss + hs + 16)
            if section_guid != GZIP_GUID or offset < hs + 20 or offset > se - ss:
                continue
            payload = data[ss + offset:se]
            dec = zlib.decompressobj(wbits=31)
            content = dec.decompress(payload, LIMIT + 1)
            if len(content) > LIMIT:
                raise ValueError("Decompressed size exceeds limit")
            content += dec.flush(LIMIT + 1 - len(content))
            if not dec.eof or len(content) > LIMIT:
                raise ValueError("Invalid or oversized compressed payload")
            return content
        raise ValueError("Target FFS has no expected GZIP section")
    raise ValueError("Expected FFS not found")


def run(tgz):
    content = decoded_first_fv(read_uefi(tgz))
    print(f"Decoded first GZIP container: {len(content)} bytes")
    # A guided decompressor may return more than one sibling UEFI section;
    # the FV-image (type 0x17) is not guaranteed to start at byte zero.
    print(f"Decoded prefix (16 bytes): {content[:16].hex()}")
    parsed = list(sections(content, 0, len(content)))
    print("Decoded top-level sections:",
          ", ".join(f"type=0x{typ:02x}@0x{pos:x},size=0x{end-pos:x}"
                    for pos, end, typ, _ in parsed[:16]) or "none")
    volumes = []
    for pos, section_end, typ, header_size in parsed:
        if typ != 0x17:
            continue
        fv_start = pos + header_size
        try:
            start, end, length = parse_fv(content, fv_start, section_end)
        except ValueError as exc:
            print(f"Skipping invalid FV-image at 0x{pos:x}: {exc}")
            continue
        volumes.append((start, end, length, fv_start))
    if not volumes:
        raise ValueError("No valid nested FV-image section found in decoded top-level sections")
    if len(volumes) > 1:
        raise ValueError(f"Found {len(volumes)} valid nested FVs; refuse ambiguous first-volume selection")
    start, end, length, fv_start = volumes[0]
    print(f"Nested FV: offset=0x{fv_start:x}, length=0x{length:x}")
    owners = []
    for at, last, begin, guid, typ in ffs_files(content, start, end):
        owners.append((at, last, begin, guid, typ))
    print(f"Nested FFS files: {len(owners)}")

    for label, guid in TARGETS.items():
        for encoding, needle in (("UEFI", guid.bytes_le), ("network", guid.bytes)):
            matches = []
            at = 0
            while len(matches) < 20:
                at = content.find(needle, at)
                if at < 0:
                    break
                matches.append(at)
                at += 1
            print(f"\n{label} GUID {guid} ({encoding}): {len(matches)} literal match(es)")
            for offset in matches:
                owner = next((v for v in owners if v[0] <= offset < v[1]), None)
                if owner is None:
                    print(f"  0x{offset:x}: outside nested FFS ranges")
                    continue
                fo, fe, body, fileguid, filetype = owner
                names = []
                containing_sections = []
                for ss, se, st, hs in sections(content, body, fe):
                    if st == 0x15:
                        raw = content[ss + hs:se]
                        try:
                            name = raw.decode("utf-16le").split("\x00", 1)[0][:100]
                        except UnicodeDecodeError:
                            name = "<invalid UTF16>"
                        names.append(name)
                    if ss <= offset < se:
                        containing_sections.append(f"0x{st:02x}@0x{ss:x}")
                print(f"  0x{offset:x}: FFS 0x{fo:x}..0x{fe:x} type=0x{filetype:02x}"
                      f" file-guid={fileguid} UI-names={names or '[unknown]'}"
                      f" containing-sections={containing_sections or '[not resolved at top level]'}")
    print("\nAll offsets are relative to decoded buffer, NOT flash addresses.")
    print("Read-only; no firmware extracted, executed or uploaded.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    a = ap.parse_args()
    if not a.archive.is_file():
        ap.error("Archive not found")
    run(a.archive)
