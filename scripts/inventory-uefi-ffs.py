#!/usr/bin/env python3
"""Read-only inventory of FFS files and section headers in known Xiaomi UEFI FVs.

Reads the original Fastboot TGZ; does not extract, modify, execute or flash any
firmware. Does not decompress guided sections; outputs a structural inventory.
"""
import argparse
import hashlib
from collections import Counter
from pathlib import Path
import struct
import tarfile
import uuid

TARGETS = {
    "uefi.elf": ("0543144c7f583d7e870019d95206be2b864eae1fff878dcf9bcee52c063ecc50", 0x1000),
    "imagefv.elf": ("51220103d9d5f2c8e11f3bfe8a221db9cba2bd0478902037175067e182c94332", 0x1000),
    "tools.fv": ("d7f0c4034bb3236e3878dfd56116217dc34afd5b3d41e7a1f1e71fddbf77a002", 0x0),
}
SECTION_TYPE = {
    0x01: "compression",
    0x02: "guid-defined",
    0x10: "PE32",
    0x11: "PIC",
    0x12: "TE",
    0x13: "DXE-depex",
    0x14: "version",
    0x15: "UI-name",
    0x16: "compat16",
    0x17: "FV-image",
    0x18: "freeform",
    0x19: "raw",
    0x1b: "PEI-depex",
    0x1c: "SMM-depex",
}


def align(value, boundary):
    return (value + boundary - 1) & ~(boundary - 1)


def parse_sections(blob, begin, end, max_sections=1000):
    items = []
    at = begin
    for _ in range(max_sections):
        at = align(at, 4)
        if at + 4 > end:
            break
        header = blob[at:at + 4]
        if header == b"\xff" * 4 or header == b"\x00" * 4:
            break
        length = int.from_bytes(header[:3], "little")
        typ = header[3]
        headsize = 4
        if length == 0xffffff:
            if at + 8 > end:
                break
            length = struct.unpack_from("<I", blob, at + 4)[0]
            headsize = 8
        if length < headsize or length > end - at:
            break
        extra = ""
        if typ == 0x15:  # EFI_SECTION_USER_INTERFACE: UTF-16LE name
            raw = blob[at + headsize:at + length]
            try:
                extra = " name=" + repr(raw.decode("utf-16le").split("\x00", 1)[0][:120])
            except UnicodeDecodeError:
                extra = " [invalid UTF16]"
        elif typ == 0x02 and length >= headsize + 20:
            guid = uuid.UUID(bytes_le=bytes(blob[at + headsize:at + headsize + 16]))
            dataoff, attributes = struct.unpack_from("<HH", blob, at + headsize + 16)
            extra = f" section-guid={guid} data-offset={dataoff} attrs=0x{attributes:x}"
        elif typ == 0x01 and length >= headsize + 5:
            uncompressed = struct.unpack_from("<I", blob, at + headsize)[0]
            algorithm = blob[at + headsize + 4]
            extra = f" expected-uncompressed={uncompressed} algorithm={algorithm}"
        items.append((at, length, typ, extra))
        at += length
    return items


def inspect(name, data, base):
    if data[base + 0x28:base + 0x2c] != b"_FVH":
        raise ValueError(f"{name}: no UEFI FV signature at expected offset")
    fv_size = struct.unpack_from("<Q", data, base + 0x20)[0]
    hdrsize = struct.unpack_from("<H", data, base + 0x30)[0]
    if not (0x38 <= hdrsize <= fv_size <= len(data) - base):
        raise ValueError(f"{name}: FV length or header size out of bounds")
    end = base + fv_size
    at = align(base + hdrsize, 8)
    print(f"=== {name} ===")
    print(f"sha256={hashlib.sha256(data).hexdigest()} fv-offset=0x{base:x} fv-length=0x{fv_size:x} fv-header-length=0x{hdrsize:x}")
    counts = Counter()
    file_count = 0
    while at + 24 <= end and file_count < 5000:
        header = data[at:at + 24]
        if header == b"\xff" * 24:
            break
        if header == b"\x00" * 24:
            at += 8
            continue
        file_type = header[18]
        size = int.from_bytes(header[20:23], "little")
        header_size = 24
        if size == 0xffffff:
            if at + 32 > end:
                break
            size = struct.unpack_from("<Q", data, at + 24)[0]
            header_size = 32
        if size < header_size or size > end - at:
            print(f"Stopped at offset 0x{at:x}: invalid FFS header/size")
            break
        guid = uuid.UUID(bytes_le=bytes(header[:16]))
        sections = parse_sections(data, at + header_size, at + size)
        summary = ", ".join(
            f"{SECTION_TYPE.get(t, f'0x{t:02x}')}{e}" for _, _, t, e in sections
        )
        print(f"FFS 0x{at:06x} size=0x{size:x} type=0x{file_type:02x} guid={guid}"
              + (f" sections=[{summary}]" if summary else " sections=[none at top level]"))
        counts.update(t for _, _, t, _ in sections)
        file_count += 1
        at = align(at + size, 8)
    print(f"Parsed FFS files: {file_count}")
    print("Top-level sections:", ", ".join(f"{SECTION_TYPE.get(k, hex(k))}={v}" for k, v in counts.items()) or "none")
    print("No decompression performed; inner sections of compressed/guid-defined files remain unknown.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    args = ap.parse_args()
    if not args.archive.is_file():
        ap.error("Archive not found")
    seen = set()
    with tarfile.open(args.archive, "r|gz") as tar:
        for member in tar:
            name = Path(member.name).name
            if name not in TARGETS or not member.isfile():
                continue
            if name in seen or member.size > 16 * 1024 * 1024:
                ap.error(f"Duplicated or oversized candidate: {name}")
            seen.add(name)
            stream = tar.extractfile(member)
            if stream is None:
                ap.error(f"Unreadable candidate: {name}")
            data = stream.read()
            expected, base = TARGETS[name]
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected:
                ap.error(f"{name}: SHA256 mismatch: {digest}")
            inspect(name, data, base)
    if seen != set(TARGETS):
        ap.error("Missing expected images: " + ", ".join(sorted(set(TARGETS) - seen)))
    print("Read-only: no extraction, no execution, no device access.")


if __name__ == "__main__":
    main()
