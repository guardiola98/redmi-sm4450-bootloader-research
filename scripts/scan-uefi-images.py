#!/usr/bin/env python3
"""Read-only check of UEFI-related images in an existing Xiaomi Fastboot TGZ.

Streams selected members; prints SHA-256, ELF identification, literal GUID
offsets (UEFI and RFC/network encodings), and UEFI FV header candidates.
A missing byte pattern is not evidence that a protocol is absent.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import tarfile
import uuid

CANDIDATES = {"uefi.elf", "imagefv.elf", "tools.fv", "uefi_sec.mbn"}
GUIDS = {
    "token-candidate": uuid.UUID("0c00a314-11a1-4d7a-a5c8-70bd5f88e7df"),
    "verifiedboot": uuid.UUID("8e5eff91-21b6-47d3-af2b-c15a01e020ec"),
}
MAX_BYTES = 16 * 1024 * 1024


def offsets(blob, pattern, limit=30):
    found = []
    pos = 0
    while len(found) < limit:
        pos = blob.find(pattern, pos)
        if pos < 0:
            break
        found.append(pos)
        pos += 1
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path, help="Previously downloaded Fastboot TGZ")
    args = ap.parse_args()
    if not args.archive.is_file():
        ap.error("Archive does not exist")
    found_names = set()
    with tarfile.open(args.archive, "r|gz") as archive:
        for entry in archive:
            basename = Path(entry.name).name
            if not entry.isfile() or basename not in CANDIDATES:
                continue
            if basename in found_names or entry.size > MAX_BYTES:
                ap.error(f"Duplicate or unexpectedly large file: {basename}")
            found_names.add(basename)
            stream = archive.extractfile(entry)
            if stream is None:
                ap.error(f"Cannot read: {basename}")
            data = stream.read()
            print(f"=== {basename} ===")
            print(f"size={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
            print(f"header={'ELF' if data.startswith(bytes.fromhex('7f454c46')) else 'other'}")
            for key, guid in GUIDS.items():
                for order, value in (("UEFI", guid.bytes_le), ("network", guid.bytes)):
                    matched = offsets(data, value)
                    print(f"{key} {guid} {order}: " +
                          (", ".join(hex(off) for off in matched) if matched else "no literal match"))
            fvh = offsets(data, b"_FVH")
            print(f"FV signatures: {len(fvh)} (up to 30 shown)")
            for offset in fvh:
                start = offset - 0x28
                if start < 0 or start + 0x38 > len(data):
                    continue
                size = struct.unpack_from("<Q", data, start + 0x20)[0]
                print(f"  _FVH at 0x{offset:x}, FV start 0x{start:x}, size=0x{size:x},"
                      f" fits-file={0x38 <= size <= len(data) - start}")
    print("Missing candidate filenames:", ", ".join(sorted(CANDIDATES - found_names)) or "none")
    print("Read-only. No files extracted, no device commands, no data uploaded.")
    print("Compressed or relocated protocols may not expose literal GUID bytes.")


if __name__ == "__main__":
    main()
