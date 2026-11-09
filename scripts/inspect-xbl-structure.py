#!/usr/bin/env python3
"""Inspect verified xbl_s.melf ELF metadata and embedded UEFI FV signatures offline.

Read-only streaming extraction from an already downloaded, verified Fastboot TGZ.
This is a structural scan, NOT an exploitability test or an XBL unpacker.
"""
import argparse
import hashlib
from pathlib import Path
import struct
import tarfile

TARGETS = {
    "xbl_s.melf": "cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1",
}
MAX_SIZE = 16 * 1024 * 1024


def parse_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return ["not an ELF header"]
    cls, endian = data[4], data[5]
    if cls not in (1, 2) or endian != 1:
        return ["ELF class/endianness not supported for structural parser"]
    is64 = cls == 2
    hdr_fmt = "<HHIQQQIHHHHHH" if is64 else "<HHIIIIIHHHHHH"
    if 16 + struct.calcsize(hdr_fmt) > len(data):
        return ["ELF header truncated"]
    fields = struct.unpack_from(hdr_fmt, data, 16)
    machine = fields[1]
    entry = fields[3]
    phoff = fields[4]
    phentsize, phnum = fields[8], fields[9]
    lines = [f"ELF{64 if is64 else 32}, machine=0x{machine:x}, entry=0x{entry:x}, program_headers={phnum}"]
    phfmt = "<IIQQQQQQ" if is64 else "<IIIIIIII"
    needed = struct.calcsize(phfmt)
    if phentsize < needed or phnum > 256 or phoff + phnum * phentsize > len(data):
        lines.append("Program header table invalid or out of bounds")
        return lines
    for i in range(phnum):
        p = struct.unpack_from(phfmt, data, phoff + i * phentsize)
        typ = p[0]
        off, size = (p[2], p[5]) if is64 else (p[1], p[4])
        if off + size > len(data):
            lines.append(f"  PH{i}: type={typ} offset=0x{off:x} size=0x{size:x} OUT OF BOUNDS")
        else:
            lines.append(f"  PH{i}: type={typ} offset=0x{off:x} size=0x{size:x}")
    return lines


def offsets(data, token, cap=30):
    found = []
    start = 0
    while len(found) < cap:
        idx = data.find(token, start)
        if idx < 0:
            break
        found.append(idx)
        start = idx + 1
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    args = ap.parse_args()
    if not args.archive.is_file():
        ap.error("Archive not found")
    seen = set()
    with tarfile.open(args.archive, "r:gz") as archive:
        for member in archive:
            name = Path(member.name).name
            if name not in TARGETS or not member.isfile():
                continue
            if name in seen:
                ap.error(f"Duplicate archive entry: {name}")
            seen.add(name)
            if member.size > MAX_SIZE:
                ap.error(f"Unexpected size for {name}: {member.size}")
            stream = archive.extractfile(member)
            if stream is None:
                ap.error(f"Cannot read {name}")
            data = stream.read()
            digest = hashlib.sha256(data).hexdigest()
            if digest != TARGETS[name]:
                ap.error(f"Hash mismatch for {name}: {digest}")
            print(f"=== {name} ===")
            print(f"size={len(data)} sha256={digest}")
            for line in parse_elf(data):
                print(line)
            fvh = offsets(data, b"_FVH")
            print("Embedded UEFI FV header signature (_FVH):", ", ".join(hex(v) for v in fvh) if fvh else "not found")
            # In a valid UEFI FV header, _FVH lives 0x28 bytes from its start.
            for idx in fvh:
                begin = idx - 0x28
                if begin < 0 or begin + 0x38 > len(data):
                    continue
                length = struct.unpack_from("<Q", data, begin + 0x20)[0]
                plausible = 0x38 <= length <= len(data) - begin
                print(f"  candidate FV start=0x{begin:x}, claimed size=0x{length:x}, bounds-valid={plausible}")
    absent = TARGETS.keys() - seen
    if absent:
        print("Not found:", ", ".join(sorted(absent)))
    print("Note: no FV signature does not exclude compressed/encrypted firmware modules or protocol implementations elsewhere.")
    print("Read-only; no device connection, extraction, or execution.")


if __name__ == "__main__":
    main()
