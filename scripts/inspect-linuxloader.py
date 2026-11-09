#!/usr/bin/env python3
"""Read-only structural analysis of an extracted Qualcomm UEFI LinuxLoader PE.

Uses Python standard library. Does not execute the PE or upload files.
"""
import argparse
import hashlib
from pathlib import Path
import struct

MACHINES = {0xAA64: "ARM64 (AArch64)", 0x01C0: "ARM", 0x01C4: "ARMv7 Thumb-2", 0x8664: "AMD64"}
SUBSYSTEMS = {10: "EFI Application", 11: "EFI Boot Service Driver", 12: "EFI Runtime Driver"}


def unpack(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError(f"Truncated PE at offset {offset:#x}")
    return struct.unpack_from(fmt, data, offset)


def inspect(path):
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("Not a DOS/PE MZ image")
    pe_offset, = unpack("<I", data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Missing PE signature")
    machine, count, timestamp, _, _, optional_size, flags = unpack("<HHIIIHH", data, pe_offset + 4)
    opt = pe_offset + 24
    magic, = unpack("<H", data, opt)
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"Unsupported optional header magic {magic:#x}")
    pe32plus = magic == 0x20B
    if optional_size < (72 if pe32plus else 72):
        raise ValueError("Optional header too short")
    entry_rva, = unpack("<I", data, opt + 16)
    image_base, = unpack("<Q" if pe32plus else "<I", data, opt + (24 if pe32plus else 28))
    section_alignment, file_alignment = unpack("<II", data, opt + 32)
    subsystem, = unpack("<H", data, opt + 68)
    size_image, = unpack("<I", data, opt + 56)

    print(f"Path: {path}")
    print(f"Size: {len(data)} bytes")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
    print(f"Format: {'PE32+' if pe32plus else 'PE32'}")
    print(f"Machine: {MACHINES.get(machine, 'unknown')} (0x{machine:04x})")
    print(f"Subsystem: {SUBSYSTEMS.get(subsystem, 'other')} ({subsystem})")
    print(f"Entry RVA: 0x{entry_rva:x}")
    print(f"Image base: 0x{image_base:x}")
    print(f"Size of image: 0x{size_image:x}")
    print(f"Alignments: section={section_alignment:#x} file={file_alignment:#x}")
    print(f"Sections ({count}):")

    start = opt + optional_size
    if start + count * 40 > len(data):
        raise ValueError("Section headers truncated")
    for idx in range(count):
        off = start + idx * 40
        name, vsize, va, raw_size, raw_ptr, _, _, _, _, characteristics = unpack("<8sIIIIIIHHI", data, off)
        label = name.rstrip(b"\x00").decode("ascii", "replace")
        if raw_size and raw_ptr + raw_size > len(data):
            print(f"  WARNING: section {label} extends beyond file")
        print(f"  {label:8} RVA={va:#x} VirtualSize={vsize:#x} FileOffset={raw_ptr:#x} FileSize={raw_size:#x} Flags={characteristics:#x}")

    print("Static structure only; firmware has NOT been executed.")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pe", nargs="?", type=Path, help="Path to extracted section1.pe; if omitted, find it under work/uefi-extracted")
    args = ap.parse_args()
    if args.pe:
        path = args.pe
    else:
        matches = list(Path("work/uefi-extracted").rglob("section1.pe"))
        if len(matches) != 1:
            ap.error(f"Expected exactly one section1.pe, found {len(matches)}; provide explicit path")
        path = matches[0]
    if not path.is_file():
        ap.error("PE file not found")
    try:
        inspect(path)
    except ValueError as ex:
        ap.error(str(ex))


if __name__ == "__main__":
    main()
