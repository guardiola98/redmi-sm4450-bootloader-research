#!/usr/bin/env python3
"""Extract only the named ABL ELF from an existing Xiaomi fastboot archive.

Read-only on the phone. Never executes firmware. Refuses unsafe output paths,
unexpected filenames, unexpectedly large files, and a mismatching SHA256.
"""
import argparse
import hashlib
from pathlib import Path
import tarfile

EXPECTED = "f1c1f9ffbfa596cc352bf13aaa8e751eaee5168ab0344c641a70f0aa5f1607eb"
EXPECTED_MEMBER = "images/abl.elf"

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    ap.add_argument("--out", type=Path, default=Path("work/abl.elf"))
    args = ap.parse_args()
    if not args.archive.is_file():
        ap.error("Archive not found")
    destination = args.out.resolve()
    if destination.is_symlink() or args.out.is_symlink():
        ap.error("Refusing a symbolic-link output")
    if destination.exists():
        ap.error("Output already exists; refusing overwrite")
    found = None
    with tarfile.open(args.archive, "r:gz") as archive:
        members = [
            m for m in archive.getmembers()
            if m.isfile() and m.name.endswith("/" + EXPECTED_MEMBER)
        ]
        if len(members) != 1:
            ap.error(f"Expected exactly one {EXPECTED_MEMBER}, found {len(members)}")
        member = members[0]
        if not (100_000 <= member.size <= 2_000_000):
            ap.error(f"Unexpected ABL size: {member.size}")
        src = archive.extractfile(member)
        if src is None:
            ap.error("Cannot read archive member")
        found = src.read()
    actual = hashlib.sha256(found).hexdigest()
    if actual != EXPECTED:
        ap.error(f"ABL SHA256 mismatch: {actual}")
    if not found.startswith(b"\x7fELF"):
        ap.error("Not an ELF file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as out:
        out.write(found)
    print(f"Extracted: {destination}")
    print(f"Size: {len(found)} bytes")
    print(f"SHA256: {actual}")
    print("File extracted locally. It was not executed, uploaded or flashed.")

if __name__ == "__main__":
    main()
