#!/usr/bin/env python3
"""Read-only GUID marker scan in Qualcomm XBL from a Xiaomi Fastboot archive.

Streams only images/xbl_s.melf into memory (~1.2 MB), checks SHA-256, and
searches the bytes for a known token-protocol GUID in either UEFI layout.
Never executes, extracts, flashes or uploads firmware.
"""
import argparse
import hashlib
from pathlib import Path
import tarfile
import uuid

EXPECTED_HASH = "cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1"
TOKEN_GUID = uuid.UUID("0c00a314-11a1-4d7a-a5c8-70bd5f88e7df")
VERIFIEDBOOT_GUID = uuid.UUID("8e5eff91-21b6-47d3-af2b-c15a01e020ec")
TARGET_NAME = "/images/xbl_s.melf"


def matches(data, needle):
    out = []
    index = 0
    while (i := data.find(needle, index)) >= 0:
        out.append(hex(i))
        index = i + 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path, help="Matching Xiaomi EEA Fastboot .tgz")
    args = ap.parse_args()
    if not args.archive.is_file():
        ap.error("Archive not found")
    with tarfile.open(args.archive, "r:gz") as tar:
        candidates = [
            m for m in tar.getmembers()
            if m.isfile() and m.name.endswith(TARGET_NAME)
        ]
        if len(candidates) != 1:
            ap.error(f"Expected one xbl_s.melf, got {len(candidates)}")
        m = candidates[0]
        if m.size > 32 * 1024 * 1024:
            ap.error(f"Unexpected XBL size: {m.size}")
        file = tar.extractfile(m)
        if file is None:
            ap.error("Cannot read XBL image")
        data = file.read()
    digest = hashlib.sha256(data).hexdigest()
    print(f"Source: {m.name}")
    print(f"Bytes: {len(data)}")
    print(f"SHA256: {digest}")
    if digest != EXPECTED_HASH:
        ap.error("XBL hash differs from verified baseline; refusing to interpret scan")
    for name, guid in (("token candidate", TOKEN_GUID), ("VerifiedBoot", VERIFIEDBOOT_GUID)):
        for label, raw in (("UEFI little-endian", guid.bytes_le), ("network byte order", guid.bytes)):
            offsets = matches(data, raw)
            print(f"{name} {guid} ({label}): {', '.join(offsets) if offsets else 'no literal match'}")
    print("A missing literal GUID is NOT evidence that the protocol is absent.")
    print("No phone access and no firmware execution or modification.")


if __name__ == "__main__":
    main()
