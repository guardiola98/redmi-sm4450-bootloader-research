#!/usr/bin/env python3
"""Read-only search of relevant ASCII and UTF-16LE strings in the extracted LinuxLoader PE.

Prints matching strings and file offsets only. Does not execute or modify firmware.
"""
import argparse
from collections import Counter
from pathlib import Path
import re

CATEGORIES = {
    "fastboot": re.compile(r"fastboot|oem |flashing|flash |getvar|bootloader|reboot-bootloader", re.I),
    "lock": re.compile(r"unlock|lock.state|locked|critical|device.state|allow.unlock|secure.boot", re.I),
    "avb": re.compile(r"verified.boot|vbmeta|verity|avb|rollback|verification|verify.boot", re.I),
    "security": re.compile(r"signature|authenticat|permission|certificat|tamper|trust|challenge", re.I),
}
ASCII = re.compile(rb"[\x20-\x7e]{5,}")
UTF16LE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

def collect(data, encoding, pattern):
    for match in pattern.finditer(data):
        raw = match.group(0)
        value = raw.decode("ascii" if encoding == "ascii" else "utf-16-le", errors="replace")
        groups = [name for name, check in CATEGORIES.items() if check.search(value)]
        if groups:
            yield (match.start(), encoding, value, groups)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", type=Path, help="Extracted PE location (default: auto-find)")
    ap.add_argument("--max", type=int, default=100, help="Maximum hits to display, default 100")
    args = ap.parse_args()
    if args.max < 1 or args.max > 1000:
        ap.error("--max must be in 1..1000")
    if args.file:
        file = args.file
    else:
        paths = list(Path("work/uefi-extracted").rglob("section1.pe"))
        if len(paths) != 1:
            ap.error(f"Expected 1 section1.pe, found {len(paths)}; use --file")
        file = paths[0]
    data = file.read_bytes()
    hits = sorted([*collect(data, "ascii", ASCII), *collect(data, "utf16le", UTF16LE)], key=lambda hit: hit[0])
    counts = Counter(tag for hit in hits for tag in hit[3])
    print(f"File: {file}")
    print(f"Bytes: {len(data)}; matching strings: {len(hits)}")
    print("Category counts:", ", ".join(f"{k}={counts[k]}" for k in CATEGORIES))
    for offset, encoding, value, groups in hits[:args.max]:
        print(f"0x{offset:06x} [{encoding}] ({','.join(groups)}) {value[:180]}")
    if len(hits) > args.max:
        print(f"... {len(hits)-args.max} more hits not shown; use --max to increase.")
    print("Offsets are FILE offsets, not memory addresses. Findings are clues, not proof of vulnerability.")

if __name__ == "__main__":
    main()
