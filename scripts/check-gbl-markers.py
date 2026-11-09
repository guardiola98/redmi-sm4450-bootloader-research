#!/usr/bin/env python3
"""Read-only GBL-related feature marker inventory on extracted LinuxLoader PE.

This does NOT test exploitability. A marker's absence does not mean vulnerable.
No code from third-party exploit checkers is copied.
"""
from pathlib import Path
import argparse
import hashlib

MARKERS = [
    ("gpu-command", "set-gpu-preemption"),
    ("fence-command", "set-hw-fence-value"),
    ("gpu-rejection-text", "Invalid Argument"),
    ("fence-rejection-text", "invalid input (must be 0 or 1)"),
    ("generic-fastboot", "Fastboot: Processing commands"),
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, help="PE to inspect; by default locate section1.pe")
    args = parser.parse_args()
    if args.file is None:
        found = list(Path("work/uefi-extracted").rglob("section1.pe"))
        if len(found) != 1:
            parser.error(f"Found {len(found)} PE candidates, expected exactly one")
        path = found[0]
    else:
        path = args.file
    data = path.read_bytes()
    print(f"PE: {path}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
    for name, marker in MARKERS:
        offsets = []
        lower = data.lower()
        needle = marker.lower().encode()
        start = 0
        while True:
            found = lower.find(needle, start)
            if found < 0:
                break
            offsets.append(f"0x{found:x}")
            start = found + 1
            if len(offsets) >= 20:
                break
        print(f"{name}: {'present at ' + ', '.join(offsets) if offsets else 'not found'}")
    print("INCONCLUSIVE: markers alone do not prove an applicable, exploitable, or patched issue.")
    print("No firmware was executed or modified.")

if __name__ == "__main__":
    main()
