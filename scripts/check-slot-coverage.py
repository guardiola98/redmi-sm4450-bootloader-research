#!/usr/bin/env python3
"""Read-only inspect of rawprogram partition targets for A/B slots.

Inspects XML members from a Xiaomi fastboot .tgz; no extraction to disk or flash.
Note: rawprogram files are flashing instructions and do NOT prove installed slots match.
"""
import argparse
from collections import defaultdict
from pathlib import Path
import tarfile
import xml.etree.ElementTree as ET
import re

XML_RE = re.compile(r"^rawprogram\d+\.xml$", re.I)
INTEREST = re.compile(r"^(abl|xbl|xbl_config|tz|boot|vendor_boot|vbmeta|vbmeta_system|dtbo|devcfg)(?:_[ab])?$", re.I)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    args = ap.parse_args()
    if not args.archive.is_file():
        ap.error("Archive does not exist")
    labels = defaultdict(list)
    with tarfile.open(args.archive, "r|gz") as t:
        for item in t:
            if not item.isfile() or not XML_RE.fullmatch(Path(item.name).name):
                continue
            if item.size > 4*1024*1024:
                continue
            f = t.extractfile(item)
            if f is None:
                continue
            try:
                root = ET.fromstring(f.read())
            except ET.ParseError as e:
                print(f"WARNING: cannot parse {item.name}: {e}")
                continue
            for el in root.iter():
                if el.tag.rsplit("}", 1)[-1].lower() != "program":
                    continue
                label = el.get("label", "").strip()
                if INTEREST.fullmatch(label):
                    name = Path(el.get("filename", "").strip()).name
                    labels[label].append((Path(item.name).name, name or "(empty)"))
    print("=== PARTITION LABELS IN STANDARD RAWPROGRAM XML ===")
    for label in sorted(labels):
        print(f"{label:23} " + "; ".join(f"{file} -> {image}" for file, image in labels[label]))
    print("\n=== A/B COVERAGE (MANIFEST ONLY) ===")
    for base in ["abl","xbl","xbl_config","tz","boot","vendor_boot","vbmeta","vbmeta_system","dtbo","devcfg"]:
        present = [slot for slot in ("a", "b") if f"{base}_{slot}" in labels]
        print(f"{base:16}: {', '.join(present) if present else 'not listed'}")
    print("\nIMPORTANT: This only describes XML targets, not live device partitions or flash script behavior.")
    print("No partitions were changed.")

if __name__ == "__main__":
    main()
