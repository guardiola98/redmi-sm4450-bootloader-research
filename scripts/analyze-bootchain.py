#!/usr/bin/env python3
"""Read-only offline boot-image hashes and partition labels from a Xiaomi Fastboot TGZ.

Streams one archive pass; never extracts, executes, or flashes firmware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import xml.etree.ElementTree as ET

TARGETS = re.compile(r"^(?:abl|xbl(?:_.*)?|tz|hyp|devcfg|aop_devcfg|featenabler|vbmeta(?:_.*)?|boot|vendor_boot|init_boot|dtbo|XblRamdump)\.(?:elf|melf|mbn|bin|img)$", re.I)
RAWPROGRAM = re.compile(r"rawprogram[0-9]+\.xml$", re.I)
CHUNK = 4 * 1024 * 1024

def inspect(archive_path):
    images, mappings, total = [], [], 0
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            total += 1
            name = Path(member.name).name
            if RAWPROGRAM.fullmatch(name):
                if member.size > 4 * 1024 * 1024:
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                try:
                    root = ET.fromstring(stream.read())
                except ET.ParseError:
                    print(f"Could not parse XML: {name}")
                    continue
                for element in root.iter():
                    if element.tag.rsplit("}", 1)[-1].lower() != "program":
                        continue
                    filename = Path(element.attrib.get("filename", "").strip()).name
                    label = element.attrib.get("label", "").strip()
                    if filename and (TARGETS.fullmatch(filename) or re.search("abl|xbl|vbmeta|boot|tz", label, re.I)):
                        mappings.append({"manifest": name, "partition": label, "filename": filename})
            elif TARGETS.fullmatch(name):
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                digest, header = hashlib.sha256(), b""
                for chunk in iter(lambda: stream.read(CHUNK), b""):
                    if not header:
                        header = chunk[:16]
                    digest.update(chunk)
                kind = ("ELF" if header.startswith(b"\x7fELF") else
                        "Android boot" if header.startswith(b"ANDROID!") else
                        "AVB metadata" if header.startswith(b"AVB0") else
                        "Other / container")
                images.append({"name": name, "size": member.size, "sha256": digest.hexdigest(), "header": kind})
    return {"archive": archive_path.name, "regular_files": total,
            "images": sorted(images, key=lambda item: item["name"].lower()),
            "partition_mappings": sorted(mappings, key=lambda item: (item["partition"], item["filename"]))}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--json", type=Path, help="Optional local JSON report filename")
    args = parser.parse_args()
    if not args.archive.is_file():
        parser.error("Archive not found")
    report = inspect(args.archive)
    print(f"Scanned {report['regular_files']} regular archive entries")
    print("=== BOOT COMPONENTS ===")
    for item in report["images"]:
        print(f"{item['name']:25} {item['size']:>12} bytes  {item['header']:20} sha256={item['sha256']}")
    print("=== RAWPROGRAM REFERENCES ===")
    for item in report["partition_mappings"]:
        print(f"{item['manifest']:20} partition={item['partition']:20} file={item['filename']}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Saved local JSON: {args.json}")
    print("Read-only: no firmware extracted, flashed, or executed.")

if __name__ == "__main__":
    main()
