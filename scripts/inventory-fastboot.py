#!/usr/bin/env python3
"""Read-only offline inventory of a Xiaomi fastboot .tgz archive.

Streams TAR metadata, never extracts or executes firmware. Displays file paths,
sizes, and selected boot-related entries. Does not send data anywhere.
"""
import argparse
import hashlib
import pathlib
import re
import tarfile

BOOT_RE = re.compile(r"(?:^|/)(?:abl|xbl(?:_config)?|tz|hyp|devcfg|keymaster|uefisecapp|vbmeta(?:_system|_vendor)?|boot|vendor_boot|init_boot|dtbo)(?:[._-]|$)", re.I)
EXPECTED_MD5 = "330e013f7fc6acc15e7f17e8edb4d6a8"
EXPECTED_SHA256 = "d2d44b39440d4915a10b3198d0075a32253c6058405ba67be1fc5667a067eac9"

def digest_file(path):
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=pathlib.Path, help="Unmodified Xiaomi fastboot .tgz")
    parser.add_argument("--all", action="store_true", help="Show all regular archive entries")
    parser.add_argument("--skip-hash", action="store_true", help="Skip archive-wide checksum verification")
    args = parser.parse_args()

    if not args.archive.is_file():
        parser.error(f"No such file: {args.archive}")
    if not args.skip_hash:
        md5, sha = digest_file(args.archive)
        print(f"MD5:    {md5} {'(matches indexed package)' if md5 == EXPECTED_MD5 else '(DIFFERS from indexed package)'}")
        print(f"SHA256: {sha} {'(matches baseline)' if sha == EXPECTED_SHA256 else '(DIFFERS from baseline)'}")
        if md5 != EXPECTED_MD5 or sha != EXPECTED_SHA256:
            print("WARNING: Package is not identical to the recorded baseline.")
    print("=== ARCHIVE CONTENTS (read-only) ===")
    count = 0
    with tarfile.open(args.archive, mode="r:gz") as archive:
        for item in archive:
            if not item.isfile():
                continue
            count += 1
            if args.all or BOOT_RE.search(item.name):
                print(f"{item.size:>12} bytes  {item.name}")
    print(f"Total regular entries: {count}")
    print("No archive entries were extracted. No commands were executed from the archive.")

if __name__ == "__main__":
    main()
