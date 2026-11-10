#!/usr/bin/env python3
"""Synthetic ELF metadata checks; no SMEM records or firmware execution."""
import runpy
from pathlib import Path
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('inspect-xbl-ram-producer.py')))


def elf():
    data = bytearray(0x90)
    data[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HHIQQQIHHHHHH', data, 16,
                     2,183,1,0x1000,64,0,0,64,56,1,0,0,0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1,5,0x80,0x1000,0x1000,16,32,1)
    return data


class ComponentLayout(unittest.TestCase):
    def test_component_extent_and_parent_relative_mapping(self):
        data = b'padding!' + elf()
        layout = API['component'](data, 8)
        self.assertEqual(layout['size'], 0x90)
        self.assertEqual(API['read_va'](data, layout, 0x1004, 4)[0], 8 + 0x84)

    def test_bss_is_not_file_backed(self):
        data = elf()
        with self.assertRaises(ValueError):
            API['read_va'](data, API['component'](data, 0), 0x1010, 1)

    def test_truncated_headers_and_segments_rejected(self):
        for length in (3, 16, 63, 100, 143):
            with self.assertRaises(ValueError):
                API['component'](elf()[:length], 0)

    def test_overlapping_file_mappings_are_not_guessed(self):
        data = elf()
        layout = API['component'](data, 0)
        layout['segments'].append(dict(layout['segments'][0]))
        with self.assertRaises(ValueError):
            API['read_va'](data, layout, 0x1000, 4)

    def test_firmware_evidence_requires_exact_hash(self):
        with self.assertRaises(ValueError):
            API['inspect'](elf())


if __name__ == '__main__':
    unittest.main()
