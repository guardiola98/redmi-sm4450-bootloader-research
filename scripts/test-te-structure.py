"""Synthetic TE map/bounds tests; no firmware execution."""
import importlib.util
from pathlib import Path
import struct
import unittest
spec=importlib.util.spec_from_file_location('te',Path(__file__).with_name('inspect-uefi-te.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def sample():
    b=bytearray(512)
    struct.pack_into('<HHBBHIIQ',b,0,0x5a56,0xaa64,1,11,0x128,0x210,0x200,0x100000)
    struct.pack_into('<8sIIII',b,40,b'.text',0x80,0x200,0x80,0x200)
    return b


class TeTests(unittest.TestCase):
    def test_stripped_mapping(self):
        r=m.inspect(sample())
        self.assertEqual(r['entry_file_offset'],'0x110')
        self.assertEqual(r['entry_va'],'0x100210')

    def test_truncated_header_or_sections(self):
        for size in (20,50):
            with self.assertRaises(ValueError):m.inspect(sample()[:size])

    def test_raw_data_cannot_overlap_header_or_eof(self):
        for pointer in (0x100,0x400):
            b=sample();struct.pack_into('<I',b,60,pointer)
            with self.assertRaises(ValueError):m.inspect(b)

    def test_entry_must_be_backed(self):
        b=sample();struct.pack_into('<I',b,8,0x300)
        with self.assertRaises(ValueError):m.inspect(b)


if __name__=='__main__':unittest.main()
