"""Synthetic ELF bounds and offset-mapping tests; no firmware execution."""
import importlib.util
from pathlib import Path
import struct
import unittest
spec=importlib.util.spec_from_file_location('tz',Path(__file__).with_name('inspect-tz-structure.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def elf():
    data=bytearray(256);data[:6]=b'\x7fELF\x02\x01'
    struct.pack_into('<H',data,18,183)
    struct.pack_into('<Q',data,32,64)
    struct.pack_into('<HH',data,54,56,1)
    struct.pack_into('<II6Q',data,64,1,5,128,0x1000,0x1000,64,128,4096)
    return data

class BoundsTests(unittest.TestCase):
    def test_file_backed_only(self):
        rows=m.segments(elf())
        self.assertEqual(m.map_offset(rows,128),[0x1000])
        self.assertEqual(m.map_offset(rows,191),[0x103f])
        self.assertEqual(m.map_offset(rows,192),[])
    def test_truncated_headers(self):
        with self.assertRaises(ValueError):m.segments(elf()[:100])
    def test_out_of_file(self):
        data=elf();struct.pack_into('<Q',data,64+32,300)
        with self.assertRaises(ValueError):m.segments(data)
    def test_file_larger_than_memory(self):
        data=elf();struct.pack_into('<Q',data,64+40,32)
        with self.assertRaises(ValueError):m.segments(data)

if __name__=='__main__':unittest.main()
