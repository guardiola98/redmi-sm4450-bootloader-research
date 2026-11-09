import importlib.util
from pathlib import Path
import unittest
s = importlib.util.spec_from_file_location('extractor', Path(__file__).with_name('extract-protocol-pe.py'))
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
class ExtractionTests(unittest.TestCase):
    def test_missing_targets(self):
        with self.assertRaises(ValueError): m.extract(b'')
    def test_truncated_fv(self):
        with self.assertRaises(ValueError): m.extract(b'\x08\x00\x00\x17abcd')
    def test_section_bounds(self):
        self.assertEqual(list(m.loc.sections(b'\xff\xff\x00\x10abcd',0,8)), [])
if __name__ == '__main__': unittest.main()
