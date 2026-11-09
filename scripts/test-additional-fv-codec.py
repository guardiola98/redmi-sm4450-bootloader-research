"""Synthetic checks for bounded decompression used by the additional census."""
import importlib.util
from pathlib import Path
import lzma
import unittest

spec = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('inventory-additional-fvs.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CodecTests(unittest.TestCase):
    def setUp(self):
        self.old = m.codec.OUT_LIMIT
        m.codec.OUT_LIMIT = 128

    def tearDown(self):
        m.codec.OUT_LIMIT = self.old

    def test_exact_limit(self):
        result, error = m.codec.decompress_limited(lzma.compress(b'A'*128), m.codec.LZMA_GUID)
        self.assertEqual(result, b'A'*128)
        self.assertIsNone(error)

    def test_excess_rejected(self):
        result, error = m.codec.decompress_limited(lzma.compress(b'A'*129), m.codec.LZMA_GUID)
        self.assertIsNone(result)
        self.assertEqual(error, 'decompressed size exceeds limit')

    def test_truncated_rejected(self):
        result, error = m.codec.decompress_limited(lzma.compress(b'abc')[:-6], m.codec.LZMA_GUID)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

if __name__ == '__main__':
    unittest.main()
