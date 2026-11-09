"""Synthetic dependency bytecode only; no firmware execution."""
import importlib.util
from pathlib import Path
import unittest
import uuid
spec = importlib.util.spec_from_file_location('fv', Path(__file__).with_name('inventory-additional-fvs.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
G = uuid.UUID('12345678-1234-5678-9abc-123456789abc')


class DepexTests(unittest.TestCase):
    def test_guid_boolean_expression(self):
        result = m.decode_depex(b'\x02'+G.bytes_le+b'\x06\x03\x08')
        self.assertEqual(result['references'], [dict(opcode=2, guid=str(G))])
        self.assertFalse(result['ordering_only'])

    def test_ordering_is_not_protocol_dependency(self):
        for opcode in (0, 1):
            self.assertTrue(m.decode_depex(bytes([opcode])+G.bytes_le+b'\x08')['ordering_only'])
        with self.assertRaises(ValueError):
            m.decode_depex(b'\x00'+G.bytes_le+b'\x06\x08')

    def test_invalid_bounds_and_stack(self):
        for expression in (b'', b'\x02'+G.bytes_le[:-1], b'\x03\x08',
                           b'\x06', b'\x06\x06\x08', b'\x06\x08\x00', b'\xff'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                m.decode_depex(expression)

    def test_sor_and_not(self):
        self.assertEqual(m.decode_depex(b'\x09\x06\x05\x08')['opcodes'], [9,6,5,8])
        with self.assertRaises(ValueError):
            m.decode_depex(b'\x06\x09\x08')


if __name__ == '__main__':
    unittest.main()
