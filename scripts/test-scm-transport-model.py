"""Synthetic ARMv8 transport result model; does not invoke firmware/SMC."""
import unittest

def transport(status, registers, buffer):
    if status == 0:
        return 0, [1, *registers[:3]], buffer
    return 0x8000000000000007, [registers[0], 0, 0, 0], buffer

class TransportTests(unittest.TestCase):
    def test_marker_is_transport_generated(self):
        untouched = bytes([0xa5]) * 0x4c4
        status, result, data = transport(0, [0, 0, 0], untouched)
        self.assertEqual((status, result), (0, [1, 0, 0, 0]))
        self.assertIs(data, untouched)

    def test_argument_count_is_not_policy_count(self):
        self.assertEqual(0x22 & 15, 2)
        self.assertLessEqual(0x22 & 15, 10)
        self.assertEqual(0x02001401 | 0x40000000, 0x42001401)

if __name__ == '__main__':
    unittest.main()
