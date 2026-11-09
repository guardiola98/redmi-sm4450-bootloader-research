"""Synthetic model of the observed lookup interval, not execution of TZ."""
import unittest

def interval_branch(identifier):
    # Branches at 1c099c30, 1c099cd0, 1c099ce8, 1c099e1c.
    if not 0x02001300 < identifier <= 0x02001501:
        return 'outside-model'
    index = (identifier - 0x02001301) & ((1 << 64)-1)
    return 'table' if index <= 0x11 else 'return-one'

class DispatchTests(unittest.TestCase):
    def test_target_normalization_and_rejection(self):
        self.assertEqual(0x42001401 & 0x3f00ffff, 0x02001401)
        self.assertEqual(interval_branch(0x02001401), 'return-one')
    def test_boundary(self):
        self.assertEqual(interval_branch(0x02001301), 'table')
        self.assertEqual(interval_branch(0x02001312), 'table')
        self.assertEqual(interval_branch(0x02001313), 'return-one')
        self.assertEqual(interval_branch(0x02001501), 'return-one')

if __name__=='__main__':unittest.main()
