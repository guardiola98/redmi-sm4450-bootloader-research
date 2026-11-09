"""Synthetic control-flow model only; no firmware, tokens or SCM execution."""
import unittest


def scan(count, match=None):
    # Detect repeated effective index instead of reproducing nontermination.
    seen = set()
    index = 0
    if count == 0:
        return 'no-match', seen
    while index not in seen:
        seen.add(index)
        if index == match:
            return 'match', seen
        index = (index + 1) & 255
        if count == index:
            return 'no-match', seen
    return 'cycle', seen


class ContractTests(unittest.TestCase):
    def test_finite_counts(self):
        for count in range(256):
            result, seen = scan(count)
            self.assertEqual(result, 'no-match')
            self.assertEqual(len(seen), count)

    def test_large_count_cycles(self):
        for count in (256, 257, 0xffffffff):
            result, seen = scan(count)
            self.assertEqual(result, 'cycle')
            self.assertEqual(len(seen), 256)
            self.assertLessEqual(0xe0 + 4 * max(seen) + 4, 0x4e0)

    def test_match_can_exit(self):
        self.assertEqual(scan(256, 0)[0], 'match')
        self.assertEqual(scan(256, 255)[0], 'match')

    def test_declared_size_does_not_bound_embedded_count(self):
        # A correctly sized opaque response can still encode any uint32 count.
        for count in (249, 250, 255, 256, 0xffffffff):
            response = bytearray(0x4c4)
            response[0xdc:0xe0] = count.to_bytes(4, 'little')
            self.assertEqual(len(response), 0x4c4)
            self.assertEqual(int.from_bytes(response[0xdc:0xe0], 'little'), count)

    def test_requested_buffer_boundary(self):
        self.assertEqual((0x4c4 - 0xe0) // 4, 249)
        self.assertEqual(0xe0 + 249 * 4, 0x4c4)


if __name__ == '__main__':
    unittest.main()
