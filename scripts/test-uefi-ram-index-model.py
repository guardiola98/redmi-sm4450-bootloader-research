#!/usr/bin/env python3
"""Symbolic RAM-table indices only: no SMEM bytes, payload or firmware run.

Evidence: TE 0xa7023300/0xa70234d4, original words recorded by the
hash-pinned config inspector. The source partition sequence is unknown.
"""
import unittest

ENTRY_SIZE = 0x48
CAPACITY = 32


def destinations(accepted, version):
    """Return logical indices for descriptor and attribute writes."""
    output_index = 0
    result = []
    for input_index, selected in enumerate(accepted):
        if selected:
            attribute_index = input_index if version == 1 else output_index
            result.append((output_index, attribute_index))
            output_index += 1
            if output_index > CAPACITY:
                break  # ASSERT occurs after the recorded write.
    return result


class RamIndexTests(unittest.TestCase):
    def test_v1_filtering_separates_descriptor_and_attributes(self):
        self.assertEqual(destinations([False, True], 1), [(0, 1)])
        self.assertEqual(destinations([True, False, True], 1), [(0, 0), (1, 2)])
        self.assertEqual(destinations([True, True], 1), [(0, 0), (1, 1)])

    def test_other_version_uses_output_index_consistently(self):
        self.assertEqual(destinations([False, True, False, True], 2), [(0, 0), (1, 1)])

    def test_postwrite_capacity_check_is_late_in_both_versions(self):
        for version in (1, 2):
            self.assertEqual(len(destinations([True]*32, version)), CAPACITY)
            writes = destinations([True]*33, version)
            self.assertEqual(writes[-1][0], CAPACITY)
            self.assertEqual(writes[-1][0] * ENTRY_SIZE, 0x900)
            # The first output array ends exactly at the second one's base.
            self.assertEqual(0xa7044610 + ENTRY_SIZE * CAPACITY, 0xa7044f10)

    def test_v1_attribute_index_can_exceed_capacity_with_small_output_count(self):
        writes = destinations([False]*32 + [True], 1)
        self.assertEqual(writes, [(0, 32)])
        self.assertGreaterEqual(writes[0][1] * ENTRY_SIZE + 0x38, CAPACITY * ENTRY_SIZE)
        # Only one output entry: a count>32 guard would not reject this case.
        self.assertLessEqual(len(writes), CAPACITY)


if __name__ == '__main__':
    unittest.main()
