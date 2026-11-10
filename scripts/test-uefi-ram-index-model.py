#!/usr/bin/env python3
"""Symbolic RAM-table indices only: no SMEM bytes, payload or firmware run.

Evidence: TE 0xa7023300/0xa70234d4, original words recorded by the
hash-pinned config inspector. Device data is unknown; the XBL producer is v3.
"""
import unittest

ENTRY_SIZE = 0x48
CAPACITY = 32


def producer_count(ddr_regions):
    """0x1485c584/0x1485c894: count-only success path, no descriptors.

    Assumes successful providers and valid size conversions. DDR entries come
    first; three bounded appends follow. A failed append is not publication.
    """
    if ddr_regions < 0:
        raise ValueError('Nonnegative region count required')
    count = min(ddr_regions, CAPACITY)
    for _ in range(3):
        if count >= CAPACITY:
            return False, count
        count += 1
    return True, count


def updated_count(count, operation):
    """0x1485c938 count invariant for intact tables; no addresses/SMEM bytes."""
    if not 0 <= count <= CAPACITY:
        raise ValueError('Outside the identified producer invariant')
    if count in (0, CAPACITY):
        return False, count
    if operation == 'split':
        return True, count + 1
    if operation == 'remove':
        return True, count - 1
    if operation == 'trim':
        return True, count
    raise ValueError('Unknown symbolic operation')


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
    def test_producer_allocation_covers_exactly_32_v3_records(self):
        self.assertEqual(0x18 + 32 * 0x48, 0x918)
        self.assertEqual(0x18 + 31 * 0x48 + 0x48, 0x918)

    def test_successful_builder_requires_room_for_three_appends(self):
        for ddr in range(65):
            success, count = producer_count(ddr)
            self.assertEqual(success, ddr <= 29)
            self.assertLessEqual(count, CAPACITY)
            if success:
                self.assertEqual(count, ddr + 3)

    def test_identified_v3_path_does_not_have_v1_attribute_mismatch(self):
        self.assertEqual(destinations([False, True, False, True], 3), [(0, 0), (1, 1)])

    def test_updater_preserves_intact_count_bound(self):
        for count in range(33):
            for operation in ('split', 'remove', 'trim'):
                _, result = updated_count(count, operation)
                self.assertTrue(0 <= result <= CAPACITY)
        self.assertEqual(updated_count(31, 'split'), (True, 32))
        self.assertEqual(updated_count(32, 'split'), (False, 32))

    def test_shift_before_inner_guard_is_bounded_by_outer_count_guard(self):
        # Insert-shift destination starts at count, permitted only for count<32.
        for count in range(1, 32):
            highest_destination = count
            self.assertLess(highest_destination, CAPACITY)
        self.assertEqual(updated_count(32, 'trim'), (False, 32))
        with self.assertRaises(ValueError):
            updated_count(33, 'split')  # Not claimed safe for corrupted state.

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
