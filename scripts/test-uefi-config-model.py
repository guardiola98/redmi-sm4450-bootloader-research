#!/usr/bin/env python3
"""Synthetic UEFI config contracts: no firmware execution or config payload.

Tests explicit validity of the narrow getter's temporary, caller error guards,
table index boundaries, and the audit inspector's independent address mapping.
"""
import importlib.util
from pathlib import Path
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


config = module('config', 'inspect-scm-static-config.py')
evidence = module('evidence', 'inspect-uefi-config-contract.py')
scm = module('scm', 'test-scm-initialization-model.py')
EFI_ERROR = 1 << 63


def narrow_getter(status, produced, prior_stack_word, caller_output):
    """A concrete stale-word representative, never an actual uninitialized read.

    Wide getter writes its local only on success. Narrow getter reads anyway.
    Return validity separately so tests cannot silently treat it as real config.
    """
    initialized = produced is not None
    temporary = produced if initialized else prior_stack_word
    if temporary >> 32:
        return EFI_ERROR | 2, caller_output, initialized
    return status, temporary, initialized


def insertion_offset(count, capacity):
    # Observed B.HI then nonzero-capacity test; no allocation or write.
    return 16 * count if count <= capacity and capacity else None


def decompression_choice(status, produced, prior):
    status, out, _ = narrow_getter(status, produced, prior, 1)
    # Caller only replaces NOT_FOUND, but a masked status leaves out=1.
    return 1 if status == EFI_ERROR | 14 else out


def decimal_conversion(value):
    """Symbolic integer input, no string or firmware configuration generated."""
    maximum = (1 << 64) - 1
    return (EFI_ERROR | 3, maximum) if value > maximum else (0, value)


class ConfigTests(unittest.TestCase):
    def test_resource_inventory_tracks_sections_and_duplicate_names(self):
        raw = (b'[ConfigParameters]\nConfigParameterCount=4\nSecurityFlag=0xC4\n'
               b'# SecurityFlag=0\nsecurityflag=0\n[ChipIDConfig]\n')
        result = config.summarize_text(raw)
        self.assertEqual(result['config_parameter_value_rows'], 2)
        self.assertEqual(result['selected_keys']['SecurityFlag'], ['0xC4'])
        self.assertEqual(result['duplicate_parameter_names'], ['securityflag'])
        self.assertIn('ChipIDConfig', result['section_names'])

    def test_memory_summary_separates_static_ranges_from_dynamic_exclusions(self):
        raw = (b'[MemoryMap]\n0x8000,0x1000,Example,AddMem,SYS_MEM,SYS_MEM_CAP,Conv,WRITE_BACK\n'
               b'0xA000,0x2000,Later,AddDynamicMem,SYS_MEM,SYS_MEM_CAP,Conv,WRITE_BACK\n'
               b'[RegisterMap]\n0x4000,0x1000,Register,AddDev,MMAP_IO,UNCACHEABLE,MmIO,NS_DEVICE\n')
        result = config.summarize_memory_ranges(raw)
        self.assertEqual(result['section_counts'], {'MemoryMap': 2, 'RegisterMap': 1})
        self.assertEqual(result['eligible_before_dynamic_merge'], 2)
        self.assertEqual(result['excluded_before_dynamic_merge'], 1)
        self.assertEqual(result['minimum_eligible_base'], '0x4000')
        self.assertTrue(result['all_ranges_page_aligned'])
        self.assertFalse(result['contains_address_zero'])

    def test_memory_summary_refuses_wrapped_ranges(self):
        with self.assertRaises(ValueError):
            config.summarize_memory_ranges(
                b'[MemoryMap]\n0xfffffffffffff000,0x2000,X,AddMem,X,X,X,X\n')

    def test_valid_uint32_and_overflow(self):
        self.assertEqual(narrow_getter(0, 0xc4, 0, 0), (0, 0xc4, True))
        self.assertEqual(narrow_getter(0, 1 << 32, 0, 17), (EFI_ERROR | 2, 17, True))

    def test_failed_wide_getter_does_not_initialize_temporary(self):
        missing = EFI_ERROR | 14
        self.assertEqual(narrow_getter(missing, None, 0x12345678, 0),
                         (missing, 0x12345678, False))
        self.assertEqual(narrow_getter(missing, None, 1 << 32, 17),
                         (EFI_ERROR | 2, 17, False))

    def test_scm_status_guards_preserve_defaults_despite_output_pollution(self):
        for prior in (0, 0x100, 0xffffffff, 1 << 32, (1 << 64)-1):
            status, value, valid = narrow_getter(EFI_ERROR | 14, None, prior, 0)
            self.assertNotEqual(status, 0)
            self.assertFalse(valid)
            self.assertEqual(scm.table_sizes(value if status == 0 else None)[0], (256, 256, 256))
            self.assertNotIn(('log', 0), scm.initialize(0, 0, config_status=status, flags=value)[1])

    def test_missing_decompression_key_preserves_default_for_both_error_paths(self):
        for prior in (0, 1, 0xffffffff, 1 << 32, (1 << 64)-1):
            self.assertEqual(decompression_choice(EFI_ERROR | 14, None, prior), 1)

    def test_unchecked_consumer_can_use_polluted_output_conditionally(self):
        status, out, valid = narrow_getter(EFI_ERROR | 14, None, 1, 0)
        self.assertNotEqual(status, 0)
        self.assertFalse(valid)
        self.assertTrue(out != 0)  # 0xa7024994 consumes without testing status.
        self.assertEqual(narrow_getter(EFI_ERROR | 14, None, 1 << 32, 0)[1], 0)
        self.assertEqual(narrow_getter(0, 1, 0, 0), (0, 1, True))

    def test_decimal_overflow_status_is_lost_by_wide_getter_but_narrow_rejects(self):
        conversion_status, saturated = decimal_conversion(1 << 64)
        self.assertNotEqual(conversion_status, 0)
        # a701ba8c returns only value; a701d6f0 makes wide status zero.
        wide_status = 0
        self.assertEqual(saturated, (1 << 64)-1)
        self.assertEqual(narrow_getter(wide_status, saturated, 0, 17),
                         (EFI_ERROR | 2, 17, True))
        self.assertEqual(decimal_conversion((1 << 64)-1), (0, (1 << 64)-1))

    def test_capacity_equality_is_one_entry_outside_declared_table(self):
        self.assertEqual(insertion_offset(63, 64), 1008)
        self.assertEqual(insertion_offset(64, 64), 1024)
        self.assertIsNone(insertion_offset(65, 64))
        self.assertIsNone(insertion_offset(0, 0))
        # Actual resource has 43 values: final written entry is index 42.
        self.assertLess(insertion_offset(42, 64) + 15, 64 * 16)

    def test_preferred_va_mapping_rejects_unbacked_reads(self):
        layout = dict(image_base='0x100000', sections=[dict(rva=0x200, raw_size=8, te_offset=4)])
        blob = b'HEADabcdefgh'
        self.assertEqual(evidence.read_va(blob, layout, 0x100204, 4), (8, b'efgh'))
        for address, size in ((0x1001ff, 1), (0x100208, 1), (0x100204, 5), (0x100204, -1)):
            with self.assertRaises(ValueError):
                evidence.read_va(blob, layout, address, size)


if __name__ == '__main__':
    unittest.main()
