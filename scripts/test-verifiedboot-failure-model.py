#!/usr/bin/env python3
"""Offline abstraction of observed CFG edges, not firmware execution.

An injected null allocation result, successful storage and SCM status flow are modeled.
The real allocator error paths halt in ASSERT; reaching this injected result
through ordinary allocation failure has not been established.
SCM/QSEE setup succeeds by assumption. No device, tokens, RSA or allocator
exhaustion is implemented. See docs/verifiedboot-failure-analysis.md.
"""
from dataclasses import dataclass
import unittest


@dataclass
class State:
    magic: bool = True
    normal: int = 0
    critical: int = 0


def transfer(op, ram, disk, allocation_ok):
    # VB 0x17bc/0x185c -> 0x1950 -> 0x1640: zero, no copy.
    if not allocation_ok:
        return 0
    source, target = (disk, ram) if op == 0 else (ram, disk)
    target.magic, target.normal, target.critical = (
        source.magic, source.normal, source.critical)
    return 0


def setter(field, value, ram, disk, allocation_ok):
    # ABL 0x440b0 / 0x44188: early equality return; store precedes call.
    if getattr(ram, field) == value:
        return 0
    setattr(ram, field, value)
    return transfer(1, ram, disk, allocation_ok)


def initial_read(ram, disk, read_ok, write_ok, secure_result_byte):
    status = transfer(0, ram, disk, read_ok)
    needs_read = False  # ABL 0x446e8..0x446f0, after zero status
    if not ram.magic:
        ram.magic = True
        ram.normal = ram.critical = int(secure_result_byte == 0)
        status = transfer(1, ram, disk, write_ok)
    return status, needs_read


def secure_query_byte(locate_status=0, protocol_present=True,
                      scm_status=0, response_status=1, state_word=0x40):
    # 0x100b4: all local failures converge at 0x1016c; helpers preserve w0.
    if (locate_status != 0 or not protocol_present or scm_status != 0
            or response_status != 1):
        result = 0xffffffff
    else:
        result = state_word & 0xffffffff  # ldur w0, [x22, #-0x70]
    # 0x10284 error -> 0x8000000000000001 -> 0x2e4c0 byte 1.
    return 1 if result == 0xffffffff else int((result & 0x47) == 0x40)


def authorized_set(token_status, ram, disk, allocation_ok):
    # Scope ends at first setter, before later reset/recovery operations.
    if token_status != 0:
        return token_status
    return setter('normal', 1, ram, disk, allocation_ok)


class FailureEffects(unittest.TestCase):
    def test_false_write_success_both_fields(self):
        for field in ('normal', 'critical'):
            ram, disk = State(), State()
            self.assertEqual(setter(field, 1, ram, disk, False), 0)
            self.assertEqual(getattr(ram, field), 1)
            self.assertEqual(getattr(disk, field), 0)

    def test_repeated_set_skips_persistence(self):
        ram, disk = State(), State()
        setter('normal', 1, ram, disk, False)
        setter('normal', 1, ram, disk, True)
        self.assertEqual((ram.normal, disk.normal), (1, 0))

    def test_successful_later_write_copies_whole_configuration(self):
        ram, disk = State(), State()
        setter('normal', 1, ram, disk, False)
        setter('critical', 1, ram, disk, True)
        self.assertEqual((disk.normal, disk.critical), (1, 1))

    def test_token_failure_blocks_setter(self):
        ram, disk = State(), State()
        self.assertNotEqual(authorized_set(0x50, ram, disk, False), 0)
        self.assertEqual((ram.normal, disk.normal), (0, 0))

    def test_read_failure_preserves_valid_existing_buffer(self):
        ram, disk = State(normal=1), State()
        self.assertEqual(initial_read(ram, disk, False, False, 1), (0, False))
        self.assertEqual((ram.normal, disk.normal), (1, 0))

    def test_invalid_magic_defaults_depend_on_secure_result(self):
        for secure in (0, 1, 255):
            ram, disk = State(magic=False), State()
            self.assertEqual(initial_read(ram, disk, False, False, secure), (0, False))
            self.assertEqual((ram.normal, ram.critical), (int(secure == 0),)*2)
            self.assertEqual((disk.normal, disk.critical), (0, 0))

    def test_scm_failures_keep_invalid_header_defaults_locked(self):
        cases = [dict(locate_status=1), dict(locate_status=0x8000000000000001),
                 dict(protocol_present=False), dict(scm_status=1),
                 dict(response_status=0), dict(response_status=2),
                 dict(state_word=0xffffffff)]
        for case in cases:
            with self.subTest(case=case):
                ram, disk = State(magic=False), State()
                initial_read(ram, disk, False, True, secure_query_byte(**case))
                self.assertEqual((ram.normal, ram.critical), (0, 0))
                self.assertEqual((disk.normal, disk.critical), (0, 0))

    def test_successful_scm_response_still_controls_defaults(self):
        for word, expected in [(0x40, 0), (0x48, 0), (0, 1), (0x41, 1)]:
            with self.subTest(word=word):
                ram, disk = State(magic=False), State()
                initial_read(ram, disk, False, False,
                             secure_query_byte(state_word=word))
                self.assertEqual((ram.normal, ram.critical), (expected, expected))

    def test_normal_read_restores_persistent_state(self):
        ram, disk = State(normal=1), State()
        initial_read(ram, disk, True, True, 1)
        self.assertEqual(ram.normal, 0)


if __name__ == '__main__':
    unittest.main()
