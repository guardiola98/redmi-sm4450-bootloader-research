#!/usr/bin/env python3
"""Synthetic contracts only: symbolic owners/statuses, no firmware or payloads.

Evidence: TzDxeLA 0x1e74/0x1f2c/0x3454; ShmBridgeDxe 0x2890/0x2b4c.
These tests establish conditional state transitions, not real repeat callers.
"""
import unittest

EFI_ERROR = 1 << 63


def diagnostic_route(security_status, marker, flags, encrypted_status, encrypted):
    if not security_status & EFI_ERROR and marker == 1 and flags & 0x501:
        return 'security-stop'
    if encrypted_status & EFI_ERROR:
        return 'query-stop'
    return 'encrypted' if encrypted == 1 else 'policy'


def load_result(transport_status, application_id):
    # 0x1d08 discards the ID on any nonzero status; diagnostic returns void.
    value = 0 if transport_status else application_id & 0xffffffff
    return EFI_ERROR | 1 if ((value + 1) & 0xffffffff) < 2 else 0


class SharedBlock:
    """One symbolic registered node, initially owned by TzDxeLA."""
    def __init__(self):
        self.owner = 'tz'
        self.capacity = 0x82000
        self.available_bytes = 0

    def release(self):
        # Matching pointer is enough: provider does not check the busy flag.
        self.owner = None
        self.available_bytes += self.capacity

    def acquire(self, owner):
        if self.owner is not None:
            raise ValueError('Model only allows reuse of a free block')
        self.owner = owner
        self.available_bytes -= self.capacity


def cached_get(block, size):
    if not 0 < size <= block.capacity:
        raise ValueError('This bounded model covers the cache-hit path only')
    # TzDxeLA returns cached pointer without acquiring the provider node.
    return block


class ResourceTests(unittest.TestCase):
    def test_security_and_encryption_errors_are_distinct_gates(self):
        self.assertEqual(diagnostic_route(0, 1, 0x100, 0, 0), 'security-stop')
        self.assertEqual(diagnostic_route(EFI_ERROR | 7, 1, 0x100, 0, 0), 'policy')
        self.assertEqual(diagnostic_route(0, 0, 0x100, EFI_ERROR | 3, 0), 'query-stop')
        self.assertEqual(diagnostic_route(0, 1, 0, 0, 1), 'encrypted')

    def test_returned_diagnostic_cannot_repair_load_error(self):
        for error in (1, EFI_ERROR | 3, EFI_ERROR | 9):
            self.assertEqual(load_result(error, 17), EFI_ERROR | 1)
        for invalid_id in (0, 0xffffffff):
            self.assertEqual(load_result(0, invalid_id), EFI_ERROR | 1)
        self.assertEqual(load_result(0, 17), 0)

    def test_serial_cache_reuse_does_not_reacquire_ownership(self):
        block = SharedBlock()
        cached_get(block, 16).release()
        reused = cached_get(block, 16)
        self.assertIsNone(reused.owner)
        reused.release()
        self.assertEqual(block.available_bytes, 2 * block.capacity)

    def test_intervening_allocation_can_alias_the_stale_cache(self):
        block = SharedBlock()
        cached_get(block, 16).release()
        block.acquire('another-client')
        reused = cached_get(block, 16)
        self.assertEqual(reused.owner, 'another-client')
        # Caller still releases it. No actual memory access is performed.
        reused.release()
        self.assertIsNone(block.owner)


if __name__ == '__main__':
    unittest.main()
