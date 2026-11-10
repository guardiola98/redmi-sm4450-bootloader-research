#!/usr/bin/env python3
"""Symbolic file-resource contracts; no file bytes, firmware or failure injection."""
import unittest


def roots(provider, successful_opens):
    # Fat 0x57bc allocates distinct handles; FvSimpleFileSystem caches its root.
    if provider == 'fat':
        return {f'root-{i}' for i in range(successful_opens)}
    if provider == 'fv':
        return {'cached-root'} if successful_opens else set()
    raise ValueError('Unknown symbolic provider')


def cleanup_trace(stage):
    """Tz 0x4a00 after successful root/file opening, on returning services.

    Trace records the actual free argument, including None. It does not call
    any allocator, UEFI service, or synthetic failing memory implementation.
    """
    live = {'root', 'file'}
    frees = []
    closes = []
    if stage == 'info-allocation-error':
        return live, closes, frees
    if stage != 'first-info-error':
        live.add('info')
    if stage == 'data-allocation-error':
        live.remove('info')
        return live, closes, ['info']
    if stage in ('read-error', 'success'):
        live.add('data')
    closes.append('file')
    live.remove('file')
    if 'info' in live:
        frees.append('info')
        live.remove('info')
    if stage != 'success':
        pointer = 'data' if 'data' in live else None
        frees.append(pointer)
        live.discard(pointer)
    return live, closes, frees


def grown_cache_result(allocation_result, returned_capacity):
    # Consumer-only hypothetical returned result. Ordinary provider failures
    # halt instead of supplying None; see shared_provider_outcome below.
    return allocation_result, returned_capacity if allocation_result is not None else 0


def shared_provider_outcome(size, ordinary_error=False):
    """Bounded contract: aligned request, valid state, nonzero successful base."""
    if size == 0:
        return 'returned-null'
    return 'assert-wait' if ordinary_error else 'returned-nonnull'


class FileContracts(unittest.TestCase):
    def test_provider_root_lifetimes_are_not_interchangeable(self):
        self.assertEqual(len(roots('fat', 3)), 3)
        self.assertEqual(len(roots('fv', 3)), 1)

    def test_info_errors_reach_free_with_null(self):
        for stage in ('first-info-error', 'second-info-error'):
            live, closes, frees = cleanup_trace(stage)
            self.assertEqual(live, {'root'})
            self.assertEqual(closes, ['file'])
            self.assertIsNone(frees[-1])

    def test_allocation_error_exits_skip_open_handles(self):
        for stage in ('info-allocation-error', 'data-allocation-error'):
            live, closes, _ = cleanup_trace(stage)
            self.assertEqual(live, {'root', 'file'})
            self.assertEqual(closes, [])

    def test_read_error_releases_both_pool_objects(self):
        live, closes, frees = cleanup_trace('read-error')
        self.assertEqual(live, {'root'})
        self.assertEqual(closes, ['file'])
        self.assertEqual(frees, ['info', 'data'])

    def test_failed_growth_clears_cache_but_not_file_temporary(self):
        live, _, _ = cleanup_trace('success')
        pointer, capacity = grown_cache_result(None, 0x90000)
        self.assertIsNone(pointer)
        self.assertEqual(capacity, 0)
        # 0x2630 returns before its sole FreePool(data), at 0x275c.
        self.assertIn('data', live)
        self.assertEqual(grown_cache_result('new-node', 0x90000), ('new-node', 0x90000))

    def test_successful_short_read_count_is_not_the_reported_length(self):
        # Pure lengths: the provider may report a shorter successful read.
        declared_size, remaining = 128, 80
        actual_read = min(declared_size, remaining)
        reported_by_tz = declared_size
        self.assertEqual(reported_by_tz - actual_read, 48)
        self.assertGreater(reported_by_tz, actual_read)

    def test_full_read_has_no_unwritten_tail(self):
        declared_size = 128
        actual_read = min(declared_size, declared_size)
        self.assertEqual(declared_size - actual_read, 0)

    def test_ordinary_shared_error_is_not_a_null_return_producer(self):
        self.assertEqual(shared_provider_outcome(0x90000, True), 'assert-wait')
        self.assertEqual(shared_provider_outcome(0x90000), 'returned-nonnull')
        self.assertEqual(shared_provider_outcome(0), 'returned-null')


if __name__ == '__main__':
    unittest.main()
