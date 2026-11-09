"""Synthetic state/size obligations from reviewed SCM init; no firmware execution.

External statuses are supplied by the test, not predictions of TrustZone.
Only normal-return paths are modeled; provider ASSERT paths are excluded.
"""
import unittest

EFI_ERROR = 1 << 63


def initialize(probe_status, init_status, install_status=0,
               config_status=0, flags=0, log_status=0):
    selected = 'legacy' if probe_status & EFI_ERROR else 'armv8'
    events = ['probe', 'init_'+selected]
    if init_status:
        return init_status, events
    events.append('install_'+selected)
    if install_status:
        return install_status, events
    if config_status == 0 and flags & 0x100:
        events.append(('log', log_status))
    return 0, events


def table_sizes(config=None):
    if config is None:
        local, remote, asynchronous = 256, 256, 256
    else:
        if not 0 <= config <= 0xffffffff:
            raise ValueError('Configuration is a uint32')
        local, remote, asynchronous = config >> 21, (config >> 10) & 0x7ff, config & 0x3ff
    async_size = (4*asynchronous+0x17) & ~7
    total = 24*local + ((12*remote+7) & ~7) + 2*async_size
    return (local, remote, asynchronous), total


def cleanup_accesses(remote_base, remote_count, objects, async_base):
    """Return effective addresses only; never read/write memory at them.

    Models 0x57fc and the unconditional 0x4ccc read with no live client.
    Later accesses are hypothetical if an earlier access would fault.
    """
    accesses = []
    for pointer in objects:
        index = ((pointer-remote_base) & ((1 << 64)-1)) // 12
        if index < remote_count:
            accesses += [('write32', remote_base+12*index+offset) for offset in (0, 4, 8)]
    accesses.append(('read32', async_base+8))
    return accesses


class InitializationTests(unittest.TestCase):
    def test_initializer_error_never_selects_a_second_transport(self):
        for probe, transport in ((0, 'armv8'), (EFI_ERROR|3, 'legacy')):
            for status in (EFI_ERROR|7, EFI_ERROR|9, 1):
                self.assertEqual(initialize(probe, status),
                                 (status, ['probe', 'init_'+transport]))

    def test_install_failure_is_preserved(self):
        status, events = initialize(0, 0, EFI_ERROR|9, flags=0x100)
        self.assertEqual(status, EFI_ERROR|9)
        self.assertNotIn(('log', 0), events)

    def test_log_failure_cannot_revoke_installed_transport(self):
        for log_status in (0, EFI_ERROR|7):
            status, events = initialize(0, 0, flags=0x100, log_status=log_status)
            self.assertEqual(status, 0)
            self.assertEqual(events[-2:], ['install_armv8', ('log', log_status)])
        self.assertEqual(initialize(0, 0, flags=0xc4)[1][-1], 'install_armv8')

    def test_packed_config_bounds_are_not_service_count_bounds(self):
        self.assertEqual(table_sizes(), ((256, 256, 256), 11296))
        counts, maximum = table_sizes(0xffffffff)
        self.assertEqual(counts, (2047, 2047, 1023))
        self.assertEqual(maximum, 81920)
        # Formula is monotone in each nonnegative bounded field; maximum
        # therefore covers all uint32 configurations, not just this sample.
        self.assertLess(maximum, 1 << 32)
        self.assertEqual(table_sizes(0), ((0, 0, 0), 32))
        with self.assertRaises(ValueError):
            table_sizes(1 << 32)

    def test_failed_first_table_allocation_cleanup_requires_valid_pointers(self):
        # Original PE zero globals + normal AllocatePool error, default count.
        trace = cleanup_accesses(0, 256, [0, 0], 0)
        self.assertEqual(trace[0], ('write32', 0))
        self.assertEqual(trace[-1], ('read32', 8))
        # Even a zero configured remote count does not validate async_base.
        self.assertEqual(cleanup_accesses(0, 0, [0, 0], 0), [('read32', 8)])


if __name__ == '__main__':
    unittest.main()
