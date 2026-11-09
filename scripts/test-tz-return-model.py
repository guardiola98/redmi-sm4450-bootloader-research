"""Synthetic branch/packet models. No CPU emulation or monitor-routing claim."""
import unittest

U64 = (1 << 64) - 1


def owner_zero_query(function, argument, helper_nonzero=False):
    """After 0x1c07795c accepted the identifier; original x1 retained."""
    f = function & 0xffff
    if f == 0:
        return 0x10001
    if f != 1 or argument & 0xffffffffbfff0000 != 0x80000000:
        return U64
    target = argument & 0xffff
    if target in (0, 1):
        return 0
    if target in (0x7fff, 0x8000):
        return int(not helper_nonzero)
    return U64


def lookup_status(query_return, callback):
    # cmp/csel followed by cmp/csinv at 1c077a80..1c077a98.
    return -1 if query_return else (0 if callback else -3)


def rejected_packet():
    status = lookup_status(1, 0)
    # Shifted bit mask at 1c077c6c..1c077c90: -1 does not preserve outputs.
    index = (status + 17) & 0xffffffff
    preserve = index <= 20 and bool((1 << index) & 0x1a8001)
    assert not preserve
    # local flag remains zero and internal return is 0x100, not 0x101.
    return [1, 0x83, status & U64] + [0] * 11


class ReturnTests(unittest.TestCase):
    def test_owner_zero_version(self):
        self.assertEqual(owner_zero_query(0, 0), 0x10001)

    def test_owner_zero_no_policy_lookup(self):
        self.assertEqual(owner_zero_query(1, 0x1000), U64)
        self.assertEqual(owner_zero_query(0x1401, 0), U64)
        self.assertEqual(owner_zero_query(1, 0x80000002), U64)

    def test_query_results(self):
        for query in (0, 1):
            self.assertEqual(owner_zero_query(1, 0x80000000 | query), 0)
        for query in (0x7fff, 0x8000):
            self.assertEqual(owner_zero_query(1, 0x80000000 | query), 1)
            self.assertEqual(owner_zero_query(1, 0x80000000 | query, True), 0)

    def test_nonzero_query_takes_precedence(self):
        self.assertEqual(lookup_status(1, 0), -1)
        self.assertEqual(lookup_status(0, 0), -3)
        self.assertEqual(lookup_status(0, 1), 0)

    def test_error_is_packet_x2_not_x0(self):
        packet = rejected_packet()
        self.assertEqual(len(packet), 14)
        self.assertEqual(packet[:3], [1, 0x83, U64])
        self.assertEqual(packet[3:], [0] * 11)


if __name__ == '__main__':
    unittest.main()
