"""Synthetic register-domain model, not ARM execution or a reachability test."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    'tz_return', Path(__file__).with_name('test-tz-return-model.py'))
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)


def return_to_nonsecure(packet, saved_registers, scr_ns, saved_scr_rw=True):
    """Only command 1/subtype 3, valid contexts, zero optional metadata.

    Models initialized context mode (1c01c0d0 == 1), then
    1c00feec -> 1c00f870 -> 1c011054. Other routes intentionally
    fail rather than inventing responses. NS selects the command namespace.
    """
    if len(packet) != 14 or len(saved_registers) != 31:
        raise ValueError('Incomplete synthetic register frame')
    if scr_ns or packet[0] != 1 or packet[1] & 0x7f != 3:
        raise ValueError('Outside the studied secure response route')
    if any(packet[6:]):
        raise ValueError('Optional metadata outside model scope')
    result = saved_registers.copy()
    if saved_scr_rw:
        # 1c010558..574 -> 1c010b2c: clear 0x70 bytes from word 4.
        result[4:18] = [0] * 14
    result[:4] = packet[2:6]
    return result


class MonitorTests(unittest.TestCase):
    def test_rejection_changes_register_domain(self):
        packet = previous.rejected_packet()
        restored = return_to_nonsecure(packet, [0] * 31, scr_ns=0)
        self.assertEqual(restored[:4], [previous.U64, 0, 0, 0])
        self.assertNotEqual(restored[0], packet[0])
        # W0 is negative, so ScmDxeLA's signed-positive retry is not taken.
        self.assertEqual(restored[0] & 0xffffffff, 0xffffffff)

    def test_register_order_and_preservation(self):
        saved = list(range(31))
        packet = [1, 0x83, 0x11, 0x22, 0x33, 0x44] + [0] * 8
        result = return_to_nonsecure(packet, saved, scr_ns=0)
        self.assertEqual(result[:4], [0x11, 0x22, 0x33, 0x44])
        self.assertEqual(result[4:18], [0] * 14)
        self.assertEqual(result[18:], saved[18:])
        self.assertEqual(saved, list(range(31)))

    def test_conditional_clearing_preserves_status(self):
        saved = list(range(31))
        packet = previous.rejected_packet()
        result = return_to_nonsecure(packet, saved, 0, saved_scr_rw=False)
        self.assertEqual(result[:4], [previous.U64, 0, 0, 0])
        self.assertEqual(result[4:], saved[4:])

    def test_namespaces_and_subtypes_are_separate(self):
        packet = previous.rejected_packet()
        with self.assertRaises(ValueError):
            return_to_nonsecure(packet, [0]*31, scr_ns=1)
        packet[1] = 0x81  # Initialization is not this return-only model.
        with self.assertRaises(ValueError):
            return_to_nonsecure(packet, [0]*31, scr_ns=0)

    def test_model_rejects_unstudied_metadata_and_truncation(self):
        packet = previous.rejected_packet()
        with self.assertRaises(ValueError):
            return_to_nonsecure(packet[:-1], [0]*31, scr_ns=0)
        packet[11] = 0x1234  # Synthetic entry pointer: never interpreted.
        with self.assertRaises(ValueError):
            return_to_nonsecure(packet, [0]*31, scr_ns=0)


if __name__ == '__main__':
    unittest.main()
