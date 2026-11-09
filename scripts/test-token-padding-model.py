#!/usr/bin/env python3
"""Synthetic tests of the observed padding contract; does NOT execute firmware/RSA."""
import unittest

def accepts(block, message):
    if len(block) != 256 or not 1 <= len(message) <= 245:
        return False
    separator = 255 - len(message)
    return (block[:2] == b'\x00\x01' and
            block[2:separator] == b'\xff' * (separator - 2) and
            block[separator] == 0 and block[separator+1:] == message)

def encoded(message):
    return b'\x00\x01' + b'\xff' * (253-len(message)) + b'\x00' + message

class PaddingContract(unittest.TestCase):
    def test_boundaries(self):
        for n in (1, 64, 245):
            self.assertTrue(accepts(encoded(b'A'*n), b'A'*n))
        for n in (0,246):
            self.assertFalse(accepts(encoded(b'A'*n), b'A'*n))
    def test_every_single_byte_mutation(self):
        message=b'offline synthetic fixture'
        good=encoded(message)
        for i in range(256):
            bad=bytearray(good); bad[i]^=1
            self.assertFalse(accepts(bad,message), i)
    def test_wrong_message_and_length(self):
        self.assertFalse(accepts(encoded(b'abc'),b'abd'))
        self.assertFalse(accepts(encoded(b'abc')[:-1],b'abc'))
if __name__ == '__main__': unittest.main()
