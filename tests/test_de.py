# -*- coding: utf-8 -*-
'''
Test encode/decode functions
'''
import unittest
from keepasslib import infoblock

class TestDecodeEncode (unittest.TestCase):

    def test_null(self):
        dec, enc = infoblock.null_de()
        self.assertTrue(dec('\x42') is None)
        self.assertTrue(enc(69) is None)

    def test_shunt(self):
        dec, enc = infoblock.shunt_de()
        self.assertEqual(dec('\x42'), '\x42')
        self.assertEqual(enc('foo'), 'foo')

    def test_string(self):
        strings = ['foo','to encrypt or to decrypt, that is the ?','new\nline']
        dec, enc = infoblock.string_de()
        for string in strings:
            self.assertEqual(string, dec(enc(string)))
