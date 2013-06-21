'''
Test encode/decode functions
'''

from keepass import infoblock as ib

def test_null():
    dec,enc = ib.null_de()
    assert dec('\x42') is None
    assert enc(69) is None

def test_shunt():
    dec,enc = ib.shunt_de()
    assert dec('\x42') is '\x42'
    assert enc('foo') is 'foo'

def test_string():
    strings = ['foo','to encrypt or to decrypt, that is the ?','new\nline']
    dec,enc = ib.string_de()
    for string in strings:
        assert string == dec(enc(string))
