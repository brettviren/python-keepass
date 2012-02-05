# -*- coding: utf-8 -*-

'''
The keepass file header.

From the KeePass doc:

Database header: [DBHDR]

[ 4 bytes] DWORD    dwSignature1  = 0x9AA2D903
[ 4 bytes] DWORD    dwSignature2  = 0xB54BFB65
[ 4 bytes] DWORD    dwFlags
[ 4 bytes] DWORD    dwVersion       { Ve.Ve.Mj.Mj:Mn.Mn.Bl.Bl }
[16 bytes] BYTE{16} aMasterSeed
[16 bytes] BYTE{16} aEncryptionIV
[ 4 bytes] DWORD    dwGroups        Number of groups in database
[ 4 bytes] DWORD    dwEntries       Number of entries in database
[32 bytes] BYTE{32} aContentsHash   SHA-256 hash value of the plain contents
[32 bytes] BYTE{32} aMasterSeed2    Used for the dwKeyEncRounds AES
                                    master key transformations
[ 4 bytes] DWORD    dwKeyEncRounds  See above; number of transformations

Notes:

- dwFlags is a bitmap, which can include:
  * PWM_FLAG_SHA2     (1) for SHA-2.
  * PWM_FLAG_RIJNDAEL (2) for AES (Rijndael).
  * PWM_FLAG_ARCFOUR  (4) for ARC4.
  * PWM_FLAG_TWOFISH  (8) for Twofish.
- aMasterSeed is a salt that gets hashed with the transformed user master key
  to form the final database data encryption/decryption key.
  * FinalKey = SHA-256(aMasterSeed, TransformedUserMasterKey)
- aEncryptionIV is the initialization vector used by AES/Twofish for
  encrypting/decrypting the database data.
- aContentsHash: "plain contents" refers to the database file, minus the
  database header, decrypted by FinalKey.
  * PlainContents = Decrypt_with_FinalKey(DatabaseFile - DatabaseHeader)
'''

class DBHDR(object):
    '''
    Interface to the database header chunk.
    '''

    format = [
        ('signature1',4,'I'),
        ('signature2',4,'I'),
        ('flags',4,'I'),
        ('version',4,'I'),
        ('master_seed',16,'16s'),
        ('encryption_iv',16,'16s'),
        ('ngroups',4,'I'),
        ('nentries',4,'I'),
        ('contents_hash',32,'32s'),
        ('master_seed2',32,'32s'),
        ('key_enc_rounds',4,'I'),
    ]

    signatures = (0x9AA2D903,0xB54BFB65)
    length = 124

    encryption_flags = (
        ('SHA2',1),
        ('Rijndael',2),
        ('AES',2),
        ('ArcFour',4),
        ('TwoFish',8),
    )

    def __init__(self,buf=None):
        'Create a header, read self from binary string if given'
        if buf: self.decode(buf)

    def __str__(self):
        ret = ['Header:']
        for field in DBHDR.format:
            # field is a tuple (name, size, type)
            name = field[0]
            ret.append('\t%s %s'%(name,self.__dict__[name]))
        return '\n'.join(ret)

    def encryption_type(self):
        for encflag in DBHDR.encryption_flags[1:]:
            if encflag[1] & self.flags: return encflag[0]
        return 'Unknown'

    def encode(self):
        'Provide binary string representation'
        import struct
        ret = ""
        for field in DBHDR.format:
            name,bytes,typecode = field
            value = self.__dict__[name]
            buf = struct.pack('<'+typecode,value)
            ret += buf
        return ret

    def decode(self,buf):
        'Fill self from binary string.'
        import struct
        index = 0
        for field in DBHDR.format:
            name,nbytes,typecode = field
            string = buf[index:index+nbytes]
            index += nbytes
            value = struct.unpack('<'+typecode, string)[0]
            self.__dict__[name] = value
        if DBHDR.signatures[0] != self.signature1 or \
                DBHDR.signatures[1] != self.signature2:
            msg = 'Bad sigs:\n%s %s\n%s %s'%\
                (DBHDR.signatures[0],DBHDR.signatures[1],
                 self.signature1,self.signature2)
            raise IOError,msg
