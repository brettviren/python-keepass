#!/usr/bin/env python
'''
KeePass v1 database file from Docs/DbFormat.txt of KeePass v1.

General structure:

[DBHDR][GROUPINFO][GROUPINFO][GROUPINFO]...[ENTRYINFO][ENTRYINFO][ENTRYINFO]...

[1x] Database header
[Nx] All groups
[Mx] All entries

'''

import struct


class DBHDR(object):
    '''Database header: [DBHDR]

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

    format = [
        ('dwSignature1',4,'I'),
        ('dwSignature2',4,'I'),
        ('dwFlags',4,'I'),
        ('dwVersion',4,'I'),
        ('aMasterSeed',16,'16s'),
        ('aEncryptionIV',16,'16s'),
        ('dwGroups',4,'I'),
        ('dwEntries',4,'I'),
        ('aContentsHash',32,'32s'),
        ('aMasterSeed2',32,'32s'),
        ('dwKeyEncRounds',4,'I'),
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
        return

    def __str__(self):
        ret = ['Header:']
        for field in DBHDR.format:
            name = field[0]
            size = field[1]
            typ = field[2]
            ret.append('\t%s %s'%(name,self.__dict__[name]))
            continue
        return '\n'.join(ret)

    def encryption_type(self):
        for encflag in DBHDR.encryption_flags[1:]:
            if encflag[1] & self.dwFlags: return encflag[0]
        return 'Unknown'

    def encode(self):
        'Provide binary string representation'

        ret = ""

        for field in DBHDR.format:
            name,bytes,typecode = field
            value = self.__dict__[name]
            buf = struct.pack('<'+typecode,value)
            ret += buf
            continue
        return ret

    def decode(self,buf):
        'Fill self from binary string.'
        index = 0
        for field in DBHDR.format:
            name,nbytes,typecode = field
            string = buf[index:index+nbytes]
            index += nbytes
            value = struct.unpack('<'+typecode, string)[0]
            self.__dict__[name] = value
            continue

        if DBHDR.signatures[0] != self.dwSignature1 or \
                DBHDR.signatures[1] != self.dwSignature2:
            msg = 'Bad sigs:\n%s %s\n%s %s'%\
                (DBHDR.signatures[0],DBHDR.signatures[1],
                 self.dwSignature1,self.dwSignature2)
            raise IOError,msg

        return

    pass                        # DBHDR

# return tupleof (decode,encode) functions

def null_de(): return (lambda buf:Null, lambda val:Null)
def shunt_de(): return (lambda buf:buf, lambda val:val)

def ascii_de():
    from binascii import b2a_hex, a2b_hex
    return (lambda buf:b2a_hex(buf).replace('\0',''), 
            lambda val:a2b_hex(value)+'\0')

def string_de():
    return (lambda buf: buf.replace('\0',''), lambda val: val+'\-')

def short_de():
    return (lambda buf:struct.unpack("<H", buf)[0],
            lambda val:struct.pack("<H", val))

def int_de():
    return (lambda buf:struct.unpack("<I", buf)[0],
            lambda val:struct.pack("<I", val))

def date_de():
    from datetime import datetime
    def decode(buf):
        b = struct.unpack('<5B', buf)
        year = (b[0] << 6) | (b[1] >> 2);
        mon  = ((b[1] & 0b11)     << 2) | (b[2] >> 6);
        day  = ((b[2] & 0b111111) >> 1);
        hour = ((b[2] & 0b1)      << 4) | (b[3] >> 4);
        min  = ((b[3] & 0b1111)   << 2) | (b[4] >> 6);
        sec  = ((b[4] & 0b111111));
        #print 'dateify:',b,buf,year, mon, day, hour, min, sec
        return datetime(year, mon, day, hour, min, sec)

    def encode(val):
        year, mon, day, hour, min, sec = val
        b=[]
        b[0] = 0x0000FFFF & ( (year>>6)&0x0000003F )
        b[1] = 0x0000FFFF & ( ((year&0x0000003f)<<2) | ((month>>2) & 0x00000003) )
        b[2] = 0x0000FFFF & ( (( mon&0x00000003)<<6) | ((day&0x0000001F)<<1) | ((hour>>4)&0x00000001) )
        b[3] = 0x0000FFFF & ( ((hour&0x0000000F)<<4) | ((min>>2)&0x0000000F) )
        b[4] = 0x0000FFFF & ( (( min&0x00000003)<<6) | (sec&0x0000003F))
        return struct.pack('<5B',b)
    return (decode,encode)

class InfoBase(object):
    'Base class for info type blocks'

    def __init__(self,format,string=None):
        self.format = format
        self.order = []         # keep field order
        if string: self.decode(string)
        return

    def __str__(self):
        ret = [self.__class__.__name__ + ':']
        for num,form in self.format.iteritems():
            try:
                value = self.__dict__[form[0]]
            except KeyError:
                continue
            ret.append('\t%s %s'%(form[0],value))
        return '\n'.join(ret)

    def decode(self,string):
        'Fill self from binary string'
        index = 0
        while True:
            substr = string[index:index+6]
            index += 6
            typ,siz = struct.unpack('<H I',substr)
            self.order.append((typ,siz))

            substr = string[index:index+siz]
            index += siz
            buf = struct.unpack('<%ds'%siz,substr)[0]

            name,decenc = self.format[typ]
            if name is None: break
            try:
                value = decenc[0](buf)
            except struct.error,msg:
                msg = '%s, typ = %d[%d] -> %s buf = "%s"'%\
                    (msg,typ,siz,self.format[typ],buf)
                raise struct.error,msg

            #print '%s: type = %d[%d] -> %s buf = "%s" value = %s'%\
            #    (name,typ,siz,self.format[typ],buf,str(value))
            self.__dict__[name] = value
            continue
        return

    def __len__(self):
        length = 0
        for typ,siz in self.order:
            length += 2+4+siz
        return length

    def encode(self):
        'Return binary string representatoin'
        string = ""
        for typ,siz in self.order:
            name,decenc = self.format(typ)
            value = self.__dict__[name]
            encoded = decenc[1](value)
            buf = struct.pack('<H',typ)
            buf += struct.pack('<I',siz)
            buf += struct.pack('<$ds'%siz,encoded)
            string += buf
            continue
        return string

    pass



class GroupInfo(InfoBase):
    '''One group: [FIELDTYPE(FT)][FIELDSIZE(FS)][FIELDDATA(FD)]
           [FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)]...

[ 2 bytes] FIELDTYPE
[ 4 bytes] FIELDSIZE, size of FIELDDATA in bytes
[ n bytes] FIELDDATA, n = FIELDSIZE

Notes:
- Strings are stored in UTF-8 encoded form and are null-terminated.
- FIELDTYPE can be one of the following identifiers:
  * 0000: Invalid or comment block, block is ignored
  * 0001: Group ID, FIELDSIZE must be 4 bytes
          It can be any 32-bit value except 0 and 0xFFFFFFFF
  * 0002: Group name, FIELDDATA is an UTF-8 encoded string
  * 0003: Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0004: Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0005: Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0006: Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0007: Image ID, FIELDSIZE must be 4 bytes
  * 0008: Level, FIELDSIZE = 2
  * 0009: Flags, 32-bit value, FIELDSIZE = 4
  * FFFF: Group entry terminator, FIELDSIZE must be 0
  '''

    format = {
        0x0: ('Ignored',null_de()),
        0x1: ('GroupID',int_de()),
        0x2: ('GroupName',string_de()),
        0x3: ('CreationTime',date_de()),
        0x4: ('LastModTime',date_de()),
        0x5: ('LastAccTime',date_de()),
        0x6: ('ExpireTime',date_de()),
        0x7: ('ImageID',int_de()),
        0x8: ('Level',short_de()),
        0x9: ('Flags',int_de()),
        0xFFFF: (None,None),
        }

    def __init__(self,string):
        super(GroupInfo,self).__init__(GroupInfo.format,string)
        return
    pass

class EntryInfo(InfoBase):
    '''One entry: [FIELDTYPE(FT)][FIELDSIZE(FS)][FIELDDATA(FD)]
           [FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)]...

[ 2 bytes] FIELDTYPE
[ 4 bytes] FIELDSIZE, size of FIELDDATA in bytes
[ n bytes] FIELDDATA, n = FIELDSIZE

Notes:
- Strings are stored in UTF-8 encoded form and are null-terminated.
- FIELDTYPE can be one of the following identifiers:
  * 0000: Invalid or comment block, block is ignored
  * 0001: UUID, uniquely identifying an entry, FIELDSIZE must be 16
  * 0002: Group ID, identifying the group of the entry, FIELDSIZE = 4
          It can be any 32-bit value except 0 and 0xFFFFFFFF
  * 0003: Image ID, identifying the image/icon of the entry, FIELDSIZE = 4
  * 0004: Title of the entry, FIELDDATA is an UTF-8 encoded string
  * 0005: URL string, FIELDDATA is an UTF-8 encoded string
  * 0006: UserName string, FIELDDATA is an UTF-8 encoded string
  * 0007: Password string, FIELDDATA is an UTF-8 encoded string
  * 0008: Notes string, FIELDDATA is an UTF-8 encoded string
  * 0009: Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000A: Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000B: Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000C: Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000D: Binary description UTF-8 encoded string
  * 000E: Binary data
  * FFFF: Entry terminator, FIELDSIZE must be 0
  '''

    format = {
        0x0: ('Ignored',null_de()),
        0x1: ('UUID',ascii_de()),
        0x2: ('GroupID',int_de()),
        0x3: ('ImageID',int_de()),
        0x4: ('Title',string_de()),
        0x5: ('URL',string_de()),
        0x6: ('Username',string_de()),
        0x7: ('Password',string_de()),
        0x8: ('Notes',string_de()),
        0x9: ('CreationTime',date_de()),
        0xA: ('LastModTime',date_de()),
        0xB: ('LastAccTime',date_de()),
        0xC: ('ExpirationTime',date_de()),
        0xD: ('BinaryDesc',string_de()),
        0xE: ('BinaryData',shunt_de()),
        0xFFFF: (None,None),
        }

    def __init__(self,string):
        super(EntryInfo,self).__init__(EntryInfo.format,string)
        return

    pass


class Database(object):
    '''
    Access a KeePass DB file of format v3
    '''
    
    def __init__(self, masterkey, filename = None):
        self.masterkey = masterkey
        if filename:
            self.read(filename)
            return
        self.header = DBHDR()
        self.groups = []
        self.entries = []
        return

    def read(self,filename):
        fp = open(filename)
        buf = fp.read()
        fp.close()

        headbuf = buf[:124]
        self.header = DBHDR(headbuf)
        self.groups = []
        self.entries = []

        payload = buf[124:]

        self.finalkey = self.final_key(self.masterkey)
        payload = self.decrypt_payload(payload, self.finalkey)

        ngroups = self.header.dwGroups
        while ngroups:
            gi = GroupInfo(payload)
            self.groups.append(gi)
            length = len(gi)
            print 'GroupInfo of length',length,'payload=',len(payload)
            payload = payload[length:]
            ngroups -= 1
            continue

        nentries = self.header.dwEntries
        while nentries:
            ei = EntryInfo(payload)
            self.entries.append(ei)
            payload = payload[len(ei):]
            nentries -= 1
            continue
        return

    def final_key(self,masterkey):
        'Munge masterkey into the final key for decryping payload.'
        from Crypto.Cipher import AES
        import hashlib

        key = hashlib.sha256(masterkey).digest()
        cipher = AES.new(self.header.aMasterSeed2,  AES.MODE_ECB)
        
        enc_rounds = self.header.dwKeyEncRounds
        while enc_rounds:
            enc_rounds -= 1
            key = cipher.encrypt(key)
            continue
        key = hashlib.sha256(key).digest()
        return hashlib.sha256(self.header.aMasterSeed + key).digest()

    def decrypt_payload(self, payload, finalkey):
        'Decrypt payload (non-header) part of the buffer'

        enctype = self.header.encryption_type()
        if enctype != 'Rijndael':
            raise ValueError, 'Unsupported encryption type: "%s"'%enctype

        payload = self.decrypt_payload_aes_cbc(payload, finalkey)
        crypto_size = len(payload)

        if ((crypto_size > 2147483446) or (not crypto_size and self.header.dwGroups)):
            raise ValueError, "Decryption failed.\nThe key is wrong or the file is damaged"

        import hashlib
        if self.header.aContentsHash != hashlib.sha256(payload).digest():
            raise ValueError, "Decryption failed. The file checksum did not match."

        return payload

    def decrypt_payload_aes_cbc(self, payload, finalkey):
        'Decrypt payload buffer with AES CBC'

        from Crypto.Cipher import AES
        cipher = AES.new(finalkey, AES.MODE_CBC, self.header.aEncryptionIV)
        payload = cipher.decrypt(payload)
        extra = ord(payload[-1])
        payload = payload[:len(payload)-extra]
        return payload

    def encrypt_payload(self,payload,finalkey):
        unimplemented
        return

    def __str__(self):
        ret = [str(self.header)]
        ret += map(str,self.groups)
        ret += map(str,self.entries)
        return '\n'.join(ret)


    def write(self,filename):
        payload = self.encode_gi_and_ei()
        payload = self.encrypt_payload(payload)
        fp = open(filename,w)
        fp.write(self.header.encode())
        fp.write(payload)
        fp.close()

    pass

