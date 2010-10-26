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

def nullify(buf):
    return None

def shunt(buf):
    return buf

def asciiify(buf):
    from binascii import b2a_hex
    return b2a_hex(buf).replace('\0','')

def stringify(buf):
    return buf.replace('\0','')

def shortify(buf):
    return struct.unpack("<H", buf)[0]

def intify(buf):
    return struct.unpack("<I", buf)[0]

def dateify(buf):
    from datetime import datetime
    b = struct.unpack('<5B', buf)
    year = (b[0] << 6) | (b[1] >> 2);
    mon  = ((b[1] & 0b11)     << 2) | (b[2] >> 6);
    day  = ((b[2] & 0b111111) >> 1);
    hour = ((b[2] & 0b1)      << 4) | (b[3] >> 4);
    min  = ((b[3] & 0b1111)   << 2) | (b[4] >> 6);
    sec  = ((b[4] & 0b111111));
    #print 'dateify:',b,buf,year, mon, day, hour, min, sec
    return datetime(year, mon, day, hour, min, sec)

    

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

    encryption_flags = (
        ('SHA2',1),
        ('Rijndael',2),
        ('AES',2),
        ('ArcFour',4),
        ('TwoFish',8),
        )

    def __init__(self,kpdb):
        'Read self from the kpdb file object'
        for field in DBHDR.format:
            name,bytes,typecode = field
            value = kpdb.read(bytes, typecode)
            if len(value) == 1: value = value[0]
            self.__dict__[name] = value
            continue

        if DBHDR.signatures[0] != self.dwSignature1 or \
                DBHDR.signatures[1] != self.dwSignature2:
            msg = 'Bad sigs:\n%s %s\n%s %s'%\
                (DBHDR.signatures[0],DBHDR.signatures[1],
                 self.dwSignature1,self.dwSignature2)
            raise IOError,msg

        return

    def __len__(self):
        length = 0
        for field in format:
            length += field[1] * self.fieldlength(field)
        return length

    def __str__(self):
        ret = ['Header:']
        for field in DBHDR.format:
            name = field[0]
            size = field[1]
            typ = field[2]
            ret.append('%s:(%s) [%d] = %s'%(field,typ,size,self.__dict__[name]))
            continue
        return '\n'.join(ret)

    def encryption_type(self):
        for encflag in DBHDR.encryption_flags[1:]:
            if encflag[1] & self.dwFlags: return encflag[0]
        return 'Unknown'
    pass

class InfoBase(object):
    'Base class for info type blocks'
    def __init__(self,kpdb,format):
        self.format = format
        while True:
            typ = kpdb.read(2,'H')[0]
            siz = kpdb.read(4,'I')[0]
            buf = kpdb.read(siz,'%ds'%siz)[0]
            name,func = self.format[typ]
            if name is None: break
            try:
                value = func(buf)
            except struct.error,msg:
                msg = '%s, typ = %d[%d] -> %s buf = "%s"'%(msg,typ,siz,self.format[typ],buf)
                raise struct.error,msg

            print '%s: type = %d[%d] -> %s buf = "%s" value = %s'%\
                (name,typ,siz,self.format[typ],buf,str(value))
            self.__dict__[name] = value
            continue
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
        0x0: ('Ignored',nullify),
        0x1: ('GroupID',intify),
        0x2: ('GroupName',stringify),
        0x3: ('CreationTime',dateify),
        0x4: ('LastModTime',dateify),
        0x5: ('LastAccTime',dateify),
        0x6: ('ExpireTime',dateify),
        0x7: ('ImageID',intify),
        0x8: ('Level',shortify),
        0x9: ('Flags',intify),
        0xFFFF: (None,None),
        }

    def __init__(self,kpdb):
        super(GroupInfo,self).__init__(kpdb,GroupInfo.format)
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
        0x0: ('Ignored',nullify),
        0x1: ('UUID',asciiify),
        0x2: ('GroupID',intify),
        0x3: ('ImageID',intify),
        0x4: ('Title',stringify),
        0x5: ('URL',stringify),
        0x6: ('Username',stringify),
        0x7: ('Password',stringify),
        0x8: ('Notes',stringify),
        0x9: ('CreationTime',dateify),
        0xA: ('LastModTime',dateify),
        0xB: ('LastAccTime',dateify),
        0xC: ('ExpirationTime',dateify),
        0xD: ('BinaryDesc',stringify),
        0xE: ('BinaryData',shunt),
        0xFFFF: (None,None),
        }

    def __init__(self,kpdb):
        super(EntryInfo,self).__init__(kpdb,EntryInfo.format)
        return

    pass

class Kpdb3file(object):

    def __init__(self,filename,rw='r'):
        fp = open(filename,rw)
        self._buffer = fp.read()
        self.index = 0
        return

    def payload(self,offset=124):
        if self.index != offset:
            raise 'Unexpected offset %d != %d'%(self.index,offset)
        return self._buffer[offset:]

    def set_payload(self,payload,offset=124):
        if self.index != offset:
            raise 'Unexpected offset %d != %d'%(self.index,offset)
        self._buffer = self._buffer[:offset] + payload

    def read(self,nbytes,typecode):
        'Read next nbytes and return a type given by typecode'
        import struct
        typecode = '<'+typecode
        string = self._buffer[self.index:self.index+nbytes]
        self.index += nbytes
        try:
            value = struct.unpack(typecode,string)
        except struct.error,err:
            print err
            print 'typecode="%s", nbytes=%d, calcsize=%d, string="%s"'%\
                (typecode,nbytes,struct.calcsize(typecode),string)
            raise
        return value

    def read32(self):
        'Read the next 32 bits and return as a 32 bit unsigned int'
        return self.read(4,"I")

    def read16(self):
        'Read the next 32 bits and return as a 32 bit unsigned int'
        return self.read(2,"H")

    pass

class Database(object):
    '''
    Access a KeePass DB file of format v3
    '''
    
    def __init__(self, filename, masterkey, rw='r'):
        self.dbfile = Kpdb3file(filename, rw)

        print 'reading header'
        self.header = DBHDR(self.dbfile)
        print "%s"%self.header

        finalkey = self.final_key(masterkey)
        payload = self.dbfile.payload()
        payload = self.decrypt_payload(payload, finalkey)
        self.dbfile.set_payload(payload)

        self.groups = []
        ngroups = self.header.dwGroups
        print 'reading %d groups'%ngroups
        while ngroups:
            self.groups.append(GroupInfo(self.dbfile))
            ngroups -= 1
            continue

        self.entries = []
        nentries = self.header.dwEntries
        print 'reading %d entries'%nentries
        while nentries:
            self.entries.append(EntryInfo(self.dbfile))
            nentries -= 1
            continue
        return

    def final_key(self, masterkey):
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

    def __str__(self):
        ret = [str(self.header)]
        ret += map(str,self.groups)
        ret += map(str,self.entries)
        return '\n'.join(ret)

    pass

