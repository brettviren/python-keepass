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

from header import DBHDR
from infoblock import GroupInfo, EntryInfo


class Database(object):
    '''
    Access a KeePass DB file of format v3
    '''
    
    def __init__(self, filename = None, masterkey=""):
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

        self.finalkey = self.final_key(self.masterkey,
                                       self.header.master_seed,
                                       self.header.master_seed2,
                                       self.header.key_enc_rounds)
        payload = self.decrypt_payload(payload, self.finalkey, 
                                       self.header.encryption_type(),
                                       self.header.encryption_iv)

        ngroups = self.header.ngroups
        while ngroups:
            gi = GroupInfo(payload)
            self.groups.append(gi)
            length = len(gi)
            #print 'GroupInfo of length',length,'payload=',len(payload)
            payload = payload[length:]
            ngroups -= 1
            continue

        nentries = self.header.nentries
        while nentries:
            ei = EntryInfo(payload)
            self.entries.append(ei)
            payload = payload[len(ei):]
            nentries -= 1
            continue
        return

    def final_key(self,masterkey,masterseed,masterseed2,rounds):
        '''Munge masterkey into the final key for decryping payload by
        encrypting it for the given number of rounds masterseed2 and
        hashing it with masterseed.'''
        from Crypto.Cipher import AES
        import hashlib

        key = hashlib.sha256(masterkey).digest()
        cipher = AES.new(masterseed2,  AES.MODE_ECB)
        
        while rounds:
            rounds -= 1
            key = cipher.encrypt(key)
            continue
        key = hashlib.sha256(key).digest()
        return hashlib.sha256(masterseed + key).digest()

    def decrypt_payload(self, payload, finalkey, enctype, iv):
        'Decrypt payload (non-header) part of the buffer'

        if enctype != 'Rijndael':
            raise ValueError, 'Unsupported decryption type: "%s"'%enctype

        payload = self.decrypt_payload_aes_cbc(payload, finalkey, iv)
        crypto_size = len(payload)

        if ((crypto_size > 2147483446) or (not crypto_size and self.header.ngroups)):
            raise ValueError, "Decryption failed.\nThe key is wrong or the file is damaged"

        import hashlib
        if self.header.contents_hash != hashlib.sha256(payload).digest():
            raise ValueError, "Decryption failed. The file checksum did not match."

        return payload

    def decrypt_payload_aes_cbc(self, payload, finalkey, iv):
        'Decrypt payload buffer with AES CBC'

        from Crypto.Cipher import AES
        cipher = AES.new(finalkey, AES.MODE_CBC, iv)
        payload = cipher.decrypt(payload)
        extra = ord(payload[-1])
        payload = payload[:len(payload)-extra]
        #print 'Unpadding payload by',extra
        return payload

    def encrypt_payload(self, payload, finalkey, enctype, iv):
        'Encrypt payload'
        if enctype != 'Rijndael':
            raise ValueError, 'Unsupported encryption type: "%s"'%enctype
        return self.encrypt_payload_aes_cbc(payload, finalkey, iv)

    def encrypt_payload_aes_cbc(self, payload, finalkey, iv):
        'Encrypt payload buffer with AES CBC'
        from Crypto.Cipher import AES
        cipher = AES.new(finalkey, AES.MODE_CBC, iv)
        # pad out and store amount as last value
        length = len(payload)
        encsize = (length/AES.block_size+1)*16
        padding = encsize - length
        #print 'Padding payload by',padding
        for ind in range(padding):
            payload += chr(padding)
        return cipher.encrypt(payload)
        
    def __str__(self):
        ret = [str(self.header)]
        ret += map(str,self.groups)
        ret += map(str,self.entries)
        return '\n'.join(ret)

    def encode_payload(self):
        'Return encoded, plaintext groups+entries buffer'
        payload = ""
        for group in self.groups:
            payload += group.encode()
        for entry in self.entries:
            payload += entry.encode()
        return payload

    def write(self,filename,masterkey=""):
        '''' 
        Write out DB to given filename with optional master key.
        If no master key is given, the one used to create this DB is used.
        '''
        import hashlib

        header = DBHDR(self.header.encode())

        # fixme: should regenerate encryption_iv, master_seed,
        # master_seed2 and allow for the number of rounds to change

        payload = self.encode_payload()
        header.contents_hash = hashlib.sha256(payload).digest()

        finalkey = self.final_key(masterkey = masterkey or self.masterkey,
                                  masterseed = self.header.master_seed,
                                  masterseed2 = self.header.master_seed2,
                                  rounds = self.header.key_enc_rounds)

        payload = self.encrypt_payload(payload, finalkey, 
                                       header.encryption_type(),
                                       header.encryption_iv)

        fp = open(filename,'w')
        fp.write(header.encode())
        fp.write(payload)
        fp.close()
        return

    def group(self,field,value):
        for group in self.groups:
            if group.__dict__[field] == value: return group
            continue
        return None

    def dump_entries(self,format,show_passwords=False):
        for ent in self.entries:
            group = self.group('groupid',ent.groupid)
            dat = dict(ent.__dict__)
            if not show_passwords:
                dat['password'] = '****'
            for what in ['group_name','level']:
                nick = what
                if 'group' not in nick: nick = 'group_'+nick
                dat[nick] = group.__dict__[what]

            print format%dat
            continue
        return

    pass

