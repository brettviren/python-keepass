# -*- coding: utf-8 -*-
'''
KeePass v1 database file from Docs/DbFormat.txt of KeePass v1.

General structure:

[DBHDR][GROUPINFO][GROUPINFO][GROUPINFO]...[ENTRYINFO][ENTRYINFO][ENTRYINFO]...

[1x] Database header
[Nx] All groups
[Mx] All entries

'''

import hashlib

from .header import DBHDR
from .infoblock import GroupInfo, EntryInfo


class Database(object):
    '''
    Access a KeePass DB file of format v3
    '''
    
    def __init__(self, filename=None, masterkey=""):
        self.masterkey = masterkey
        self.groups = []
        self.entries = []
        if filename:
            self.read(filename)
        else:
            self.header = DBHDR()

    def read(self,filename):
        'Read in given .kdb file'
        fp = open(filename, 'rb')
        try:
            buf = fp.read()
        finally:
            fp.close()

        headbuf = buf[:124]
        self.header = DBHDR(headbuf)

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
            if gi.level > 0:
                for group in reversed(self.groups):
                    if group.level < gi.level:
                        gi.parent = group
                        break
            self.groups.append(gi)
            length = len(gi)
            #print 'GroupInfo of length',length,'payload=',len(payload)
            payload = payload[length:]
            ngroups -= 1

        nentries = self.header.nentries
        while nentries:
            ei = EntryInfo(payload)
            for group in self.groups:
                if group.groupid == ei.groupid:
                    ei.parent = group
                    break
            self.entries.append(ei)
            payload = payload[len(ei):]
            nentries -= 1

    def final_key(self,masterkey,masterseed,masterseed2,rounds):
        '''Munge masterkey into the final key for decryping payload by
        encrypting it for the given number of rounds masterseed2 and
        hashing it with masterseed.'''
        from Crypto.Cipher import AES

        key = hashlib.sha256(masterkey).digest()
        cipher = AES.new(masterseed2,  AES.MODE_ECB)

        while rounds:
            rounds -= 1
            key = cipher.encrypt(key)
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
        self.header.ngroups = len(self.groups)
        self.header.nentries = len(self.entries)

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
        try:
            fp.write(header.encode())
            fp.write(payload)
        finally:
            fp.close()

    def group(self,field,value):
        'Return the group which has the given field and value'
        for group in self.groups:
            if group.__dict__[field] == value: return group

    def hierarchy(self):
        '''Return database with groups and entries organized into a
        hierarchy'''
        from .hier import Node

        top = Node()
        breadcrumb = [top]
        node_by_id = {None:top}
        for group in self.groups:
            n = Node(group)
            node_by_id[group.groupid] = n

            while group.level - breadcrumb[-1].level() != 1:
                breadcrumb.pop()

            breadcrumb[-1].nodes.append(n)
            breadcrumb.append(n)

        for ent in self.entries:
            n = node_by_id[ent.groupid]
            n.entries.append(ent)

        return top

    def search(self, key, search_passwords=False):
        """Get all groups and entries containing the given key.
        Search group names and title, url and username of entries.
        Also searches entry passwords if search_password is True.
        The search is performed case insensitive.

        @return: iterator of groups and entries
        @rtype: iterator(GroupInfo|EntryInfo)
        """
        key = key.lower()
        for entry in self.entries:
            if key in entry.title.lower():
                yield entry
            elif key in entry.url.lower():
                yield entry
            elif key in entry.username.lower():
                yield entry
            elif key in entry.path().lower():
                yield entry
            elif search_passwords and key in entry.password.lower():
                yield entry
