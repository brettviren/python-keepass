#!/usr/bin/env python
'''
KeePass v1 database file from Docs/DbFormat.txt of KeePass v1.

General structure:

[DBHDR][GROUPINFO][GROUPINFO][GROUPINFO]...[ENTRYINFO][ENTRYINFO][ENTRYINFO]...

[1x] Database header
[Nx] All groups
[Mx] All entries
'''

# This file is part of python-keepass and is Copyright (C) 2012 Brett Viren.
# 
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.

import sys, struct, os
import datetime
import uuid
import random
from copy import copy

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
        'Read in given .kdb file'
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
        '''Munge masterkey into the final key for decrypting payload by
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
        Resets IVs and master seeds.
        '''
        import hashlib

        header = copy(self.header)
        header.ngroups = len(self.groups)
        header.nentries = len(self.entries)
        header.reset_random_fields()

        payload = self.encode_payload()
        header.contents_hash = hashlib.sha256(payload).digest()

        finalkey = self.final_key(masterkey = masterkey or self.masterkey,
                                  masterseed = header.master_seed,
                                  masterseed2 = header.master_seed2,
                                  rounds = header.key_enc_rounds)

        payload = self.encrypt_payload(payload, finalkey, 
                                       header.encryption_type(),
                                       header.encryption_iv)

        fp = open(filename,'w')
        fp.write(header.encode())
        fp.write(payload)
        fp.close()
        return

    def group(self,field,value):
        'Return the group which has the given field and value'
        for group in self.groups:
            if group.__dict__[field] == value: return group
            continue
        return None

    def dump_entries(self,format,show_passwords=False):
        for ent in self.entries:
            group = self.group('groupid',ent.groupid)
            if not group:
                sys.stderr.write("Skipping missing group with ID %d\n"%
                                 ent.groupid)
                continue
            dat = dict(ent.__dict__) # copy
            if not show_passwords:
                dat['password'] = '****'
            for what in ['group_name','level']:
                nick = what
                if 'group' not in nick: nick = 'group_'+nick
                dat[nick] = group.__dict__[what]

            print format%dat
            continue
        return

    def hierarchy(self):
        '''Return database with groups and entries organized into a
        hierarchy'''
        from hier import Node

        top = Node()
        breadcrumb = [top]
        node_by_id = {None:top}
        for group in self.groups:
            n = Node(group)
            node_by_id[group.groupid] = n

            while group.level - breadcrumb[-1].level() != 1:
                pn = breadcrumb.pop()
                continue

            breadcrumb[-1].nodes.append(n)
            breadcrumb.append(n)
            continue

        for ent in self.entries:
            n = node_by_id[ent.groupid]
            n.entries.append(ent)

        return top
    
    def update_by_hierarchy(self, hierarchy):
        '''
        Update the database using the given hierarchy.  
        This replaces the existing groups and entries.
        '''
        import hier
        collector = hier.CollectVisitor()
        hier.visit(hierarchy, collector)
        self.groups = collector.groups
        self.entries = collector.entries
        return
    
    def gen_groupid(self):
        """
        Generate a new groupid (4-byte value that isn't 0 or 0xffffffff).
        """
        existing_groupids = {group.groupid for group in self.groups}
        if len(existing_groupids) >= 0xfffffffe:
            raise Exception("All groupids are in use!")
        while True:
            groupid = random.randint(1, 0xfffffffe) # 0 and 0xffffffff are reserved
            if groupid not in existing_groupids:
                return groupid
    
    def update_entry(self,title,username,url,notes="",new_title=None,new_username=None,new_password=None,new_url=None,new_notes=None):
        for entry in self.entries:
            if entry.title == str(title) and entry.username == str(username) and entry.url == str(url):
                if new_title: entry.title = new_title
                if new_username: entry.username = new_username
                if new_password: entry.password = new_password
                if new_url: entry.url = new_url
                if new_notes: entry.notes = new_notes
                entry.new_entry.last_mod_time = datetime.datetime.now()

    def add_entry(self,path,title,username,password,url="",notes="",imageid=1,append=True):
        '''
        Add an entry to the current database at with given values.  If
        append is False a pre-existing entry that matches path, title
        and username will be overwritten with the new one.
        '''
        import hier, infoblock

        top = self.hierarchy()
        node = hier.mkdir(top, path, self.gen_groupid)

        # fixme, this should probably be moved into a new constructor
        def make_entry():
            new_entry = infoblock.EntryInfo()
            new_entry.uuid = uuid.uuid4().hex
            new_entry.groupid = node.group.groupid
            new_entry.imageid = imageid
            new_entry.title = title
            new_entry.url = url
            new_entry.username = username
            new_entry.password = password
            new_entry.notes = notes
            new_entry.creation_time = datetime.datetime.now() 
            new_entry.last_mod_time = datetime.datetime.now() 
            new_entry.last_acc_time = datetime.datetime.now() 
            new_entry.expiration_time = datetime.datetime(2999, 12, 28, 23, 59, 59) # KeePassX 0.4.3 default
            new_entry.binary_desc = ""
            new_entry.binary_data = None
            new_entry.order = [(1, 16), 
			       (2, 4), 
			       (3, 4), 
			       (4, len(title) + 1), 
			       (5, len(url) + 1), 
			       (6, len(username) + 1), 
			       (7, len(password) + 1), 
			       (8, len(notes) + 1), 
			       (9, 5), 
			       (10, 5), 
			       (11, 5), 
			       (12, 5), 
			       (13, len(new_entry.binary_desc) + 1), 
			       (14, 0), 
			       (65535, 0)]
            #new_entry.None = None
            #fixme, deal with times
            return new_entry
        
        existing_node_updated = False
        if not append:
            for i, ent in enumerate(node.entries):
                if ent.title != title: continue
                if ent.username != username: continue
                node.entries[i] = make_entry()
                existing_node_updated = True
                break
        
        if not existing_node_updated:
            node.entries.append(make_entry())
        
        self.update_by_hierarchy(top)

    def remove_entry(self, username, url):
        for entry in self.entries:
            if entry.username == str(username) and entry.url == str(url):
                self.entries.remove(entry)

    def remove_group(self, path, level=None):
        for group in self.groups:
            if group.group_name == str(path):
                if level:
                    if group.level == level:
                        self.groups.remove(group)
                        for entry in self.entries:
                            if entry.groupid == group.groupid:
                                self.entries.remove(entry)
                else:
                    self.groups.remove(group)
                    for entry in self.entries:
                        if entry.groupid == group.groupid:
                            self.entries.remove(entry)


    pass

