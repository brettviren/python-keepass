#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys,os
from keepasslib import kpdb

filename = sys.argv[1]
masterkey  = sys.argv[2]
db = kpdb.Database(masterkey,filename)

db.header.dwGroups = 0
db.header.dwEntries = 0
buf = db.header.encode()

filename2 = os.path.splitext(filename)
filename2 = filename2[0] + '2' + filename2[1]
print 'Writing:',filename2
fp = open(filename2,"w")
fp.write(buf)
fp.close()
db2 = kpdb.Database(masterkey,filename2)
print db2
