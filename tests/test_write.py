#!/usr/bin/env python
import sys,os
try:
    from keepass import kpdb
except ImportError:
    path = os.path.dirname(os.path.dirname(__file__))
    path = os.path.join('python')
    sys.path.append(path)
    from keepass import kpdb

filename = sys.argv[1]
masterkey  = sys.argv[2]
db = kpdb.Database(filename,masterkey)

db.header.dwGroups = 0
db.header.dwEntries = 0
buf = db.header.encode()

filename2 = os.path.splitext(filename)
filename2 = filename2[0] + '2' + filename2[1]
print 'Writing:',filename2
fp = open(filename2,"w")
fp.write(buf)
fp.close()
db2 = kpdb.Database(filename2,masterkey)
print db2
