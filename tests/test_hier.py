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
h = db.hierarchy()
print h

path = sys.argv[3]
# obj = h.get(path)
# print path,' --> ',obj

from keepass import hier
visitor = hier.PathVisitor(path,False)
obj = h.walk(visitor)
print 'results for',path
for res in visitor.results():
    print res
print 'best match:',visitor.best_match
print 'remaining path:',visitor.path

visitor= hier.CollectVisitor()
h.walk(visitor)
print 'Groups:'
for g in visitor.groups:
    print '\t',g.name(),g.groupid
print 'Entries:'
for e in visitor.entries:
    print '\t',e.name(),e.groupid
