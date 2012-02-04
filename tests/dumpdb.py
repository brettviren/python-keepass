#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
print db
