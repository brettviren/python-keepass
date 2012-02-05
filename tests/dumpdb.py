#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from keepasslib import kpdb

filename = sys.argv[1]
masterkey  = sys.argv[2]
db = kpdb.Database(filename,masterkey)
print db
