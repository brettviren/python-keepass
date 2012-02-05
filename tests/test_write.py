#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
from keepasslib import kpdb
from . import get_resource


class TestWrite(unittest.TestCase):

    def test_write(self):
        filename = get_resource("test.kdb")
        masterkey  = "test"
        db = kpdb.Database(filename, masterkey)
        db.header.dwGroups = 0
        db.header.dwEntries = 0
        buf = db.header.encode()
        filename2 = get_resource("test2.kdb")
        fp = open(filename2, "wb")
        try:
            fp.write(buf)
        finally:
            fp.close()
        print kpdb.Database(filename2, masterkey)
