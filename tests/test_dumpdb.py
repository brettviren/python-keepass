# -*- coding: utf-8 -*-
import unittest
from keepasslib import kpdb
from . import get_resource

class TestDumpDb (unittest.TestCase):

    def test_dump(self):
        filename = get_resource("test.kdb")
        masterkey = 'test'
        print kpdb.Database(filename, masterkey)
