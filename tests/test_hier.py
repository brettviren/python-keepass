# -*- coding: utf-8 -*-
import unittest
from keepasslib import hier

class TestHierarchy(unittest.TestCase):

    def test_hierarchy(self):
        top = hier.Node()
        dumper = hier.NodeDumper()
        hier.walk(top, dumper)
