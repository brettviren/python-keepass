#!/usr/bin/env python2

import kpdb
import six

test = kpdb.Database()
six.print_((test))
test.write("test.kdb", "123")

test = kpdb.Database("test.kdb", "123")

six.print_((test))

test.add_entry("Internet","test","test","test","test","test")

test.add_entry("Internet","test1","test1","test1","test1","test1")

test.remove_entry("test1","test1")

six.print_((test))

test.write("test.kdb", "123")