#!/usr/bin/env python

# This file is part of python-keepass and is Copyright (C) 2012 Brett Viren.
# 
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.

from keepass import cli

cliobj = cli.Cli(sys.argv[1:])
cliobj()
