#!/usr/bin/env python


import sys
sys.path.append("./python")

from keepass import cli

cliobj = cli.Cli(sys.argv[1:])
cliobj()


