#!/usr/bin/env python


import sys

from keepass import cli

cliobj = cli.Cli(sys.argv[1:])
cliobj()


