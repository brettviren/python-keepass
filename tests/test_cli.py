# -*- coding: utf-8 -*-

import os,sys
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)),'python'))

from keepass import cli

def test_parse_args():
    main = cli.Cli(['-a', '-b', '-c', 'open', '-a', '-b', '-c', 'foo'])
    assert main.opts == [('', ['-a', '-b', '-c']), 
                         ('open', ['-a', '-b', '-c', 'foo'])]
    return

if '__main__' == __name__:
    test_parse_args()
