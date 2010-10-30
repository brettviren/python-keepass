#!/usr/bin/env python

import sys
print sys.argv
sys.argv[1] = 'hidden'          # this doesn't work
import time
time.sleep(60)
