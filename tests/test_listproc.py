#!/usr/bin/env python


def proc(ll):
    l2 = list(ll)
    for x in l2:
        print ll.pop(0)

l = [1,2,3,4,5,6]
proc(l)
print l
