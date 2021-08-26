#!/usr/bin/python

import sys

def undotIPv4 (dotted):
    return sum (int (octet) << ( (3 - i) << 3) for i, octet in enumerate (dotted.split ('.') ) )

def dotIPv4 (addr):
    return '.'.join (str (addr >> off & 0xff) for off in (24, 16, 8, 0) )

def rangeIPv4 (start, stop):
    for addr in range (undotIPv4 (start), undotIPv4 (stop) ):
        yield dotIPv4 (addr)

for x in rangeIPv4 (sys.argv[1], sys.argv[2]):
    print(x)

print(sys.argv[2])

