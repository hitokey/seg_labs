#!/usr/bin/env python3

from scapy.all import *

a = IP()

a.dst = '10.9.0.5'
a.ttl = 3
b = ICMP()
send(a/b)
