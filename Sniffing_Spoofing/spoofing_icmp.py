#!/usr/bin/env python3

from scapy.all import *

a = IP()
a.src = '10.9.0.1'
a.dst = '10.9.0.5'
p = a/ICMP()
send(p)
ls(a)
