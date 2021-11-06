#!/usr/bin/env python3

from scapy.all import *

counter = 1
timeout_ = 5
ttl = 3
#dst = "www.aliexpress.com"
dst = "www.google.com"

while True:

    a = IP()
    a.dst=dst
    #a.ttl = ttl
    p= a/ICMP()
    response = sr1(p,timeout=timeout_)

    if response is None:
        print("TTL={}: Time Out".format(counter))
    elif response.type == 0:
        print("TTL={}: {} => {}".format(counter,response.src, response.dst))
        break
    elif ttl == counter:
        break
    else:
        counter +=1
