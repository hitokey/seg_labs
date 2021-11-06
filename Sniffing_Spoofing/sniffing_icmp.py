#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
    print("Only ICMP")
    
    if pkt[ICMP] is not None:
        if pkt[ICMP].type == 8:
            pkt[ICMP].show()


iface = ['br-db2becb280a0', 'enp0s3']
pkt = sniff(iface=iface,filter='icmp',prn=print_pkt)


