#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
    pkt.show()


iface = ['br-db2becb280a0', 'enp0s3']
pkt = sniff(iface=iface,filter='dst net 10.9.0.0/24',prn=print_pkt)
