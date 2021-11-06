#!/usr/bin/env python3


from scapy.all import *


def get_and_send(pkt):

    if pkt[ICMP].type == 8: #if sniffing type
        p = pkt[IP]

        print("Sniffing: src={} dst={}".format(p.src,p.dst))

        a = IP()
        a.src = p.dst
        a.dst = p.src

        r = ICMP()
        r.id = p.id
        r.seq = p.seq

        s = a/r
        send(s)

        print("Spoofing: src={} dst={}".format(a.src,a.dst))

iface = ['br-db2becb280a0', 'enp0s3','lo']
pkt = sniff(iface=iface,filter='icmp',prn=get_and_send)

        
        
        
