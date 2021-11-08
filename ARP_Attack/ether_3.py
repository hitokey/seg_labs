from scapy.all import *

ETHER = Ether(dst='ff:ff:ff:ff:ff:ff',src='02:42:0a:09:00:69')

ARP_VAR = ARP(hwsrc='02:42:0a:09:00:69',psrc='10.9.0.6',hwdst='ff:ff:ff:ff:ff:ff',
              pdst='10.9.0.6')


pkt = ETHER/ARP_VAR

pkt.show()
sendp(pkt)
