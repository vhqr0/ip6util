#!/usr/bin/env python3

# Assert: `net.ipv6.conf.$iface$.forwarding == 1`
# for listening ff02::2, and sending NA with R flag.

import sys
import signal
import socket
from icmp6filter import icmp6setfilter, ICMP6_ND_ROUTER_SOLICIT
import scapy.all as sp
import ipaddress
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default=sp.conf.iface.name)
parser.add_argument('-I', '--internal', type=int, default=30)
parser.add_argument('-p', '--prefix', type=ipaddress.IPv6Network)
parser.add_argument('-M', '--flagm', type=int, default=0)
parser.add_argument('-O', '--flago', type=int, default=0)
parser.add_argument('-A', '--flaga', type=int, default=1)
parser.add_argument('-L', '--flagl', type=int, default=1)
args = parser.parse_args()

interface = args.interface
internal = args.internal
prefix = args.prefix
flagm = args.flagm
flago = args.flago
flaga = args.flaga
flagl = args.flagl
p = sp.ICMPv6ND_RA(M=flagm, O=flago)
if prefix:
    p /= sp.ICMPv6NDOptPrefixInfo(A=flaga,
                                  L=flagl,
                                  prefix=str(prefix.network_address),
                                  prefixlen=prefix.prefixlen)
buf = sp.raw(p)

sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
icmp6setfilter(sock, ICMP6_ND_ROUTER_SOLICIT)


def send_ra(tgt):
    sock.sendto(buf, (tgt, 0))


def send_ra_internal():
    send_ra('ff02::1')
    signal.alarm(internal)


signal.signal(signal.SIGALRM, lambda _no, _f: send_ra_internal())
signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))

if internal > 0:
    send_ra_internal()

while True:
    _, ep = sock.recvfrom(4096)
    send_ra(ep[0])
