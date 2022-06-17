#!/usr/bin/env python3

import sys
import signal
import socket
from icmp6filter import icmp6setfilter, ICMP6_ND_ROUTER_ADVERT
import scapy.all as sp
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default=sp.conf.iface.name)
parser.add_argument('-t', '--target', default='ff02::1')
parser.add_argument('-l', '--listen', action='store_true')
parser.add_argument('router')
args = parser.parse_args()

interface = args.interface
listen = args.listen
target = args.target
router = args.router
buf = sp.raw(sp.ICMPv6ND_NA(tgt=router, R=0))

sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
icmp6setfilter(sock, ICMP6_ND_ROUTER_ADVERT)

def send_na():
    sock.sendto(buf, (target, 0))

send_na()

if listen:
    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    while True:
        _ = sock.recv(4096)
        send_na()
