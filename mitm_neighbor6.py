#!/usr/bin/env python3

import socket
import scapy.all as sp
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default=sp.conf.iface.name)
parser.add_argument('-R', '--flagr', type=int, default=0)
parser.add_argument('target')
parser.add_argument('item')
args = parser.parse_args()

interface = args.interface
mac = sp.get_if_hwaddr(interface)
flagr = args.flagr
target = args.target
item = args.item

sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)

p = sp.Ether(src=mac) / \
    sp.IPv6(src=item, dst=target) / \
    sp.ICMPv6ND_NA(tgt=item, R=flagr) / \
    sp.ICMPv6NDOptDstLLAddr(lladdr=mac)
sp.sendp(p, iface=interface)
