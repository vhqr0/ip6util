#!/usr/bin/env python3

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

p = sp.Ether(src=mac) / \
    sp.IPv6(src=item, dst=target) / \
    sp.ICMPv6ND_NA(tgt=item, R=flagr) / \
    sp.ICMPv6NDOptDstLLAddr(lladdr=mac)
sp.sendp(p, iface=interface)
