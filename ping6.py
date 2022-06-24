#!/usr/bin/env python3

import sys
import os
import math
import time
import signal
import socket
from icmp6filter import *
import scapy.all as sp
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface')
parser.add_argument('-e', '--echoping')
parser.add_argument('-a', '--arping')
parser.add_argument('-r', '--rsping', action='store_true')
parser.add_argument('-l', '--length', type=int, default=64)
args = parser.parse_args()

interface = args.interface
echoping = args.echoping
arping = args.arping
rsping = args.rsping
length = max(args.length - 8, 0)
pid = os.getpid() & 0xffff
seq = 0

sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
if interface:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                    interface.encode())
icmp6f = ICMP6Filter()
icmp6f.setblockall()


def gettimeofday():
    t = time.time()
    sec = math.floor(t)
    t -= sec
    t *= 10**6
    usec = math.floor(t)
    return sec & 0xffffffff, usec & 0xffffffff


def do_echoping():
    icmp6f.setpass(ICMP6_ECHOREP)
    icmp6f.setsockopt(sock)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
    ep = socket.getaddrinfo(echoping,
                            None,
                            family=socket.AF_INET6,
                            type=socket.SOCK_RAW)[0][-1]

    def send_echoreq():
        global seq
        sec, usec = gettimeofday()
        buf = struct.pack('!BBHHHII', ICMP6_ECHOREQ, 0, 0, pid, seq, sec, usec)
        seq += 1
        if length > 0:
            buf += b'\xa5' * length
        sock.sendto(buf, ep)
        signal.alarm(1)

    signal.signal(signal.SIGALRM, lambda _no, _f: send_echoreq())
    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    signal.alarm(1)
    while True:
        buf, cmsgs, flags, rep = sock.recvmsg(4096, 4096)
        rpid, rseq, rsec, rusec = struct.unpack_from('!HHII',
                                                     buffer=buf,
                                                     offset=4)
        if rpid != pid or len(buf) != 16 + length:
            continue
        hlim = '???'
        for cmsg in cmsgs:
            if cmsg[0] == socket.IPPROTO_IPV6 and \
               cmsg[1] == socket.IPV6_HOPLIMIT:
                hlim = int.from_bytes(cmsg[2], sys.byteorder)
                break
        sec, usec = gettimeofday()
        sec -= rsec
        usec -= rusec
        rtt = sec * 1000 + usec / 1000
        print(f'recvfrom {rep[0]}, {8 + length} bytes, '
              f'seq: {rseq}, rtt: {rtt}ms, hlim: {hlim}')


def do_arping():
    icmp6f.setpass(ICMP6ND_NA)
    icmp6f.setsockopt(sock)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    tgt = socket.inet_pton(socket.AF_INET6, arping)
    _ep = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff' + tgt[-3:]
    ep = (socket.inet_ntop(socket.AF_INET6, _ep), 0)
    b = struct.pack('!BBHI16s', ICMP6ND_NS, 0, 0, 0, tgt)

    def send_ns():
        sock.sendto(b, ep)
        signal.alarm(1)

    signal.signal(signal.SIGALRM, lambda _no, _f: send_ns())
    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    signal.alarm(1)
    while True:
        buf, rep = sock.recvfrom(4096)
        p = sp.ICMPv6ND_NA(buf)
        print(f'recvfrom {rep[0]}, r: {p.R}, s: {p.S}, o: {p.O}')
        if sp.ICMPv6NDOptDstLLAddr in p:
            print(f'    lladdr: {p[sp.ICMPv6NDOptDstLLAddr].lladdr}')


def do_rsping():
    icmp6f.setpass(ICMP6ND_RA)
    icmp6f.setsockopt(sock)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    b = struct.pack('!BBHI', ICMP6ND_RS, 0, 0, 0)

    def send_rs():
        sock.sendto(b, ('ff02::2', 0))
        signal.alarm(1)

    signal.signal(signal.SIGALRM, lambda _no, _f: send_rs())
    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    signal.alarm(1)
    while True:
        buf, rep = sock.recvfrom(4096)
        p = sp.ICMPv6ND_RA(buf)
        print(f'recvfrom {rep[0]}, m: {p.M}, o: {p.O}')
        if sp.ICMPv6NDOptSrcLLAddr in p:
            print(f'    lladdr: {p[sp.ICMPv6NDOptSrcLLAddr].lladdr}')
        if sp.ICMPv6NDOptPrefixInfo in p:
            pi = p[sp.ICMPv6NDOptPrefixInfo]
            print(f'    prefix: {pi.prefix}/{pi.prefixlen}, '
                  f'l: {pi.L}, a: {pi.A}')


if echoping:
    do_echoping()
elif arping:
    do_arping()
elif rsping:
    do_rsping()
