import socket
import struct

ICMP6_ECHOREQ = 128
ICMP6_ECHOREP = 129
ICMP6ND_RS = 133
ICMP6ND_RA = 134
ICMP6ND_NS = 135
ICMP6ND_NA = 136

SO_ICMP6_FILTER = 1


class ICMP6Filter:

    def __init__(self):
        self.f = [0 for _ in range(8)]

    def setpassall(self):
        self.f = [0 for _ in range(8)]

    def setblockall(self):
        self.f = [0xffffffff for _ in range(8)]

    def setpass(self, icmp6type):
        self.f[icmp6type >> 5] &= 0xffffffff - (1 << (icmp6type & 0x1f))

    def setblock(self, icmp6type):
        self.f[icmp6type >> 5] |= 1 << (icmp6type & 0x1f)

    def willpass(self, icmp6type):
        return self.f[icmp6type >> 5] & (1 << (icmp6type & 0x1f)) == 0

    def willblock(self, icmp6type):
        return self.f[icmp6type >> 5] & (1 << (icmp6type & 0x1f)) == 1

    def setsockopt(self, sock):
        sock.setsockopt(socket.IPPROTO_ICMPV6, SO_ICMP6_FILTER,
                        struct.pack('@8I', *self.f))
