import icmp6filter_pym as m

import socket

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
ICMP6_ND_ROUTER_SOLICIT = 133
ICMP6_ND_ROUTER_ADVERT = 134
ICMP6_ND_NEIGHBOR_SOLICIT = 135
ICMP6_ND_NEIGHBOR_ADVERT = 136


def icmp6setfilter(sock, icmp6type):
    assert isinstance(sock, socket.socket) and isinstance(icmp6type, int)
    m.icmp6setfilter(sock.fileno(), icmp6type)
