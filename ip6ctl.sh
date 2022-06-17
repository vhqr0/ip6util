#!/bin/sh

case "$1" in
    status)
        sysctl net.ipv6.conf.all.disable_ipv6
        sysctl net.ipv6.conf.all.forwarding
        ;;
    start)
        sysctl -w net.ipv6.conf.all.disable_ipv6=0
        ;;
    stop)
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        ;;
    restart)
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        sysctl -w net.ipv6.conf.all.disable_ipv6=0
        ;;
    fw)
        sysctl -w net.ipv6.conf.all.forwarding=1
        ;;
    nofw)
        sysctl -w net.ipv6.conf.all.forwarding=0
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|fw|nofw}"
        exit 1
esac
