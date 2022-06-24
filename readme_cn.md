# ip6ctl

## usage

usage: ./ip6ctl.sh {start|stop|restart|fw|nofw|status}

## description

开启、关闭或重启内核IPv6、IPv6转发。

# ping6

## usage

usage: ./ping6.py [-i interface] [-ear [address]] [-l length]

## description

Ping(-e address)、ARPing(-a address)或RSPing(-r)。

# fake_router6、kill_router6

## usage

usage: ./fake_router6.py [-i interface] [-I internal] [-p prefix] [-MOAL val]

usage: ./kill_router6.py [-i interface] [-t target] [-l] ROUTER

## description

fake_router6时最小化的RA守护进程，通过参数配置RA报文的几个主要参数。

kill_router6通过主动发送R标记为0的NA报文消除一个目标主机的默认路由器。

这两个程序可以配合使用将攻击主机设置为目标主机的默认路由器，

且可以改变目标主机的地址自动配置方式，进一步进行DHCPv6劫持和DNS劫持。

## options

internal：主动发送RA报文的时间间隔，默认值为30，为0时不主动发送RA报文。

prefix：RA前缀信息选项，为空时不携带该选项，忽略A、L标志。

target：发送NA报文的目的地址，默认为ff02::1。

router：要删除的路由器的地址。

# dos_new6

## usage

usage: ./dos_new6.py [-i interface]

## description

针对DAD的拒绝服务攻击。需要能够收到目标DAD报文：开启promisc模式或手动加入多播地址。

# mitm_neighbor6

## usage

usage: ./mitm_neighbor6 [-i interface] [-R val] target item

## description

通过发送带目标链路层地址选项的NA报文改变目标主机的邻居表的特定地址的链路层地址为攻击主机的链路层地址。

开启IPv6转发并通过两次该程序可以实现中间人攻击。值得注意的是所有NDP报文经过转发跳数会变为254，需要通过其它方式阻止NDP报文跳数的改变。

## options

target：发送NA报文的目的地址。

item：要改变的表项。
