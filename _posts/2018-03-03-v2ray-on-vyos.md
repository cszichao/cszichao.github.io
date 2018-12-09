---
title: Build a Transparent TCP/UDP Proxy with V2Ray on VyOS
description: Fuck the great fire wall in China with V2Ray on VyOS
header: Build a Transparent TCP/UDP Proxy with V2Ray on VyOS
tags: V2Ray VyOS GFW
---
This article shows an enterprise solution for building a transparent TCP/UDP proxy gateway using [VyOS](https://vyos.io/) and [V2Ray](https://www.v2ray.com/) to help you crossing the [Great Firewall of China](https://en.wikipedia.org/wiki/Internet_censorship_in_China).

For home users, it is recommended and much easier to build a [shadowsocks](https://github.com/shadowsocks) transparent proxy on a mips or arm router using [OpenWrt](https://openwrt.org/), [padavan](https://bitbucket.org/padavan/rt-n56u) or [Asuswrt-Merlin](https://asuswrt.lostrealm.ca/).


# System Overview
[VyOS](https://vyos.io/) is an open source network/router operating system which based on Debian and joins multiple applications such as Quagga, ISC DHCPD, OpenVPN, StrongS/WAN and others under a single management interface.

[V2Ray](https://www.v2ray.com), a.k.a. Project V, is a set of open source tools to help people build their own privicy network over Internet by providing secure KCP/TCP/UDP tunneling service.

A typical network structure with this system is shown as below:

![system overview]({{ "/img/system-overview.svg" | absolute_url }})

In this network, VyOS acts as a firewall as well as a proxy gateway which auto redirects traffic of [GFW blocked sites](https://github.com/gfwlist/gfwlist) to V2Ray server by V2Ray client installed on VyOS. As illustrated in the figure, all enterprise services are runing in an virtual machine on hypervisors such as [ESXi](https://www.vmware.com/products/esxi-and-esx.html), [KVM](https://www.linux-kvm.org/page/Main_Page) and [Hyper-V](https://en.wikipedia.org/wiki/Hyper-V) etc. VyOS uses a physical NIC directly (via [PCI Passthough](https://www.ibm.com/developerworks/library/l-pci-passthrough/)) as a WAN port, and provides a sub LAN `192.168.0.0/24` with gateway `192.168.0.1` using virtual NIC and virtual Switch for incoming traffic.

[iKuai OS](https://www.ikuai8.com/) is another free closed source soft router system provides brilliant web management UI & NAT performance but lack of packge management features. Its WAN is connected to VyOS LAN's virtual Switch as a client of VyOS and provides a sub LAN `10.1.0.0/20` with gateway `10.1.1.1` for enterprise network by bridging a virtual NIC and a physical NIC together.

Now, we assume a device in this enterprise network with IP address `10.1.1.101`. When it browses a non-GFW-blocked site, [https://www.bing.com](https://www.bing.com) for example, the traffic should be 

```
10.1.1.101 -> 10.1.1.1 -> 192.168.0.1 -> www.bing.com
```

While for a GFW-blocked site, such as [https://www.google.com](https://www.google.com), the traffic should be

```
10.1.1.101 -> 10.1.1.1 -> 192.168.0.1 -> v2ray client -> v2ray server -> www.google.com
```

and the detailed procedure is shown in the figure below:

![system overview]({{ "/img/v2ray-on-vyos.svg" | absolute_url }})

[Dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) is an open source DNS, DHCP server, which can also forward different domain name queries to different name servers. Here we forward non-GFW-blocked domains directly to public DNS servers such as [114dns](https://www.114dns.com). For GFW-blocked domains, the corresponding DNS is [poisoned](https://en.wikipedia.org/wiki/DNS_spoofing) by GFW, so we should proxy (or redirect) the DNS query traffic to V2Ray servers to get the right answer. Here we use the [Dokodemo-Door](https://www.v2ray.com/chapter_02/protocols/dokodemo.html) of V2Ray to tunnel the DNS query securely to [Google's public DNS](https://developers.google.com/speed/public-dns/) 8.8.8.8. Meantime, the solved GFW-blocked IP Addresses are save into an [ipset](http://ipset.netfilter.org/) named `gfwlist` used for further iptables routing.

[iptables](https://en.wikipedia.org/wiki/Iptables) is usesd to forward different kinds of (GFW-blocked and non-GFW-blocked) incoming traffic to different destinations, for IPs in the ipset of gwflist, the traffic would be forward to a Dokodemo-Door of V2Ray with redirecting feature. With the help of these 2 Dokodemo-Doors, we can forward our TCP/UDP traffic to V2Ray server over GFW easily.

## Questions

### Why VyOS?

* Debian based, lots of linux packages to choose from.
* Why not [Debian](https://www.debian.org/)? Too many related settings at different places to make a Debian into a router system. Vyos has only one single and uniform management interface.
* Why not [pfsense](https://www.pfsense.org/)? pfsense is a brilliant firewall system as well as a great router base on OpenBSD. However, its routing performance [isn't as great as](https://dotbalm.org/leaving-pfsense-for-vyos/) VyOS.
* Why not [OpenWrt x86](https://openwrt.org/)? As it says, *The OpenWrt Project is a Linux operating system targeting embedded devices*, **OpenWrt x86** is only a compatible port on low-end x86 hardwares, not for enterprise.

### Why V2Ray?
* Supports lots of outbound protocols, including [VMess](https://www.v2ray.com/chapter_02/protocols/vmess.html), [Shadowsocks](https://www.v2ray.com/chapter_02/protocols/socks.html) and [SOCKS](https://www.v2ray.com/chapter_02/protocols/shadowsocks.html).
* Simple JSON based configuration.
* Why not [Shadowsocks](https://github.com/shadowsocks)? Shadowsocks supports only one outbund protocol, **ss-redir** and **ss-tunnel** is also required to make transparent proxy and DNS forwarding. While V2Ray has only one standalone executable program with a JSON config file.

### Why iKuai OS?
* Why not use VyOS directly? Absolutely you can, and its also recommend to use VyOS directly if you do not need any visual management UI.
* Any alternatives? Surely, so many, like [hi-spider](http://www.hi-spider.com), [panabit](http://www.panabit.com/), [brazilfw](https://www.brazilfw.com.br) or even hardware routers.

# Prerequisites
* VT-d supported CPU.
* At least 2 physical NICs on different PCI slots.
* Choose and install a hypervisor on your machine.
* Create a VM named VyOS with one physical NIC passthough and one virtual NIC, then download and install the VyOS on it.
* Create another VM named iKuaiOS with one physical NIC passthough and two virtual NICs, then download and install iKuai OS on it.
* Plug the VyOS's physical NIC to Internet.
* Plug the iKuai OS's physical NIC to Intranet.

# Configurations
## VyOS
### Pre Setup
Get rid of the annoying 

> INIT: Id "TO" respawning too fast: disabled for 5 
minutes.

by disable TTyS0 (serial) Console:

```
$ configure
# delete system console device ttyS0
# commit
# save
# exit
$ reboot
```

add debian squeeze source

```bash
sudo su

# add source
cat << EOF >/etc/apt/sources.list
deb http://archive.debian.org/debian/ squeeze main contrib non-free
deb-src http://archive.debian.org/debian/ squeeze main contrib non-free
deb http://archive.debian.org/debian-archive/debian-security/ squeeze/updates main contrib non-free
deb-src http://archive.debian.org/debian-archive/debian-security/ squeeze/updates main contrib non-free
deb http://archive.debian.org/debian-archive/backports.org squeeze-backports main contrib non-free
EOF

# update and install vim & daemon 
apt-get -o Acquire::Check-Valid-Until=false update
apt-get install vim daemon
```

### WAN Setup
Enter the config mode, then config eth0, a.k.a. the physical NIC using DHCP

```bash
set interfaces ethernet eth0 description 'WAN interface'
set interfaces ethernet eth0 duplex auto
set interfaces ethernet eth0 speed auto
set interfaces ethernet eth0 smp_affinity auto
set interfaces ethernet eth0 mtu 1500
set interfaces ethernet eth0 address dhcp
```
### LAN Setup
Enter the config mode, then config eth1, a.k.a. the virtual NIC as LAN `192.168.0.1/24`

```bash
set interfaces ethernet eth1 description 'LAN Interface'
set interfaces ethernet eth1 duplex auto
set interfaces ethernet eth1 speed auto
set interfaces ethernet eth1 smp_affinity auto
set interfaces ethernet eth1 mtu 1500
set interfaces ethernet eth1 address 192.168.0.1/24
```
Start the LAN DHCP server, offering `192.168.0.101 - 192.168.0.199`

```bash
set service dhcp-server disabled 'false'
set service dhcp-server shared-network-name LAN description 'LAN DHCP'
set service dhcp-server shared-network-name LAN subnet 192.168.0.1/24 default-router 192.168.0.1
set service dhcp-server shared-network-name LAN subnet 192.168.0.1/24 start 192.168.0.101 stop 192.168.0.199
set service dhcp-server shared-network-name LAN subnet 192.168.0.1/24 lease '86400'
set service dhcp-server shared-network-name LAN subnet 192.168.0.1/24 dns-server 192.168.0.1
```

Setup the loopback

```bash
set interfaces loopback lo description LOCAL-NET
```

### NAT Setup
Enter the config mode, add SNAT rule

```bash
set nat source rule 1 outbound-interface eth0
set nat source rule 1 source address 192.168.0.1/24
set nat source rule 1 translation address masquerade
```

### Miscellaneous
SSH server setup

```bash
set service ssh port '22'
```

System setup

```bash
set system host-name router
set system domain-name router.example.com
set system time-zone Asia/Beijing
set system ntp server time.asia.apple.com
```

Finish setup and save

```
# commit
# save
# exit
```

Now, for any virtual machine connected to the VyOS LAN virtual NIC, which can get a DHCP address `192.168.0.1xx` with net mask `255.255.255.0` and gateway `192.168.0.1`, with a self provided DNS Address, it could connect to the Internet normally.


## V2Ray
### Install and Daemonize V2Ray

Install V2Ray using scripts and make it autostarts

```bash
sudo su
# install V2Ray
bash <(curl -L -s https://install.direct/go.sh)
# auto start
update-rc.d v2ray defaults
```
Now you can configure V2Ray in `/etc/v2ray/config.json`

### inbound and inboundDetour
Open HTTP proxy on 1080 for `inbound` section

```json
{
    "port":1080,
    "protocol":"http",
    "settings":{
        "timeout":0
    }
}
```

Open TCP/UDP tunnel (on port `10800`) and DNS Tunnel (on port `5353`) for `inboundDetour` section

```json
[
    {
        "port":10800,
        "protocol":"dokodemo-door",
        "settings":{
            "network":"tcp,udp",
            "followRedirect":true
        }
    },
    {
        "port":5353,
        "protocol":"dokodemo-door",
        "settings":{
            "address":"8.8.8.8",
            "port":53,
            "network":"tcp,udp",
            "followRedirect":false
        }
    }
]
```

### outbound and outboundDetour
Config V2Ray (or Shadowsocks) for client in `outbound` section, here I use 2 Shadowsocks server as example. It is also very easy and painless to get a dedicated shadowsocks server via [bandwagon](https://bwh1.net/)

```json
{
    "protocol":"shadowsocks",
    "settings":{
        "servers":[
            {
                "email":"someone@example.com",
                "address":"1.1.1.1",
                "port":8888,
                "method":"aes-256-cfb",
                "password":"somepwd",
                "ota":false
            },
            {
                "email":"someone@example.com",
                "address":"2.2.2.2",
                "port":9999,
                "method":"aes-128-cfb",
                "password":"somepwd",
                "ota":false
            }
        ]
    }
}
```
Config `direct` and `blackhole` in `outboundDetour` for V2Ray router

```json
[
    {
        "protocol":"freedom",
        "tag":"direct",
        "settings":{}
    },
    {
        "protocol":"blackhole",
        "tag":"blocked",
        "settings":{}
    }
]

```

### routing

Get local IP directly and block some evil domains via `routing` section

```json
{
    "strategy":"rules",
    "settings":{
        "domainStrategy":"IPIfNonMatch",
        "rules":[
            {
                "type":"field",
                "ip":[
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "100.64.0.0/10",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.0.0.0/24",
                    "192.0.2.0/24",
                    "192.168.0.0/16",
                    "198.18.0.0/15",
                    "198.51.100.0/24",
                    "203.0.113.0/24",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ],
                "outboundTag":"direct"
            },
            {
                "type":"field",
                "domain":[
                    "baidu.com",
                    "360.com",
                    "360.cn"
                ],
                "outboundTag":"blocked"
            }
        ]
    }
}
```
### Start and Test V2Ray Client

```bash
sudo su
# start v2ray daemon
service v2ray start

# test v2ray HTTP proxy 
curl -v -x 127.0.0.1 www.google.com
# you should get a Google's homepage response on screen now
```

change ulimit of the server:

```bash
sudo su
echo 'ulimit -n 102400' >> \
	/opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script
```

## dnsmasq

Open DNS server on port `53`:

```bash
echo 'listen-address=192.168.0.1
port=53
cache-size=100000
conf-dir=/etc/dnsmasq.d,.bak
resolv-file=/etc/resolv.dnsmasq.conf'>/etc/dnsmasq.conf
```

Setup forward DNS server as [114DNS](https://www.114dns.com/):

```bash
echo 'nameserver 114.114.114.114
nameserver 114.114.115.115'>/etc/resolv.dnsmasq.conf
```

Add gwflist's [dnsmasq rule file with ipset](https://github.com/cokebar/gfwlist2dnsmasq) to dnsmasq:

```bash
curl https://cokebar.github.io/gfwlist2dnsmasq/dnsmasq_gfwlist_ipset.conf \
	-o /etc/dnsmasq.d/dnsmasq_gfwlist_ipset.conf
```

Start dnsmasq and make it autostarts:

```bash
sudo su
service dnsmasq start
update-rc.d dnsmasq defaults
```

## iptables
add gfwlist ipset and related iptables rule:

```bash
sudo su
ipset -N gfwlist iphash
iptables -t nat -A PREROUTING -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-port 10800
iptables -t nat -A OUTPUT -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-port 10800
```

make this ipset and iptables rule persistent:

```bash
sudo su
echo 'ipset -N gfwlist iphash
iptables -t nat -A PREROUTING -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-port 10800
iptables -t nat -A OUTPUT -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-port 10800'>> \
	/opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script
```

## iKuai OS

* Bind (bridge) the physical NIC and one of the virtual NICs together as the iKuai LAN `10.1.0.0/20`
* Connect the other virtual NIC to VyOS's LAN virtual NIC as iKuai WAN with DHCP
* Setup iKuai's DHCP server with DNS server `192.168.0.1`
* Plug a device to iKuai's LAN with DHCP, open Google's homepage to test the system

# Best Practices

## Static Routing on VyOS

Assume iKuai's WAN gets a DHCP address `192.168.0.101`, for static routing to `10.1.0.0/20` subnet, use this following configuration:

```bash
set protocols static route 10.1.0.0/20 next-hop 192.168.0.101
```
## DNS Force Redirecting

Although we've set up a clean DNS server on `192.168.0.1:53`, for clients who uses self defined DNS servers other than this one, they still got the poisoned DNS records. So the best solution is redirecting all the DNS query traffic to `192.168.0.1:53` in VyOS:

```bash
iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j DNAT --to 192.168.0.1
iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 53 -j DNAT --to 192.168.0.1
```

# Trouble Shooting

## Fail to Connect to V2Ray DNS Tunnel

The GFW or several ISPs may block the UDP traffic somehow, one solution is force the DNS query over TCP.

[Overture](https://github.com/shawn1m/overture) is a DNS server/forwarder/dispatcher which can help us dispatch the incoming UDP DNS query to upstream DNS server use TCP only.

Thus, the DNS query for a GFW blocked site would be

```
Client Query -(UDP)-> iKuaiOS DNS Server -(UDP)-> Dnsmasq -(UDP)-> Overture -(TCP)-> V2Ray DNS Dokodemo-Door -(TCP)->||GFW||-(TCP)-> V2Ray Server
```

Download the latest linux amd64 prebuild binary of overture from [here](https://github.com/shawn1m/overture/releases), then move it into /usr/bin/ directory:

```bash
# download overture from https://github.com/shawn1m/overture/releases the unzip it
mv ./overture-linux-amd64 /usr/bin/overture
chmod +x /usr/bin/overture
```

change the V2Ray's DNS Tunnel Port from `5353` into `15353`, then restart it:

```bash
# replace 5353 into 15353
# make sure only one 5353 token in your config file 
sed -i "s/:5353/:15353/g" /etc/v2ray/config.json
service v2ray restart
```

configure the overtune's server port as `5353` and tcp only upstream as `127.0.0.1:15353`:

```bash
# make the overture's config dir
mkdir -p /etc/overture
cat << EOF >/etc/overture/config.json
{
	"BindAddress": ":5353",
	"PrimaryDNS": [{
		"Name": "V2RayDNSTunnel",
		"Address": "127.0.0.1:15353",
		"Protocol": "tcp",
		"SOCKS5Address": "",
		"Timeout": 6,
		"EDNSClientSubnet": {
			"Policy": "disable",
			"ExternalIP": ""
		}
	}],
	"OnlyPrimaryDNS": true,
	"RedirectIPv6Record": false,
	"DomainBase64Decode": true,
	"MinimumTTL": 100000,
	"CacheSize": 604800,
	"RejectQtype": [255]
}
EOF
```

test the config

```bash
# on vyOS terminal
overture -c /etc/overture/config.json

# on your local machine
dig @192.168.0.1 -p 15353 www.google.com +tcp # DNS tunnel
dig @192.168.0.1 -p 5353 www.google.com # overture server
dig @192.168.0.1 www.google.com # Dnsmasq Server
dig @10.1.1.1 www.google.com # iKuaiOS 
dig www.google.com # locally 
```

Daemonize overture

```bash
cat << EOF >/etc/init.d/overture
#!/bin/sh
### BEGIN INIT INFO
# Provides:          overture
# Required-Start:    \$network \$local_fs \$remote_fs
# Required-Stop:     \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: overture DNS services
# Description:       overture DNS services
### END INIT INFO

DESC=overture
NAME=overture
DAEMON=/usr/bin/overture
PIDFILE=/var/run/\$NAME.pid
SCRIPTNAME=/etc/init.d/\$NAME

DAEMON_OPTS="-c /etc/overture/config.json"

# Exit if the package is not installed
[ -x \$DAEMON ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/\$NAME ] && . /etc/default/\$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
    ulimit -n 102400
    mkdir -p /var/log/overture
    # Return
    #   0 if daemon has been started
    #   1 if daemon was already running
    #   2 if daemon could not be started
    #   3 if configuration file not ready for daemon
    start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON --test > /dev/null \
        || return 1
    start-stop-daemon --start --quiet --pidfile \$PIDFILE --exec \$DAEMON --background -m -- \$DAEMON_OPTS \
        || return 2
    # Add code here, if necessary, that waits for the process to be ready
    # to handle requests from services started subsequently which depend
    # on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
    # Return
    #   0 if daemon has been stopped
    #   1 if daemon was already stopped
    #   2 if daemon could not be stopped
    #   other if a failure occurred
    start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile \$PIDFILE
    RETVAL="\$?"
    [ "\$RETVAL" = 2 ] && return 2
    # Wait for children to finish too if this is a daemon that forks
    # and if the daemon is only ever run from this initscript.
    # If the above conditions are not satisfied then add some other code
    # that waits for the process to drop all resources that could be
    # needed by services started subsequently.  A last resort is to
    # sleep for some time.
    start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec \$DAEMON
    [ "\$?" = 2 ] && return 2
    # Many daemons don't delete their pidfiles when they exit.
    rm -f \$PIDFILE
    return "\$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
    #
    # If the daemon can reload its configuration without
    # restarting (for example, when it is sent a SIGHUP),
    # then implement that here.
    #
    start-stop-daemon --stop --signal 1 --quiet --pidfile \$PIDFILE
    return 0
}

case "\$1" in
  start)
    [ "\$VERBOSE" != no ] && log_daemon_msg "Starting \$DESC " "\$NAME"
    do_start
    case "\$?" in
        0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
        2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
    esac
  ;;
  stop)
    [ "\$VERBOSE" != no ] && log_daemon_msg "Stopping \$DESC" "\$NAME"
    do_stop
    case "\$?" in
        0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
        2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
    esac
    ;;
  status)
       status_of_proc "\$DAEMON" "\$NAME" && exit 0 || exit \$?
       ;;
  reload|force-reload)
    #
    # If do_reload() is not implemented then leave this commented out
    # and leave 'force-reload' as an alias for 'restart'.
    #
    log_daemon_msg "Reloading \$DESC" "\$NAME"
    do_reload
    log_end_msg \$?
    ;;
  restart|force-reload)
    #
    # If the "reload" option is implemented then remove the
    # 'force-reload' alias
    #
    log_daemon_msg "Restarting \$DESC" "\$NAME"
    do_stop
    case "\$?" in
      0|1)
        do_start
        case "\$?" in
            0) log_end_msg 0 ;;
            1) log_end_msg 1 ;; # Old process is still running
            *) log_end_msg 1 ;; # Failed to start
        esac
        ;;
      *)
        # Failed to stop
        log_end_msg 1
        ;;
    esac
    ;;
  *)
    #echo "Usage: \$SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
    echo "Usage: \$SCRIPTNAME {start|stop|status|reload|restart|force-reload}" >&2
    exit 3
    ;;
esac
EOF

# permissions and autostart
chmod +x /etc/init.d/overture
update-rc.d overture defaults
```