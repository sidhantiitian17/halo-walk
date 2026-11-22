#!/bin/bash
# HALO-Walk EMULATED home-broadband rig (Linux network namespaces; nothing here is real hardware).
#   LAN hosts --(bridge in ns sw)-- gw --- modem --- isp --- wan
#   modem : the line-rate BOTTLENECK (HTB rate + byte FIFO = bloated modem buffer), both directions
#   isp   : fixed one-way propagation delay (netem), both directions
# usage: rig_up.sh [DOWN_MBIT=100] [UP_MBIT=20] [DELAY_MS=10] [BUF_MS_AT_20=600]
set -e
DOWN=${1:-100}; UP=${2:-20}; DELAY=${3:-10}; BUFBYTES=${RIG_BUF_BYTES:-1500000}
HOSTS="laptop gamer tv1 tv2 tv3 pc"
"$(dirname "$0")/rig_down.sh" >/dev/null 2>&1 || true
for n in sw gw modem isp wan $HOSTS; do ip netns add $n; ip -n $n link set lo up; done
nx(){ ip netns exec "$@"; }
off(){ nx $1 ethtool -K $2 tso off gso off gro off >/dev/null 2>&1 || true; }
link(){ # nsA ifA nsB ifB
  ip link add $2 netns $1 type veth peer name $4 netns $3
  ip -n $1 link set $2 up; ip -n $3 link set $4 up; off $1 $2; off $3 $4; }
# LAN switch
ip -n sw link add br0 type bridge; ip -n sw link set br0 up
i=10
for h in $HOSTS; do
  link $h eth0 sw p-$h; ip -n sw link set p-$h master br0
  ip -n $h addr add 10.0.0.$i/24 dev eth0; ip -n $h -6 addr add fd00:0::$i/64 dev eth0 nodad
  ip -n $h route add default via 10.0.0.1; ip -n $h -6 route add default via fd00:0::1
  i=$((i+1))
done
link gw lan0 sw p-gw; ip -n sw link set p-gw master br0
ip -n gw addr add 10.0.0.1/24 dev lan0; ip -n gw -6 addr add fd00:0::1/64 dev lan0 nodad
link gw wan0 modem m-gw
ip -n gw addr add 10.1.0.1/30 dev wan0; ip -n gw -6 addr add fd00:1::1/64 dev wan0 nodad
ip -n modem addr add 10.1.0.2/30 dev m-gw; ip -n modem -6 addr add fd00:1::2/64 dev m-gw nodad
link modem m-isp isp i-modem
ip -n modem addr add 10.2.0.1/30 dev m-isp; ip -n modem -6 addr add fd00:2::1/64 dev m-isp nodad
ip -n isp addr add 10.2.0.2/30 dev i-modem; ip -n isp -6 addr add fd00:2::2/64 dev i-modem nodad
link isp i-wan wan eth0
ip -n isp addr add 10.9.0.1/24 dev i-wan; ip -n isp -6 addr add fd00:9::1/64 dev i-wan nodad
for k in 2 3 4 5 6; do ip -n wan addr add 10.9.0.$k/24 dev eth0; ip -n wan -6 addr add fd00:9::$k/64 dev eth0 nodad; done
for n in gw modem isp; do nx $n sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1; done
# routes
ip -n gw route add default via 10.1.0.2; ip -n gw -6 route add default via fd00:1::2
ip -n modem route add 10.0.0.0/24 via 10.1.0.1; ip -n modem -6 route add fd00:0::/64 via fd00:1::1
ip -n modem route add default via 10.2.0.2; ip -n modem -6 route add default via fd00:2::2
ip -n isp route add 10.0.0.0/24 via 10.2.0.1; ip -n isp route add 10.1.0.0/30 via 10.2.0.1
ip -n isp -6 route add fd00:0::/64 via fd00:2::1; ip -n isp -6 route add fd00:1::/64 via fd00:2::1
ip -n wan route add default via 10.9.0.1; ip -n wan -6 route add default via fd00:9::1
# EMULATED modem bottleneck (down: egress m-gw, up: egress m-isp)
bott(){ # dev rate   (burst = 5 ms of tokens, >= 15 kB: lets the emulator catch up after timer latency)
  B=$(awk -v r=$2 'BEGIN{b=int(r*1e6/8*0.005); if(b<15000)b=15000; print b}')
  nx modem tc qdisc replace dev $1 root handle 1: htb default 1
  nx modem tc class replace dev $1 parent 1: classid 1:1 htb rate ${2}mbit ceil ${2}mbit burst ${B}b cburst ${B}b quantum 1514
  nx modem tc qdisc replace dev $1 parent 1:1 handle 10: bfifo limit $BUFBYTES; }
bott m-gw $DOWN; bott m-isp $UP
# EMULATED propagation delay
nx isp tc qdisc replace dev i-modem root netem delay ${DELAY}ms limit 20000
nx isp tc qdisc replace dev i-wan   root netem delay ${DELAY}ms limit 20000
echo "$DOWN $UP $DELAY $BUFBYTES" > /run/halo_rig
echo "rig up: down=${DOWN}mbit up=${UP}mbit delay=${DELAY}ms/dir buffer=${BUFBYTES}B"
