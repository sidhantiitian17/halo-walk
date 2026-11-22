#!/bin/bash
# change the EMULATED line rate at runtime: set_rate.sh DOWN_MBIT UP_MBIT
bb(){ awk -v r=$1 'BEGIN{b=int(r*1e6/8*0.005); if(b<15000)b=15000; print b}'; }
B=$(bb $1)
ip netns exec modem tc class change dev m-gw  parent 1: classid 1:1 htb rate ${1}mbit ceil ${1}mbit burst ${B}b cburst ${B}b quantum 1514
B=$(bb $2)
ip netns exec modem tc class change dev m-isp parent 1: classid 1:1 htb rate ${2}mbit ceil ${2}mbit burst ${B}b cburst ${B}b quantum 1514
