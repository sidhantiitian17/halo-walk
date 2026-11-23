#!/bin/bash
# Isolate the 100 Mbit/s data path and record traffic before and after HTB.
# This diagnostic is separate from the original M1 acceptance run.
set -euo pipefail
cd "$1"
dest=$2
mkdir -p "$dest"
capture_dir=$(mktemp -d)
trap 'rig/rig_down.sh; rm -rf "$capture_dir"' EXIT
rig/rig_up.sh 100.0 20.0 10
ip netns exec pc iperf3 -s -1 -p 5300 >"$dest/server.log" 2>&1 &
receiver=$!
sleep 1
# tcpdump drops privileges, so keep its output in the guest tmpfs with write access.
chmod 1777 "$capture_dir"
ip netns exec modem tcpdump -ni m-gw -Q out -s 64 -B 16384 -w "$capture_dir/modem.pcap" udp >"$dest/tcpdump.log" 2>&1 &
capture=$!
sleep 1.5
ip netns exec wan iperf3 -c 10.0.0.15 -p 5300 -u -b 160M -l 1400 -t 5 >"$dest/iperf.log" 2>&1 &
sender=$!
{
    ip netns exec modem tc -d -s class show dev m-gw
    for _ in 1 2 3 4 5; do
        sleep 0.5
        date +%s.%N
        ip netns exec modem tc -s qdisc show dev m-gw
        ip -n modem -s link show dev m-isp
    done
} >"$dest/counters.log"
wait "$sender"
sleep 0.5
kill -TERM "$capture"
wait "$capture"
wait "$receiver"
cp "$capture_dir/modem.pcap" "$dest/"
