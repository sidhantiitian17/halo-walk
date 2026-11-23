#!/bin/bash
# Diagnostic S2 repetition. Packet taps add work, so score the untouched matrix separately.
set -euo pipefail
label=$1
dir="/tmp/$label-taps"
dest="/exchange/$label/taps"
mkdir -p "$dir" "$dest"
test ! -e /run/halo_rig
bash /exchange/bench.sh "$label" S2,C3,1 &
bench_pid=$!
for _ in {1..80}; do
    [[ -f /run/halo_rig ]] && break
    kill -0 "$bench_pid"
    sleep 0.25
done
test -f /run/halo_rig
filter='udp src port 3478 and dst host 10.0.0.10'
ip netns exec modem tcpdump -n -i m-isp -Q in -s 58 -U -w "$dir/modem-ingress.pcap" "$filter" 2>"$dir/modem-ingress.log" &
ingress_pid=$!
ip netns exec gw tcpdump -n -i wan0 -Q in -s 58 -U -w "$dir/gateway-ingress.pcap" "$filter" 2>"$dir/gateway-ingress.log" &
gateway_pid=$!
ip netns exec gw tcpdump -n -i lan0 -Q out -s 58 -U -w "$dir/gateway-egress.pcap" "$filter" 2>"$dir/gateway-egress.log" &
egress_pid=$!
rc=0
wait "$bench_pid" || rc=$?
wait "$ingress_pid" 2>/dev/null || true
wait "$gateway_pid" 2>/dev/null || true
wait "$egress_pid" 2>/dev/null || true
cp "$dir/"* "$dest/"
exit "$rc"
