#!/bin/bash
set -euo pipefail
ns="halo-check-$$"
ip netns add "$ns"
trap 'ip netns del "$ns"' EXIT
ip -n "$ns" link add check0 type veth peer name check1
ip netns exec "$ns" tc qdisc add dev check0 root cake bandwidth 100mbit
ip netns exec "$ns" tc qdisc add dev check1 root netem delay 10ms
ip netns exec "$ns" tc qdisc show
