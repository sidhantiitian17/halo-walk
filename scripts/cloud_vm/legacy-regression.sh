#!/bin/bash
# Guest only. Give the legacy integration checks an isolated network and their tracked fixtures.
set -euo pipefail
label=$1
[[ $label =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || exit 2
root=$(mktemp -d)
ns="halo-legacy-$$"
ip netns add "$ns"
trap 'ip netns del "$ns"; rm -rf "$root"' EXIT
tar -xf "/exchange/$label.tar" -C "$root"
ip -n "$ns" link set lo up
ip -n "$ns" link add legacywan type veth peer name legacypeer
ip -n "$ns" addr add 192.0.2.1/24 dev legacywan
ip -n "$ns" addr add 192.0.2.2/24 dev legacypeer
ip -n "$ns" link set legacywan up
ip -n "$ns" link set legacypeer up
ip -n "$ns" route add default via 192.0.2.2 dev legacywan
cd "$root"
timeout --kill-after=10 220 ip netns exec "$ns" /opt/halo-venv/bin/python -m pytest -q tests
