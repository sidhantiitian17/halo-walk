#!/bin/bash
# reset: kill every process inside rig namespaces, delete namespaces
for n in $(ip netns list 2>/dev/null | awk '{print $1}'); do
  for p in $(ip netns pids $n 2>/dev/null); do kill -9 $p 2>/dev/null; done
done
sleep 0.2
for n in $(ip netns list 2>/dev/null | awk '{print $1}'); do ip netns del $n 2>/dev/null; done
rm -f /run/halo_rig; ip link del ifb4wan0 2>/dev/null; true
