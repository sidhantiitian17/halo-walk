#!/bin/bash
# Execute the repository's fidelity test for each required rate and archive the captures.
set -euo pipefail
label=$1
dir="/tmp/$label"
dest="/exchange/$label/fidelity"
mkdir -p "$dir" "$dest"
tar -xf "/exchange/$label.tar" -C "$dir"
cd "$dir"
rc=0
for rate in 20 50 100; do
    rm -f /tmp/fid.pcap
    if /workspace/.halo-venv/bin/python scenarios/fidelity.py "$rate" "$dest/fid_$rate.json"; then
        cp /tmp/fid.pcap "$dest/fid_$rate.pcap"
    else
        echo "HALO_FIDELITY_FAILED $rate"
        rig/rig_down.sh
        rc=1
    fi
done
exit "$rc"
