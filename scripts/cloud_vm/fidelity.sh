#!/bin/bash
# Execute the repository's fidelity test for each required rate and archive the captures.
set -euo pipefail
label=$1
dir="/tmp/$label"
dest="/exchange/$label/fidelity"
mkdir -p "$dir" "$dest"
tar -xf "/exchange/$label.tar" -C "$dir"
cd "$dir"
python=/workspace/.halo-venv/bin/python
if [[ -x /opt/halo-venv/bin/python ]]; then
    python=/opt/halo-venv/bin/python
fi
rc=0
for rate in 20 50 100; do
    rm -f /tmp/fid.pcap
    echo "HALO_FIDELITY $label $rate"
    if timeout --kill-after=5 120 "$python" scenarios/fidelity.py "$rate" "$dest/fid_$rate.json" >"$dest/fid_$rate.log" 2>&1; then
        cp /tmp/fid.pcap "$dest/fid_$rate.pcap"
    else
        echo "HALO_FIDELITY_FAILED $rate exit=$?"
        [[ ! -f /tmp/fid.pcap ]] || cp /tmp/fid.pcap "$dest/fid_$rate.pcap"
        rig/rig_down.sh
        rc=1
    fi
    cat "$dest/fid_$rate.log"
done
exit "$rc"
