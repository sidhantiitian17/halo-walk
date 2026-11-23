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
clock=/sys/devices/system/clocksource/clocksource0
{
    uname -a
    iperf3 --version
    cat "$clock/available_clocksource"
} > "$dest/platform.txt"
for rate in 20 50 100; do
    rm -f /tmp/fid.pcap
    echo "HALO_FIDELITY $label $rate"
    printf '%s start clocksource: %s\n' "$rate" "$(cat "$clock/current_clocksource")" >> "$dest/platform.txt"
    if timeout --kill-after=5 120 "$python" scenarios/fidelity.py "$rate" "$dest/fid_$rate.json" >"$dest/fid_$rate.log" 2>&1; then
        cp /tmp/fid.pcap "$dest/fid_$rate.pcap"
    else
        echo "HALO_FIDELITY_FAILED $rate exit=$?"
        [[ ! -f /tmp/fid.pcap ]] || cp /tmp/fid.pcap "$dest/fid_$rate.pcap"
        timeout --kill-after=5 20 rig/rig_down.sh
        rc=1
    fi
    printf '%s end clocksource: %s\n' "$rate" "$(cat "$clock/current_clocksource")" >> "$dest/platform.txt"
    cat "$dest/fid_$rate.log"
done
dmesg | sed -n -E '/clocksource:|TSC.*unstable/p' > "$dest/clocksource.log"
exit "$rc"
