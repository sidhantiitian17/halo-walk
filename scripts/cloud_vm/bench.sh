#!/bin/bash
set -euo pipefail
label=$1
shift
dir="/tmp/$label"
dest="/exchange/$label"
mkdir -p "$dir" "$dest"
tar -xf "/exchange/$label.tar" -C "$dir"
cd "$dir"
python=/workspace/.halo-venv/bin/python
for spec in "$@"; do
    IFS=, read -r scenario config rep <<< "$spec"
    echo "HALO_RUN $label $scenario $config $rep"
    set +e
    timeout 200 "$python" scenarios/run.py "$scenario" "$config" "$rep"
    rc=$?
    set -e
    printf -v run 'r%02d' "$rep"
    src="results/raw/$scenario/$config/$run"
    if [[ -d "$src" ]]; then
        mkdir -p "$dest/$scenario/$config"
        cp -r "$src" "$dest/$scenario/$config/"
    fi
    if ((rc != 0)); then
        rig/rig_down.sh
        exit "$rc"
    fi
done
