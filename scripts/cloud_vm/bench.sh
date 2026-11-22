#!/bin/bash
set -euo pipefail
label=$1
shift
dir="/tmp/$label"
dest="/exchange/$label"
mkdir -p "$dir" "$dest"
tar -xf "/exchange/$label.tar" -C "$dir"
cd "$dir"
shared_venv=/workspace/.halo-venv
guest_venv=/opt/halo-venv
python="$shared_venv/bin/python"
if [[ -x "$guest_venv/bin/python" ]]; then
    python="$guest_venv/bin/python"
fi
for spec in "$@"; do
    IFS=, read -r scenario config rep <<< "$spec"
    if [[ "$config" == C4 && "$python" == "$shared_venv/bin/python" ]]; then
        # Stage the same pinned dependencies on the guest filesystem. Cold model startup over
        # the 9p share can exceed the unchanged harness's readiness timeout.
        mkdir -p /opt
        staged_venv=$(mktemp -d /opt/halo-venv.XXXXXX)
        cp -a "$shared_venv/." "$staged_venv/"
        "$staged_venv/bin/python" -c 'import fastapi, numpy, sklearn, xgboost'
        mv "$staged_venv" "$guest_venv"
        python="$guest_venv/bin/python"
    fi
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
