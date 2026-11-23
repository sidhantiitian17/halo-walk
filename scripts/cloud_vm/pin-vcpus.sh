#!/bin/bash
# Pin each TCG vCPU to a distinct host CPU. The guest workload is unchanged.
set -euo pipefail
if (( $# < 2 )) || [[ ! "$1" =~ ^[0-9]+$ ]]; then
    echo "Usage: $0 QEMU_PID CPU_FOR_VCPU_0 [CPU_FOR_VCPU_1 ...]" >&2
    exit 2
fi
pid=$1
shift
cpus=("$@")
[[ "$(basename "$(readlink -f "/proc/$pid/exe")")" == qemu-system-x86_64 ]]
declare -A threads=() assigned=()
for task in "/proc/$pid/task/"*; do
    name=$(cat "$task/comm")
    if [[ "$name" =~ ^CPU\ ([0-9]+)/TCG$ ]]; then
        threads[${BASH_REMATCH[1]}]=${task##*/}
    fi
done
[[ "${#threads[@]}" == "${#cpus[@]}" ]]
for i in "${!cpus[@]}"; do
    cpu=${cpus[i]}
    [[ -v threads[$i] && "$cpu" =~ ^[0-9]+$ && ! -v assigned[$cpu] ]]
    assigned[$cpu]=1
done
for i in "${!cpus[@]}"; do
    printf 'vCPU %s, CPU %s\n' "$i" "${cpus[i]}"
    taskset -pc "${cpus[i]}" "${threads[$i]}"
done
