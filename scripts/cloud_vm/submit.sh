#!/bin/bash
# Stage one batch into the guest exchange directory. Each label owns its raw runs.
set -euo pipefail
if (( $# < 3 )); then
    echo "Usage: $0 VM_DIR LABEL SCENARIO,CONFIG,REP [...]" >&2
    exit 2
fi
work=$1
label=$2
shift 2
[[ $label =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || exit 2
for spec in "$@"; do
    [[ $spec =~ ^(CPU|S[1-7]|S1x32|EST[0-9]+),C[0-4],[1-9][0-9]*$ ]] || exit 2
done
exchange=$(realpath "$work/exchange")
if [[ -e "$exchange/job" || -e "$exchange/running" || -e "$exchange/$label.tar" ]]; then
    echo "The guest is running a job or that label already exists." >&2
    exit 1
fi
cd "$(dirname "$0")/../.."
make
tar --exclude=__pycache__ -cf "$exchange/$label.tar" halo rig scenarios
{
    printf '#!/bin/bash\nset -euo pipefail\n'
    printf 'bash /exchange/preflight.sh\n'
    printf 'bash /exchange/bench.sh %q' "$label"
    printf ' %q' "$@"
    printf '\n'
} > "$exchange/job.tmp"
rm -f "$exchange/status"
mv "$exchange/job.tmp" "$exchange/job"
