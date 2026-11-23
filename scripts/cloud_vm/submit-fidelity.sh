#!/bin/bash
# Stage the original M1 workload for the running guest.
set -euo pipefail
if (( $# < 2 || $# > 3 )) || [[ ${3:-} != "" && ${3:-} != --diagnose ]]; then
    echo "Usage: $0 VM_DIR LABEL [--diagnose]" >&2
    exit 2
fi
exchange=$(realpath "$1/exchange")
label=$2
[[ $label =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || exit 2
if [[ -e "$exchange/job" || -e "$exchange/running" || -e "$exchange/$label.tar" ]]; then
    echo "The guest is running a job or that label already exists." >&2
    exit 1
fi
cd "$(dirname "$0")/../.."
revision=$(git rev-parse HEAD)
git diff --quiet "$revision" -- rig scenarios analysis
git archive --format=tar --output="$exchange/$label.tar" "$revision" halo rig scenarios
mkdir -p "$exchange/$label"
printf '%s\n' "$revision" > "$exchange/$label/source-revision.txt"
(cd "$exchange" && sha256sum "$label.tar") > "$exchange/$label/input-sha256.txt"
cp scripts/cloud_vm/{preflight,fidelity,diagnose-fidelity}.sh "$exchange/"
{
    printf '#!/bin/bash\nset -euo pipefail\n'
    printf 'bash /exchange/preflight.sh\nrc=0\n'
    printf 'bash /exchange/fidelity.sh %q || rc=1\n' "$label"
    if [[ ${3:-} == --diagnose ]]; then
        printf 'timeout -k 5 90 bash /exchange/diagnose-fidelity.sh %q %q || rc=1\n' "/tmp/$label" "/exchange/$label/diagnostic"
    fi
    printf 'exit "$rc"\n'
} > "$exchange/job.tmp"
rm -f "$exchange/status"
mv "$exchange/job.tmp" "$exchange/job"
