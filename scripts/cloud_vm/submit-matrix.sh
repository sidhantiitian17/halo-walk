#!/bin/bash
# Stage one frozen revision and the two original scenario lists.
set -euo pipefail
if (( $# != 2 )); then
    echo "Usage: $0 VM_DIR LABEL" >&2
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
git diff --quiet "$revision" -- Makefile halo rig scenarios analysis lists
make -B
git archive --format=tar --output="$exchange/$label.tar" "$revision" halo rig scenarios
tar -rf "$exchange/$label.tar" halo/libhalo_sentinel.so
mkdir "$exchange/$label"
printf '%s\n' "$revision" > "$exchange/$label/source-revision.txt"
cp lists/{all,dg2}.txt "$exchange/$label/"
{
    (cd "$exchange" && sha256sum "$label.tar")
    sha256sum halo/libhalo_sentinel.so
} > "$exchange/$label/input-sha256.txt"
mapfile -t specs < <(awk 'NF == 3 {printf "%s,%s,%s\n", $1, $2, $3}' lists/all.txt lists/dg2.txt)
{
    printf '#!/bin/bash\nset -euo pipefail\n'
    printf 'bash /exchange/preflight.sh\nrc=0\n'
    printf 'bash /exchange/fidelity.sh %q || rc=1\n' "$label"
    printf 'bash /exchange/bench.sh %q' "$label"
    printf ' %q' "${specs[@]}"
    printf ' || rc=1\nexit "$rc"\n'
} > "$exchange/job.tmp"
rm -f "$exchange/status"
mv "$exchange/job.tmp" "$exchange/job"
