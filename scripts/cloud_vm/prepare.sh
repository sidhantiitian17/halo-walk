#!/bin/bash
# Build a rootless, networkless Debian guest for the unchanged HALO-Walk harness.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=${1:-/workspace/halo-benchmark-vm}
mkdir -p "$work"
cd "$work"
work=$PWD
mkdir -p apt/lists/partial apt/guest/partial apt/host/partial host guest exchange
cat > apt/sources.list <<'SOURCES'
deb https://deb.debian.org/debian trixie main
deb https://security.debian.org/debian-security trixie-security main
SOURCES
cat > apt/apt.conf <<APT
Dir::Etc::sourcelist "$work/apt/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "$work/apt/lists";
APT::Get::List-Cleanup "false";
APT
export APT_CONFIG="$work/apt/apt.conf"
touch apt/guest.status
apt-get update
apt-get -o "Dir::Cache::archives=$work/apt/host" -o Debug::NoLocking=true \
    --download-only --no-install-recommends -y install qemu-system-x86
apt-get -o "Dir::Cache::archives=$work/apt/guest" -o "Dir::State::status=$work/apt/guest.status" \
    -o Debug::NoLocking=true --download-only --no-install-recommends -y install \
    linux-image-amd64 busybox-static bash coreutils util-linux kmod python3.13 iproute2 iputils-ping \
    nftables iperf3 conntrack ethtool curl tcpdump libgomp1 libstdc++6 tar e2fsprogs mount procps psmisc gawk sed grep findutils jq
for package in apt/host/*.deb; do dpkg-deb -x "$package" host; done
for package in apt/guest/*.deb; do dpkg-deb -x "$package" guest; done

mkdir -p guest/{proc,sys,dev,run,tmp,workspace,exchange}
ln -sfn bash guest/usr/bin/sh
ln -sfn gawk guest/usr/bin/awk
printf 'root:x:0:0:root:/root:/bin/bash\n' > guest/etc/passwd
printf 'root:x:0:\n' > guest/etc/group
printf 'hosts: files dns\n' > guest/etc/nsswitch.conf
kernel_version=$(find guest/boot -name 'vmlinuz-*' -printf '%f\n' | sort -V | tail -n1)
ln -sfn "boot/$kernel_version" guest/kernel
guest/usr/sbin/depmod -b "$work/guest" "${kernel_version#vmlinuz-}"
install -m755 "$repo/scripts/cloud_vm/init" guest/init
python3 "$repo/scripts/cloud_vm/initramfs.py" guest guest.cpio.gz
ln -sfn ../seabios/vgabios-stdvga.bin host/usr/share/qemu/vgabios-stdvga.bin
ln -sfn ../seabios/bios-256k.bin host/usr/share/qemu/bios-256k.bin
install -m755 "$repo/scripts/cloud_vm/bench.sh" exchange/bench.sh
install -m755 "$repo/scripts/cloud_vm/preflight.sh" exchange/preflight.sh
install -m755 "$repo/scripts/cloud_vm/fidelity.sh" exchange/fidelity.sh

export UV_CACHE_DIR="$work/uv-cache"
uv venv --python /usr/bin/python3.13 "$work/venv"
uv pip install --python "$work/venv/bin/python" -r "$repo/requirements-halo.txt" httpx2==2.16.2
