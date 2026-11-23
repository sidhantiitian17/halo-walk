#!/bin/bash
# Build a separate rootless guest using the evidence run's Ubuntu kernel and iperf3.
set -euo pipefail
if (( $# != 2 )); then
    echo "Usage: $0 PREPARED_DEBIAN_VM NEW_REFERENCE_VM" >&2
    exit 2
fi
base=$(realpath "$1")
test -x "$base/guest/usr/bin/tcpdump"
test ! -e "$2"
mkdir -p "$2"
work=$(realpath "$2")
repo=$(cd "$(dirname "$0")/../.." && pwd)
kernel=6.8.0-149-generic
mkdir -p "$work"/{exchange,packages,extract,keyring,gpg,apt/lists/partial,apt/cache/partial}
chmod 700 "$work/gpg"

curl -fsSL --retry 2 -o "$work/ubuntu-keyring.deb" \
    https://archive.ubuntu.com/ubuntu/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1_all.deb
dpkg-deb -x "$work/ubuntu-keyring.deb" "$work/keyring"
key="$work/keyring/usr/share/keyrings/ubuntu-archive-keyring.gpg"
fingerprint=F6ECB3762474EDA9D21B7022871920D1991BC93C
gpg --batch --homedir "$work/gpg" --show-keys --with-colons "$key" \
    | awk -F: '$1 == "fpr" {print $10}' >"$work/exchange/ubuntu-key-fingerprints.txt"
grep -Fxq "$fingerprint" "$work/exchange/ubuntu-key-fingerprints.txt"
gpg --batch --homedir "$work/gpg" --no-default-keyring --keyring "$key" --export "$fingerprint" \
    >"$work/apt/ubuntu-archive.gpg"
key="$work/apt/ubuntu-archive.gpg"
cat >"$work/apt/sources.list" <<SOURCES
deb [arch=amd64 signed-by=$key] https://archive.ubuntu.com/ubuntu noble main universe
deb [arch=amd64 signed-by=$key] https://archive.ubuntu.com/ubuntu noble-updates main universe
deb [arch=amd64 signed-by=$key] https://security.ubuntu.com/ubuntu noble-security main universe
SOURCES
cat >"$work/apt/apt.conf" <<APT
Dir::Etc::sourcelist "$work/apt/sources.list";
Dir::Etc::sourceparts "-";
Dir::State::lists "$work/apt/lists";
Dir::Cache::archives "$work/apt/cache";
APT::Get::List-Cleanup "false";
Acquire::Languages "none";
Acquire::Retries "2";
APT
export APT_CONFIG="$work/apt/apt.conf"
apt-get update
cd "$work/packages"
apt-get download "linux-image-$kernel=6.8.0-149.149" "linux-modules-$kernel=6.8.0-149.149" \
    "linux-modules-extra-$kernel=6.8.0-149.149" iperf3=3.16-1build2 libiperf0=3.16-1build2
sha256sum ./*.deb >"$work/exchange/reference-packages.sha256"
for package in ./*.deb; do
    dpkg-deb -x "$package" "$work/extract"
done

ln -s "$base/host" "$work/host"
ln -s "$base/venv" "$work/venv"
cp -a --reflink=auto "$base/guest" "$work/guest"
guest="$work/guest"
old_image=$(basename "$(readlink "$guest/kernel")")
test "$old_image" != "vmlinuz-$kernel"
if [[ "$old_image" == vmlinuz-* ]]; then
    rm -rf "$guest/usr/lib/modules/${old_image#vmlinuz-}"
fi
modules=$(find "$work/extract" -type d -path "*/modules/$kernel" -print -quit)
test -n "$modules"
cp -a "$modules" "$guest/usr/lib/modules/"
install -m755 "$work/extract/boot/vmlinuz-$kernel" "$guest/boot/"
ln -sfn "boot/vmlinuz-$kernel" "$guest/kernel"
install -m755 "$work/extract/usr/bin/iperf3" "$guest/usr/bin/iperf3"
shopt -s nullglob
libraries=("$work/extract"/{usr/,}lib/x86_64-linux-gnu/libiperf.so.0*)
cp -a "${libraries[@]}" "$guest/usr/lib/x86_64-linux-gnu/"
"$guest/usr/sbin/depmod" -b "$guest" "$kernel"
python3 "$repo/scripts/cloud_vm/initramfs.py" "$guest" "$work/guest.cpio.gz"
install -m755 "$repo/scripts/cloud_vm/"{bench,preflight,fidelity,profile-capture}.sh "$work/exchange/"
