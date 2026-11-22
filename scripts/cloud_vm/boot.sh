#!/bin/bash
set -euo pipefail
cd "${1:-/workspace/halo-benchmark-vm}"
export LD_LIBRARY_PATH="$PWD/host/usr/lib/x86_64-linux-gnu"
vcpus=${HALO_VM_VCPUS:-2}
exec host/usr/bin/qemu-system-x86_64 -L "$PWD/host/usr/share/qemu" \
    -bios "$PWD/host/usr/share/seabios/bios-256k.bin" -accel tcg,thread=multi -cpu max -smp "$vcpus" -m 4096 \
    -nographic -no-reboot -nic none -kernel guest/kernel -initrd guest.cpio.gz \
    -append 'console=ttyS0 rdinit=/init quiet panic=1' \
    -virtfs local,path="$PWD/exchange",mount_tag=exchange,security_model=none \
    -virtfs local,path="$PWD/venv",mount_tag=deps,security_model=none,readonly=on
