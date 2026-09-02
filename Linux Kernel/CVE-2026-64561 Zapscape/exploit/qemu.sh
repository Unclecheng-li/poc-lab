#!/bin/bash
# Boot a kernel + initramfs under QEMU (x86_64, nested SVM/NPT).
# Test on QEMU v9.2.0 or later.
# Usage: ./qemu.sh <kernel-bzImage> <initramfs.cpio.gz>   [env QEMU=/path/to/qemu-system-x86_64]
set -e
KERNEL="$1"; INITRD="$2"
QEMU="${QEMU:-qemu-system-x86_64}"
[ -f "$KERNEL" ] && [ -f "$INITRD" ] || { echo "usage: $0 <kernel-bzImage> <initramfs.cpio.gz>"; exit 1; }

exec "$QEMU" \
	-no-user-config \
	-m 2G -smp 2 -cpu EPYC,+svm,+npt -accel tcg,thread=multi \
	-kernel "$KERNEL" -initrd "$INITRD" \
	-append "console=ttyS0 panic=-1 oops=panic kvm_amd.nested=1 kvm_amd.npt=1 rdinit=/init" \
	-nographic -monitor none -nic none -no-reboot

