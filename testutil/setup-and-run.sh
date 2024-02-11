#!/usr/bin/env bash

set -euo pipefail

mount -t bpf bpf /sys/fs/bpf
mount -t tracefs tracefs /sys/kernel/debug/tracing

if [[ -d "/run/input/usr/src/linux/tools/testing/selftests/bpf" ]]; then
  export KERNEL_SELFTESTS="/run/input/usr/src/linux/tools/testing/selftests/bpf"
fi

if [[ -d "/run/input/lib/modules" ]]; then
  find /run/input/lib/modules -type f -name bpf_testmod.ko -exec insmod {} \;
fi

# used for debugging to check if bcc works at all
#script_dir="$(dirname "$(realpath "$0")")"
#timeout 5 python3 $script_dir/../pysamples/bcc/hello_world.py

$* && touch /run/output/statusqgitq