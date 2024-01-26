#!/usr/bin/env bash

###
# Run the passed script in a VM with a specific kernel version.
#
# Usage:
#   ./run-in-container.sh <kernel-version> <script> <script-args>
#
# Mainly used by bin/java in conjunction with `mvn test` to run tests reproducibly.
#
# Based on Cilium's ebpf/run-tests.sh from
# https://github.com/cilium/ebpf/blob/f95957d1669c9d2ee4d6dc34a6dfa25c4130003d/run-tests.sh
###

set -euo pipefail
script="$(realpath "$0")"
readonly script
script_folder="$(dirname "$script")"
readonly script_folder
source "$script_folder/oci-lib.sh"

check_docker
if ! command -v virtme-run &> /dev/null; then
  echo "virtme-run is not installed, install it via 'pip3 install virtme' or 'apt install virtme'"
  exit 1
fi

quote_env() {
  for var in "$@"; do
    if [ -v "$var" ]; then
      printf "%s=%q " "$var" "${!var}"
    fi
  done
}


declare -a preserved_env=(
  PATH
  CI_MAX_KERNEL_VERSION
  TEST_SEED
  KERNEL_VERSION
)

kernel_version="$1"
shift

# Use sudo if /dev/kvm isn't accessible by the current user.
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi
readonly sudo

testdir=$(pwd)
output="$(mktemp -d)"
# shellcheck disable=SC2034
printf -v cmd "%q " "$@"

# stdin is /dev/null, which doesn't play well with qemu. Use a fifo as a
# blocking substitute.
mkfifo "${output}/fake-stdin"
# Open for reading and writing to avoid blocking.
exec 0<> "${output}/fake-stdin"
rm "${output}/fake-stdin"

input="$(mktemp -d)"

if ! extract_oci_image "ghcr.io/cilium/ci-kernels:${kernel_version}-selftests" "${input}"; then
  extract_oci_image "ghcr.io/cilium/ci-kernels:${kernel_version}" "${input}"
fi

# get exact kernel version which is "$input/lib/modules/<version>/updates"
kernel_version=$(basename "$(find "${input}/lib/modules" -maxdepth 1 -type d)")

# /lib is a symlink which causes problems
mkdir "$input"/lib2
cp -r "$input"/lib/modules "$input"/lib2
rm -r "$input"/lib
mv $input/lib2 $input/lib

"$script_folder"/find_and_get_kernel.py "${kernel_version}" "$input"

mkdir -p "$input"/root

for ((i = 0; i < 3; i++)); do
  if ! $sudo virtme-run --kimg "${input}/boot/vmlinuz" --memory 768M --pwd \
    --rwdir="${testdir}=${testdir}" \
    --rodir=/run/input="${input}" \
    --rwdir=/run/output="${output}" \
    --rwdir=/lib/modules=$input/lib/modules \
    --rwdir=/root=$input/root \
    --script-sh "$(quote_env "${preserved_env[@]}") bash $script_folder/setup-and-run.sh $*" \
    --kopt possible_cpus=4; then
    exit 23
  fi

  if [[ -e "${output}/status" ]]; then
    break
  fi

  if [[ -v CI ]]; then
    echo "Retrying test run due to qemu crash"
    continue
  fi
done

rm -r "${input}"