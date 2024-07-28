#!/bin/sh
# Deprecated version of debug.sh

echo "Use debug_bpf.sh instead of debug.sh"

# Move to the directory where the script is located
cd "$(dirname "$0")" || exit

./debug.sh $@