#!/bin/sh
# Deprecated version of run.sh

echo "Use run.sh instead"

# Move to the directory where the script is located
cd "$(dirname "$0")" || exit

./run.sh $@